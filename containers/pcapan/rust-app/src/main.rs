use anyhow::{Context, Result};
use chrono::prelude::*;
use clap::Parser;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use log::{error, info};
use pcap::{Capture, PacketHeader};
use rayon::prelude::*;
use serde::Deserialize;
use serde_json::json;
use smartcore::linalg::basic::matrix::DenseMatrix;
use smartcore::ensemble::random_forest_classifier::RandomForestClassifier;
use std::{
    collections::{HashMap, HashSet},
    fs::{self, BufReader, File},
    io::BufRead,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
};
use tls_parser::{SNIType, TlsMessage, TlsMessageHandshake};
use x509_parser::prelude::*;

#[derive(Parser, Debug)]
#[command(name = "pcapan", about = "Analyze pcap files for network forensics")]
struct Opt {
    #[arg(short, long)]
    dir: PathBuf,
    #[arg(short, long, default_value = "whitelist.yaml")]
    whitelist: PathBuf,
    #[arg(short, long, default_value = "0")]
    cutoff: usize,
    #[arg(long)]
    google: bool,
    #[arg(short, long, default_value = "results.json")]
    output: PathBuf,
}

#[derive(Debug, Deserialize)]
struct Config {
    dns: HashMap<String, String>,
    allow: HashMap<String, String>,
    su: HashMap<String, String>,
    oksuffixes: HashSet<String>,
    okhosts: HashSet<String>,
}

fn network_parse(k: String) -> IpNetwork {
    if k.contains(':') {
        let (n, p) = k.split_once('/').map_or_else(|| (k.as_str(), "128"), |(i, p)| (i, p));
        IpNetwork::V6(Ipv6Network::new(Ipv6Addr::from_str(n).unwrap(), p.parse().unwrap()).unwrap())
    } else {
        let (n, p) = k.split_once('/').map_or_else(|| (k.as_str(), "32"), |(i, p)| (i, p));
        IpNetwork::V4(Ipv4Network::new(Ipv4Addr::from_str(n).unwrap(), p.parse().unwrap()).unwrap())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum DataSource {
    SNI,
    DNS,
    HttpHost,
    HttpUserAgent,
}

#[derive(Debug, Default, serde::Serialize)]
struct ProtocolStats {
    tcp_packets: usize,
    udp_packets: usize,
}

#[derive(Debug, Default, serde::Serialize)]
struct CollectedInfo {
    ports: HashSet<u16>,
    hosts: HashSet<(DataSource, String)>,
    user_agents: HashSet<String>,
    certificates: Vec<String>,
    size: usize,
    first_packet: usize,
    timestamps: Vec<DateTime<Utc>>,
    protocol_stats: ProtocolStats,
    packet_count: usize,
    anomaly_score: f64,
    cert_anomaly: bool,
}

#[derive(Default)]
struct ParsedData {
    inner: HashMap<IpNetwork, CollectedInfo>,
}

impl ParsedData {
    fn hostname(&mut self, packet_id: usize, dsrc: DataSource, src: IpNetwork, dst: IpNetwork, content: String) {
        self.insert_hostname(packet_id, dsrc, src, content.clone());
        self.insert_hostname(packet_id, dsrc, dst, content);
    }

    fn ports(&mut self, packet_id: usize, src: IpNetwork, dst: IpNetwork, sport: u16, dport: u16) {
        self.inner.entry(src).or_insert_with(|| CollectedInfo {
            timestamps: vec![],
            ..Default::default()
        }).ports.insert(sport);
        self.inner.entry(dst).or_insert_with(|| CollectedInfo {
            timestamps: vec![],
            ..Default::default()
        }).ports.insert(dport);
    }

    fn datasize(&mut self, packet_id: usize, src: IpNetwork, dst: IpNetwork, size: usize) {
        self.inner.entry(src).or_insert_with(|| CollectedInfo {
            timestamps: vec![],
            ..Default::default()
        }).size += size;
        self.inner.entry(dst).or_insert_with(|| CollectedInfo {
            timestamps: vec![],
            ..Default::default()
        }).size += size;
    }

    fn insert_hostname(&mut self, packet_id: usize, dsrc: DataSource, src: IpNetwork, content: String) {
        let is_private = match src {
            IpNetwork::V4(v4) => v4.is_private(),
            IpNetwork::V6(v6) => v6.is_private() || v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local(),
        };
        if !is_private {
            self.inner.entry(src).or_insert_with(|| CollectedInfo {
                first_packet: packet_id,
                timestamps: vec![],
                ..Default::default()
            }).hosts.insert((dsrc, content));
        }
    }

    fn insert_user_agent(&mut self, packet_id: usize, src: IpNetwork, ua: String) {
        let is_private = match src {
            IpNetwork::V4(v4) => v4.is_private(),
            IpNetwork::V6(v6) => v6.is_private() || v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local(),
        };
        if !is_private {
            self.inner.entry(src).or_insert_with(|| CollectedInfo {
                first_packet: packet_id,
                timestamps: vec![],
                ..Default::default()
            }).user_agents.insert(ua);
        }
    }

    fn insert_certificate(&mut self, packet_id: usize, src: IpNetwork, cert_details: String, is_anomalous: bool) {
        let entry = self.inner.entry(src).or_insert_with(|| CollectedInfo {
            first_packet: packet_id,
            timestamps: vec![],
            ..Default::default()
        });
        entry.certificates.push(cert_details);
        entry.cert_anomaly |= is_anomalous;
    }

    fn increment_protocol(&mut self, src: IpNetwork, protocol: u8) {
        let entry = self.inner.entry(src).or_insert_with(Default::default);
        entry.packet_count += 1;
        if protocol == 6 {
            entry.protocol_stats.tcp_packets += 1;
        } else if protocol == 17 {
            entry.protocol_stats.udp_packets += 1;
        }
    }

    fn add_timestamp(&mut self, src: IpNetwork, ts: DateTime<Utc>) {
        self.inner.entry(src).or_default().timestamps.push(ts);
    }
}

#[derive(Deserialize)]
struct GoogleNetwork {
    #[serde(alias = "ipv4Prefix")]
    ipv4_prefix: Option<String>,
    #[serde(alias = "ipv6Prefix")]
    ipv6_prefix: Option<String>,
    service: Option<String>,
}

#[derive(Deserialize)]
struct GoogleNetworks {
    prefixes: Vec<GoogleNetwork>,
}

fn detect_anomaly(info: &CollectedInfo) -> f64 {
    let timestamp_variance = if info.timestamps.len() > 1 {
        let mean = info.timestamps.iter().map(|t| t.timestamp() as f64).sum::<f64>() / info.timestamps.len() as f64;
        let variance = info.timestamps.iter().map(|t| {
            let diff = t.timestamp() as f64 - mean;
            diff * diff
        }).sum::<f64>() / info.timestamps.len() as f64;
        variance.sqrt()
    } else {
        0.0
    };
    let protocol_ratio = if info.protocol_stats.tcp_packets + info.protocol_stats.udp_packets > 0 {
        info.protocol_stats.tcp_packets as f64 / (info.protocol_stats.tcp_packets + info.protocol_stats.udp_packets) as f64
    } else {
        0.0
    };
    let cert_anomaly_score = if info.cert_anomaly { 1.0 } else { 0.0 };
    let features = vec![
        info.packet_count as f64,
        info.size as f64,
        info.ports.len() as f64,
        timestamp_variance,
        protocol_ratio,
        cert_anomaly_score,
    ];
    let x = DenseMatrix::from_2d_array(&[&features]);
    let classifier = RandomForestClassifier::fit(
        &DenseMatrix::from_2d_array(&[
            &[100.0, 1000.0, 5.0, 10.0, 0.5, 0.0],  // Normal
            &[1000.0, 100000.0, 50.0, 100.0, 0.9, 1.0],  // Anomalous
        ]),
        &vec![0, 1],
        Default::default(),
    ).unwrap();
    let prediction = classifier.predict(&x).unwrap();
    if prediction[0] == 1 { 0.9 } else { 0.1 }
}

fn process_pcap(
    file: &Path,
    whitelist: &[IpNetwork],
    dns: &[IpNetwork],
    suspicious: &[(IpNetwork, String)],
    config: &Config,
    cutoff: usize,
    parsed_data: &Mutex<ParsedData>,
) -> Result<()> {
    info!("Processing pcap: {:?}", file);
    let mut capture = Capture::from_file(file).context("Failed to open pcap")?;
    let mut packet_id: usize = 0;
    let mut buffer = Vec::with_capacity(65536); // Pre-allocate buffer for packets

    while let Ok(packet) = capture.next_packet() {
        packet_id += 1;
        buffer.clear();
        buffer.extend_from_slice(&packet.header.ts.tv_sec.to_le_bytes());
        buffer.extend_from_slice(&packet.header.ts.tv_usec.to_le_bytes());
        buffer.extend_from_slice(&packet.header.caplen.to_le_bytes());
        buffer.extend_from_slice(&packet.header.len.to_le_bytes());
        buffer.extend_from_slice(packet.data);

        let ts = Utc.timestamp(packet.header.ts.tv_sec as i64, (packet.header.ts.tv_usec * 1000) as u32);
        let d = pdu::EthernetPdu::new(&buffer[16..]).context("Failed to parse Ethernet PDU")?;
        match d.inner() {
            Ok(pdu::Ethernet::Ipv4(e)) => {
                let src = IpNetwork::V4(Ipv4Network::new(Ipv4Addr::from(e.source_address()), 32).unwrap());
                let dst = IpNetwork::V4(Ipv4Network::new(Ipv4Addr::from(e.destination_address()), 32).unwrap());
                let content = e.buffer();
                let mut data = parsed_data.lock().unwrap();
                data.datasize(packet_id, src, dst, content.len());
                data.add_timestamp(src, ts);
                data.add_timestamp(dst, ts);
                data.increment_protocol(src, e.protocol());
                data.increment_protocol(dst, e.protocol());
                let header_len = e.as_bytes().len();
                match e.protocol() {
                    6 => {
                        let tcp = &content[header_len..];
                        if tcp.len() < 20 { continue; }
                        let data_offset = ((tcp[12] >> 4) as usize) * 4;
                        let payload = &tcp[data_offset..];
                        if let Ok((_, record)) = tls_parser::parse_tls_plaintext(payload) {
                            for m in record.msg {
                                if let TlsMessage::Handshake(hs) = m {
                                    match hs {
                                        TlsMessageHandshake::ClientHello(ch) => {
                                            if let Some(ext) = ch.ext {
                                                if let Ok((_, extensions)) = tls_parser::parse_tls_extensions(ext) {
                                                    for e in extensions {
                                                        if let tls_parser::TlsExtension::SNI(snis) = e {
                                                            for (tp, content_bytes) in snis {
                                                                let content_str = match tp {
                                                                    SNIType::HostName => String::from_utf8_lossy(content_bytes).into_owned(),
                                                                    _ => format!("{}/{}", tp, String::from_utf8_lossy(content_bytes)),
                                                                };
                                                                data.hostname(packet_id, DataSource::SNI, src, dst, content_str);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        TlsMessageHandshake::Certificate(tlscerts) => {
                                            for c in tlscerts.cert_chain {
                                                if let Ok((_, cert)) = X509Certificate::from_der(c.data) {
                                                    let now = Utc::now();
                                                    let is_expired = cert.validity().not_after.to_datetime() < now;
                                                    let is_self_signed = cert.subject() == cert.issuer();
                                                    let is_anomalous = is_expired || is_self_signed;
                                                    let cert_json = json!({
                                                        "subject": cert.subject().to_string(),
                                                        "issuer": cert.issuer().to_string(),
                                                        "valid_from": cert.validity().not_before.to_string(),
                                                        "valid_to": cert.validity().not_after.to_string(),
                                                        "expired": is_expired,
                                                        "self_signed": is_self_signed
                                                    }).to_string();
                                                    data.insert_certificate(packet_id, src, cert_json.clone(), is_anomalous);
                                                    data.insert_certificate(packet_id, dst, cert_json, is_anomalous);
                                                }
                                            }
                                        }
                                        _ => (),
                                    }
                                }
                            }
                        }
                        let mut headers = [httparse::EMPTY_HEADER; 64];
                        let mut request = httparse::Request::new(&mut headers);
                        if let Ok(httparse::Status::Complete(_)) = request.parse(payload) {
                            for h in request.headers {
                                let name_lower = h.name.to_ascii_lowercase();
                                if name_lower == "host" {
                                    data.hostname(packet_id, DataSource::HttpHost, src, dst, String::from_utf8_lossy(h.value).into_owned());
                                } else if name_lower == "user-agent" {
                                    data.insert_user_agent(packet_id, src, String::from_utf8_lossy(h.value).into_owned());
                                    data.insert_user_agent(packet_id, dst, String::from_utf8_lossy(h.value).into_owned());
                                }
                            }
                        }
                        let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
                        let dport = u16::from_be_bytes([tcp[2], tcp[3]]);
                        data.ports(packet_id, src, dst, sport, dport);
                    }
                    17 => {
                        let udp = &content[header_len..];
                        if udp.len() <= 8 { continue; }
                        let sport = u16::from_be_bytes([udp[0], udp[1]]);
                        let dport = u16::from_be_bytes([udp[2], tcp[3]]);
                        let payload = &udp[8..];
                        data.ports(packet_id, src, dst, sport, dport);
                        if dns.iter().any(|n| n.contains(src)) {
                            if let Ok(m) = dns_parser::Packet::parse(payload) {
                                let questions = m.questions.iter()
                                    .filter_map(|q| if q.qtype == dns_parser::QueryType::A || q.qtype == dns_parser::QueryType::AAAA { Some(q.qname.to_string()) } else { None })
                                    .collect::<HashSet<_>>();
                                for answer in m.answers {
                                    match answer.data {
                                        dns_parser::RData::A(rcd) => {
                                            let aname = answer.name.to_string();
                                            if questions.contains(&aname) {
                                                data.hostname(packet_id, DataSource::DNS, dst, src, aname);
                                            }
                                        }
                                        dns_parser::RData::AAAA(_) => {}
                                        dns_parser::RData::CNAME(name) => {
                                            let cname = name.to_string();
                                            if questions.contains(&answer.name.to_string()) {
                                                data.hostname(packet_id, DataSource::DNS, dst, src, cname);
                                            }
                                        }
                                        _ => {},
                                    }
                                }
                            }
                        }
                    }
                    _ => (),
                }
            }
            Ok(pdu::Ethernet::Ipv6(e)) => {
                let src = IpNetwork::V6(Ipv6Network::new(Ipv6Addr::from(e.source_address()), 128).unwrap());
                let dst = IpNetwork::V6(Ipv6Network::new(Ipv6Addr::from(e.destination_address()), 128).unwrap());
                let content = e.buffer();
                let mut data = parsed_data.lock().unwrap();
                data.datasize(packet_id, src, dst, content.len());
                data.add_timestamp(src, ts);
                data.add_timestamp(dst, ts);
                data.increment_protocol(src, e.protocol());
                data.increment_protocol(dst, e.protocol());
                let header_len = e.as_bytes().len();
                match e.protocol() {
                    6 => {
                        let tcp = &content[header_len..];
                        if tcp.len() < 20 { continue; }
                        let data_offset = ((tcp[12] >> 4) as usize) * 4;
                        let payload = &tcp[data_offset..];
                        if let Ok((_, record)) = tls_parser::parse_tls_plaintext(payload) {
                            for m in record.msg {
                                if let TlsMessage::Handshake(hs) = m {
                                    match hs {
                                        TlsMessageHandshake::ClientHello(ch) => {
                                            if let Some(ext) = ch.ext {
                                                if let Ok((_, extensions)) = tls_parser::parse_tls_extensions(ext) {
                                                    for e in extensions {
                                                        if let tls_parser::TlsExtension::SNI(snis) = e {
                                                            for (tp, content_bytes) in snis {
                                                                let content_str = match tp {
                                                                    SNIType::HostName => String::from_utf8_lossy(content_bytes).into_owned(),
                                                                    _ => format!("{}/{}", tp, String::from_utf8_lossy(content_bytes)),
                                                                };
                                                                data.hostname(packet_id, DataSource::SNI, src, dst, content_str);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        TlsMessageHandshake::Certificate(tlscerts) => {
                                            for c in tlscerts.cert_chain {
                                                if let Ok((_, cert)) = X509Certificate::from_der(c.data) {
                                                    let now = Utc::now();
                                                    let is_expired = cert.validity().not_after.to_datetime() < now;
                                                    let is_self_signed = cert.subject() == cert.issuer();
                                                    let is_anomalous = is_expired || is_self_signed;
                                                    let cert_json = json!({
                                                        "subject": cert.subject().to_string(),
                                                        "issuer": cert.issuer().to_string(),
                                                        "valid_from": cert.validity().not_before.to_string(),
                                                        "valid_to": cert.validity().not_after.to_string(),
                                                        "expired": is_expired,
                                                        "self_signed": is_self_signed
                                                    }).to_string();
                                                    data.insert_certificate(packet_id, src, cert_json.clone(), is_anomalous);
                                                    data.insert_certificate(packet_id, dst, cert_json, is_anomalous);
                                                }
                                            }
                                        }
                                        _ => (),
                                    }
                                }
                            }
                        }
                    }
                    _ => (),
                }
            }
            _ => (),
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();
    let opt = Opt::parse();
    let config_file = File::open(&opt.whitelist).context("Failed to open whitelist")?;
    let config: Config = serde_yaml::from_reader(BufReader::new(config_file)).context("Failed to parse config")?;

    let mut whitelist = config.allow.into_keys().map(network_parse).collect::<Vec<_>>();
    let dns = config.dns.into_keys().map(network_parse).collect::<Vec<_>>();
    let mut suspicious = config.su.into_iter().map(|(k, v)| (network_parse(k), v)).collect::<Vec<_>>();

    if opt.google {
        info!("Loading Google networks...");
        let client = reqwest::blocking::Client::new();
        for _ in 0..3 {
            match client.get("https://www.gstatic.com/ipranges/goog.json").send() {
                Ok(resp) => {
                    let goog: GoogleNetworks = resp.json().context("Failed to parse Google JSON")?;
                    for n in goog.prefixes {
                        if let Some(p) = n.ipv4_prefix { whitelist.push(network_parse(p)); }
                        if let Some(p) = n.ipv6_prefix { whitelist.push(network_parse(p)); }
                    }
                    break;
                }
                Err(e) => { error!("Retrying Google fetch: {}", e); continue; }
            }
        }
        for _ in 0..3 {
            match client.get("https://www.gstatic.com/ipranges/cloud.json").send() {
                Ok(resp) => {
                    let cloud: GoogleNetworks = resp.json().context("Failed to parse Cloud JSON")?;
                    for n in cloud.prefixes {
                        if let Some(p) = n.ipv4_prefix { suspicious.push((network_parse(p), n.service.unwrap_or_default())); }
                        if let Some(p) = n.ipv6_prefix { suspicious.push((network_parse(p), n.service.unwrap_or_default())); }
                    }
                    break;
                }
                Err(e) => { error!("Retrying Cloud fetch: {}", e); continue; }
            }
        }
    }

    let parsed_data = Arc::new(Mutex::new(ParsedData { inner: HashMap::with_capacity(1000) }));

    let pcaps: Vec<PathBuf> = fs::read_dir(&opt.dir)
        .context("Failed to read pcap dir")?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().map_or(false, |ext| ext == "pcap"))
        .collect();
    pcaps.par_iter().for_each(|file| {
        if let Err(e) = process_pcap(file, &whitelist, &dns, &suspicious, &config, opt.cutoff, &parsed_data) {
            error!("Error processing pcap {:?}: {}", file, e);
        }
    });

    let mut results = parsed_data.lock().unwrap().inner.clone();
    let ok_host = |d: &str| config.okhosts.contains(d) || config.oksuffixes.iter().any(|suff| d.ends_with(suff));
    results.retain(|ip, info| {
        let is_private = match ip {
            IpNetwork::V4(v4) => v4.is_private(),
            IpNetwork::V6(v6) => v6.is_private() || v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local(),
        };
        if is_private || info.size < opt.cutoff || dns.iter().any(|n| n.contains(*ip)) {
            false
        } else if whitelist.iter().all(|n| !n.contains(*ip)) {
            if !info.hosts.is_empty() {
                info.hosts.iter().any(|(_, h)| !ok_host(h))
            } else {
                true
            }
        } else {
            false
        }
    });

    for (ip, info) in &mut results {
        info.anomaly_score = detect_anomaly(info);
        if info.anomaly_score > 0.5 || info.cert_anomaly {
            info!("Anomaly detected for IP: {:?} (score: {}, cert_anomaly: {})", ip, info.anomaly_score, info.cert_anomaly);
        }
    }

    let json_output = serde_json::to_string_pretty(&results).context("Failed to serialize results")?;
    fs::write(&opt.output, json_output).context("Failed to write output")?;
    info!("Results written to {:?}", opt.output);
    Ok(())
}