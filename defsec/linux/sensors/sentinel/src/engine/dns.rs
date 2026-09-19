// ==============================================================================
// File:        dns.rs
// Component:   Linux Sentinel — DNS Subsystem
// Description: Zero-allocation parser for extracting Domain Names from raw UDP/53
//              payloads captured by the eBPF tracepoints.
// Role:        Extracts QNAMEs to feed into the UEBA Shannon Entropy model for
//              identifying Domain Generation Algorithms (DGA).
// Author:      Robert Weber
// ==============================================================================

const MAX_POINTER_JUMPS: usize = 10; // Anti-loop safeguard for malformed packets

pub fn parse_dns_payload(payload: &[u8]) -> Vec<String> {
    let mut domains = Vec::new();

    // Minimum DNS header size is 12 bytes
    if payload.len() < 12 { return domains; }

    let num_questions = u16::from_be_bytes([payload[4], payload[5]]);
    if num_questions == 0 || num_questions > 10 { return domains; }

    let mut offset = 12;

    for _ in 0..num_questions {
        let mut domain = String::with_capacity(64);
        let mut current_offset = offset;
        let mut jumps = 0;
        let mut jumped = false;

        loop {
            // Guard against infinite loops and eBPF payload truncation bounds
            if jumps > MAX_POINTER_JUMPS || current_offset >= payload.len() {
                break;
            }

            let len_byte = payload[current_offset];

            // End of QNAME
            if len_byte == 0 {
                if !jumped { offset = current_offset + 1; }
                break;
            }

            // Check for DNS Compression Pointer (11xxxxxx)
            if len_byte & 0xC0 == 0xC0 {
                if current_offset + 1 >= payload.len() { break; }
                if !jumped { offset = current_offset + 2; }

                let pointer = u16::from_be_bytes([len_byte & 0x3F, payload[current_offset + 1]]) as usize;
                current_offset = pointer;
                jumped = true;
                jumps += 1;
                continue;
            }

            // Standard Label
            let len = len_byte as usize;
            current_offset += 1;

            if current_offset + len > payload.len() { break; }

            if !domain.is_empty() { domain.push('.'); }

            let label = String::from_utf8_lossy(&payload[current_offset..current_offset + len]);

            // Sanitize label to prevent log/SQL injection
            for c in label.chars() {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    domain.push(c);
                }
            }

            current_offset += len;
            if !jumped { offset = current_offset; }
        }

        if !domain.is_empty() {
            domains.push(domain);
        }

        if !jumped { offset += 4; } // Skip QTYPE (2) and QCLASS (2)
    }

    domains
}