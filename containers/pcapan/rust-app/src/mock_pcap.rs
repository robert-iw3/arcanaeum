#[cfg(test)]
mod tests {
    use super::*;
    use pcap::Packet;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_mock_pcap_with_cert(is_expired: bool, is_self_signed: bool) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        let mut pcap_writer = pcap::Writer::new(&mut file, pcap::Linktype::ETHERNET).unwrap();

        // Mock TLS certificate packet
        let cert_data = if is_self_signed {
            // Simplified self-signed cert (subject == issuer)
            vec![0x30, 0x82, 0x01, 0x00, // DER sequence
                 0x30, 0x81, 0x80, // Subject
                 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, // Country: US
                 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x02, 0x54, 0x45, // Org: TE
                 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x02, 0x54, 0x45, // CN: TE
                 0x30, 0x81, 0x80, // Issuer (same as subject for self-signed)
                 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
                 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x02, 0x54, 0x45,
                 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x02, 0x54, 0x45,
                 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, // Valid from: 2025-01-01
                 0x17, 0x0d, if is_expired { 0x32, 0x35, 0x30, 0x31, 0x30, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a } else { 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a }], // Valid to: 2025-01-02 or 2026-01-01
        } else {
            // Non-self-signed cert
            vec![0x30, 0x82, 0x01, 0x00,
                 0x30, 0x81, 0x80,
                 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
                 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x02, 0x54, 0x45,
                 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x02, 0x54, 0x45,
                 0x30, 0x81, 0x80, // Different issuer
                 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
                 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x02, 0x43, 0x41,
                 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x02, 0x43, 0x41,
                 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
                 0x17, 0x0d, if is_expired { 0x32, 0x35, 0x30, 0x31, 0x30, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a } else { 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a }],
        };

        let tls_packet = vec![
            0x16, 0x03, 0x01, 0x00, 0x00, // TLS record
            0x01, // Handshake type: Certificate
            0x00, 0x00, 0x00, // Length
            cert_data.as_slice(),
        ].concat();

        let packet = Packet {
            header: &PacketHeader {
                ts: libc::timeval { tv_sec: 0, tv_usec: 0 },
                caplen: tls_packet.len() as u32,
                len: tls_packet.len() as u32,
            },
            data: &tls_packet,
        };

        pcap_writer.write_packet(&packet).unwrap();
        file
    }

    #[test]
    fn test_expired_cert_anomaly() {
        let file = create_mock_pcap_with_cert(true, false);
        let parsed_data = Arc::new(Mutex::new(ParsedData { inner: HashMap::new() }));
        let whitelist: Vec<IpNetwork> = vec![];
        let dns: Vec<IpNetwork> = vec![];
        let suspicious: Vec<(IpNetwork, String)> = vec![];
        let config = Config {
            dns: HashMap::new(),
            allow: HashMap::new(),
            su: HashMap::new(),
            oksuffixes: HashSet::new(),
            okhosts: HashSet::new(),
        };

        process_pcap(file.path(), &whitelist, &dns, &suspicious, &config, 0, &parsed_data).unwrap();
        let results = parsed_data.lock().unwrap().inner.clone();
        assert!(!results.is_empty());
        let info = results.values().next().unwrap();
        assert!(info.cert_anomaly);
        let cert = serde_json::from_str::<serde_json::Value>(&info.certificates[0]).unwrap();
        assert_eq!(cert["expired"].as_bool().unwrap(), true);
        assert_eq!(cert["self_signed"].as_bool().unwrap(), false);
    }

    #[test]
    fn test_self_signed_cert_anomaly() {
        let file = create_mock_pcap_with_cert(false, true);
        let parsed_data = Arc::new(Mutex::new(ParsedData { inner: HashMap::new() }));
        let whitelist: Vec<IpNetwork> = vec![];
        let dns: Vec<IpNetwork> = vec![];
        let suspicious: Vec<(IpNetwork, String)> = vec![];
        let config = Config {
            dns: HashMap::new(),
            allow: HashMap::new(),
            su: HashMap::new(),
            oksuffixes: HashSet::new(),
            okhosts: HashSet::new(),
        };

        process_pcap(file.path(), &whitelist, &dns, &suspicious, &config, 0, &parsed_data).unwrap();
        let results = parsed_data.lock().unwrap().inner.clone();
        assert!(!results.is_empty());
        let info = results.values().next().unwrap();
        assert!(info.cert_anomaly);
        let cert = serde_json::from_str::<serde_json::Value>(&info.certificates[0]).unwrap();
        assert_eq!(cert["expired"].as_bool().unwrap(), false);
        assert_eq!(cert["self_signed"].as_bool().unwrap(), true);
    }
}