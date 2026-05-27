#[cfg(test)]
mod tests {
    use super::super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    fn create_mock_pcap() -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        let header = [
            0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        file.write_all(&header).unwrap();
        file
    }

    #[test]
    fn test_network_parse_ipv4() {
        let net = network_parse("192.168.1.0/24".to_string());
        assert!(matches!(net, IpNetwork::V4(_)));
        if let IpNetwork::V4(v4) = net { assert_eq!(v4.prefix(), 24); }
    }

    #[test]
    fn test_network_parse_ipv6() {
        let net = network_parse("2001:db8::/32".to_string());
        assert!(matches!(net, IpNetwork::V6(_)));
        if let IpNetwork::V6(v6) = net { assert_eq!(v6.prefix(), 32); }
    }

    #[test]
    fn test_ipv6_private_check() {
        let net = network_parse("fc00::/7".to_string());
        if let IpNetwork::V6(v6) = net {
            assert!(v6.is_unique_local());
        }
    }

    #[test]
    fn test_process_empty_pcap() {
        let file = create_mock_pcap();
        let whitelist = vec![];
        let dns = vec![];
        let suspicious = vec![];
        let config = Config {
            dns: HashMap::new(),
            allow: HashMap::new(),
            su: HashMap::new(),
            oksuffixes: HashSet::new(),
            okhosts: HashSet::new(),
        };
        let parsed_data = Arc::new(Mutex::new(ParsedData::default()));
        let result = process_pcap(file.path(), &whitelist, &dns, &suspicious, &config, 0, &parsed_data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_anomaly_detection() {
        let info = CollectedInfo {
            packet_count: 1000,
            size: 100000,
            ports: vec![80, 443].into_iter().collect(),
            timestamps: vec![Utc::now(), Utc::now() + chrono::Duration::seconds(10)],
            protocol_stats: ProtocolStats {
                tcp_packets: 900,
                udp_packets: 100,
            },
            ..Default::default()
        };
        let score = detect_anomaly(&info);
        assert!(score >= 0.0 && score <= 1.0);
    }
}