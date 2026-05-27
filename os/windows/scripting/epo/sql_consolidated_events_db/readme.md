```mermaid
graph TD
    subgraph endpoints [Endpoints]
        style endpoints fill:#e3f2fd,stroke:#1976d2,stroke-width:3px,color:#000
        A1["💻 Endpoint Agent 1"] -->|"HTTPS/TCP 443 → Agent Events"| E["🛡️ Trellix ePO Production Server"]
        A2["💻 Endpoint Agent 2"] -->|"HTTPS/TCP 443 → Agent Events"| E
        A3["💻 Endpoint Agent 3"] -->|"HTTPS/TCP 443 → Agent Events"| E
        An["💻 ... Many Agents"] -->|"HTTPS/TCP 443 → Agent Events"| E
    end

    subgraph production [Production Environment]
        style production fill:#ffebee,stroke:#c62828,stroke-width:3px,color:#000
        E -->|"TDS/TCP 1433 → Write Events"| PDB["🗄️ SQL Server → Production Database → EPOEvents Table"]
    end

    subgraph consolidated [Consolidated Environment]
        style consolidated fill:#e8f5e8,stroke:#2e7d32,stroke-width:3px,color:#000
        PDB -->|"TDS/TCP 1433 → Linked Server Read → (WITH NOLOCK)"| CDB["🗄️ SQL Server → ConsolidatedEventsENS → EPOEvents_Consolidated Table"]
        CDB -->|"Internal → Hourly Batched INSERT"| CDB
    end

    subgraph siem [SIEM Platforms]
        style siem fill:#f3e5f5,stroke:#6a1b9a,stroke-width:3px,color:#000
        CDB -->|"JDBC/TCP 1433 → DB Connect"| S["🔍 Splunk"]
        CDB -->|"JDBC/TCP 1433 → Logstash JDBC"| ES["🧲 Elastic / OpenSearch"]
        CDB -->|"JDBC/TCP 1433 → GELF/UDP 12201"| G["🪵 Graylog"]
        CDB -->|"JDBC/TCP 1433 → Kafka/TCP 9092"| K["🐘 Apache Kafka"]
        K -->|TCP 9092| S
        K -->|TCP 9092| ES
        K -->|TCP 9092| G
    end

    classDef db fill:#fafafa,stroke:#424242,stroke-width:2px
    class PDB,CDB db
```

### Data Flow Topology Description
---

- **Agents to ePO Production**: Trellix ENS agents on endpoints continuously send events (threat detections, scans, etc.) to the central ePO server, which writes them to the production database (`ePO.dbo.EPOEvents`).

- **Production to Consolidated**: The dedicated consolidated SQL Server instance reads incrementally from production via a linked server. The stored procedure `SP_Sync_ENSEvents` performs batched, read-only pulls (`WITH (NOLOCK)`) using `AutoID` watermark for reliability and minimal impact.

- **Consolidated to SIEM**: SIEM platforms pull directly from `ConsolidatedEventsENS.dbo.EPOEvents_Consolidated`:
  - Splunk: DB Connect (rising column on `AutoID`).
  - Elastic/OpenSearch: Logstash JDBC input.
  - Graylog: Logstash with GELF output.
  - Optional: Kafka Connect for streaming to multiple consumers.

This architecture ensures:
- Zero write impact on production.
- Isolated analytical workload.
- Scalable, incremental ingestion for near-real-time SIEM visibility.