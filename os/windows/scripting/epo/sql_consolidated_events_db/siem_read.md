# Ingesting Trellix ENS Events from ConsolidatedEventsENS into SIEM Platforms

The `ConsolidatedEventsENS` database, containing the `EPOEvents_Consolidated` table, serves as a read-optimized repository for Trellix Endpoint Security (ENS) events. Isolation from the production ePO database and optional READ_ONLY mode ensure zero impact on live operations during ingestion.

Ingestion methods for SQL Server data include pull-based (recommended for controlled, incremental retrieval) and push-based approaches (file export or streaming).

The following sections detail configurations for Splunk (CIM-compliant), Elastic/OpenSearch (ECS-compliant), and Graylog. All examples leverage incremental extraction using a watermark (`AutoID` preferred for sequential reliability).

## ETL Pipeline Overview

1. **Extract**
   - Source: `ConsolidatedEventsENS.dbo.EPOEvents_Consolidated`
   - Method: Incremental query with watermark (`AutoID` or `ReceivedUTC > last_sync`)
   - Tools: Splunk DB Connect, Logstash JDBC input, Kafka Connect JDBC source, or Debezium
   - Frequency: Hourly or higher as required

2. **Transform**
   - Normalization to standard schemas (CIM or ECS)
   - Enrichment: Hostname resolution from `AgentGUID` (via lookup if available), severity mapping, action normalization
   - Static fields: `event.dataset = "trellix.ens"`, `event.module = "trellix"`

3. **Load**
   - Direct: DB Connect → Splunk index, Logstash → Elasticsearch/OpenSearch/Graylog
   - Streaming: Kafka topic → platform-specific connector

### Reference Schema (Common EPOEvents Columns)

| Column Name        | Data Type       | Description                                      |
|--------------------|-----------------|--------------------------------------------------|
| AutoID             | BIGINT          | Primary key, sequential IDENTITY                 |
| ReceivedUTC        | DATETIME        | Event receipt timestamp (UTC)                    |
| DetectedUTC        | DATETIME        | Detection timestamp                              |
| AgentGUID          | NVARCHAR(128)   | Unique agent identifier                          |
| SourceHostName     | NVARCHAR(255)   | Hostname (when available)                        |
| ThreatName         | NVARCHAR(255)   | Detected threat signature                        |
| ThreatType         | NVARCHAR        | Type (e.g., "Trojan", "Virus")                   |
| ThreatCategory     | NVARCHAR        | Category (e.g., "Malware")                       |
| ThreatSeverity     | INT             | Severity level (1=Low to 5=Critical)             |
| ActionTaken        | NVARCHAR        | Action performed (e.g., "Cleaned", "Blocked")    |
| UserName           | NVARCHAR        | Associated user (e.g., "DOMAIN\User")            |
| FilePath           | NVARCHAR(MAX)   | Full path of affected file                       |
| ProcessName        | NVARCHAR        | Triggering process                               |
| EventID            | INT             | ePO event type identifier                        |
| EventDescription   | NVARCHAR(MAX)   | Raw event description                            |

## Field Mappings

### Splunk Common Information Model (CIM) – Malware & Endpoint Protection

| Source Field       | CIM Field              | Transformation/Notes                              |
|--------------------|------------------------|---------------------------------------------------|
| ReceivedUTC       | _time                  | Parse with `strptime`                             |
| SourceHostName    | dest, host             | Primary host field                                |
| AgentGUID         | dest (fallback)        | Use if hostname unavailable; optional lookup      |
| ThreatName        | signature              | Direct                                            |
| ThreatType        | signature_type         | Lowercase                                         |
| ThreatCategory    | category               | Direct                                            |
| ThreatSeverity    | severity               | Map: 1-2=low, 3=medium, 4-5=high/critical         |
| ActionTaken       | action                 | Lowercase + normalize (e.g., "WouldBlock" → "blocked") |
| UserName          | user                   | Direct                                            |
| FilePath          | file_path, file_name   | Split basename                                    |
| ProcessName       | process_name           | Direct                                            |
| EventDescription  | description            | Raw text                                          |
| EventID           | vendor_event_id        | Direct                                            |
| Static            | vendor = "Trellix"     |                                                   |
| Static            | product = "Endpoint Security" |                                            |
| Static            | eventtype = malware, endpoint_protection |                                  |

### Elastic Common Schema (ECS) v8.11+

| Source Field       | ECS Field                                      | Transformation/Notes                              |
|--------------------|------------------------------------------------|---------------------------------------------------|
| ReceivedUTC       | @timestamp                                     | ISO8601 parse                                     |
| DetectedUTC       | event.created                                  | Optional secondary timestamp                       |
| SourceHostName    | host.name, host.hostname                       | Primary                                           |
| AgentGUID         | host.id                                        | Fallback                                          |
| ThreatName        | threat.indicator.name                          | Direct                                            |
| ThreatType        | threat.indicator.type                          | Lowercase                                         |
| ThreatCategory    | threat.indicator.threat_type                   | Direct                                            |
| ThreatSeverity    | event.severity                                 | Map to ECS 1-10 scale (e.g., 1→2, 5→10)           |
| ActionTaken       | event.action                                   | Lowercase                                         |
| UserName          | user.name, user.domain                         | Split DOMAIN\User                                 |
| FilePath          | file.path, file.name, file.extension           | Split components                                  |
| ProcessName       | process.name                                   | Direct                                            |
| EventDescription  | event.original, message                        | Raw + structured                                  |
| EventID           | event.code                                     | Direct                                            |
| Static            | event.dataset = "trellix.ens"                  |                                                   |
| Static            | event.module = "trellix"                       |                                                   |
| Static            | event.provider = "Endpoint Security"           |                                                   |
| Conditional       | event.kind = "alert" (if ThreatName present)   |                                                   |
| Conditional       | event.category = ["malware","threat"]          | If threat detected                                |
| Conditional       | event.type = ["detection"]                     | If threat detected                                |

## Example Configurations

### Splunk – DB Connect (Pull-Based)

**Database Connection** (DB Connect UI):
- Type: Microsoft SQL Server
- JDBC URL: `jdbc:sqlserver://<server>:1433;databaseName=ConsolidatedEventsENS`

**Input** (Rising Column):
```
Name: trellix_ens_input
Query: SELECT * FROM dbo.EPOEvents_Consolidated WHERE AutoID > ? ORDER BY AutoID
Rising Column: AutoID
Interval: 3600
Index: trellix_ens
Sourcetype: trellix:ens:db
```

**props.conf** (CIM Normalization):
```
[trellix:ens:db]
EVAL-_time = strptime(ReceivedUTC, "%Y-%m-%d %H:%M:%S")
FIELDALIAS-host = SourceHostName AS host
FIELDALIAS-dest = COALESCE(SourceHostName, AgentGUID) AS dest
FIELDALIAS-signature = ThreatName AS signature
FIELDALIAS-action = lower(ActionTaken) AS action
FIELDALIAS-user = UserName AS user
EXTRACT-file_path = in FilePath (?<file_path>.+)
EVAL-file_name = mvindex(split(file_path, "\\"), -1)
EVAL-severity = case(ThreatSeverity <= 2, "low", ThreatSeverity == 3, "medium", ThreatSeverity >= 4, "high")
EVAL-vendor = "Trellix"
EVAL-product = "Endpoint Security"
TAG::eventtype = malware endpoint_protection
```

### Elastic/OpenSearch – Logstash JDBC (Pull-Based)

**logstash.conf**:
```conf
input {
  jdbc {
    jdbc_driver_library => "/path/to/mssql-jdbc.jar"
    jdbc_driver_class => "com.microsoft.sqlserver.jdbc.SQLServerDriver"
    jdbc_connection_string => "jdbc:sqlserver://<server>:1433;databaseName=ConsolidatedEventsENS"
    jdbc_user => "readonly_user"
    jdbc_password => "${SQL_PASS}"
    schedule => "0 * * * *"
    statement => "SELECT * FROM dbo.EPOEvents_Consolidated WHERE AutoID > :sql_last_value ORDER BY AutoID"
    tracking_column => "AutoID"
    tracking_column_type => "numeric"
    last_run_metadata_path => "/opt/logstash/.trellix_last_id"
  }
}

filter {
  date { match => ["ReceivedUTC", "ISO8601"] target => "@timestamp" }
  mutate {
    add_field => { "event.dataset" => "trellix.ens" "event.module" => "trellix" "event.provider" => "Endpoint Security" }
    rename => { "SourceHostName" => "host.name" "AgentGUID" => "host.id" "ThreatName" => "[threat][indicator][name]" "ActionTaken" => "event.action" "UserName" => "user.name" "FilePath" => "file.path" }
  }
  if [ThreatName] {
    mutate { add_field => { "event.category" => ["malware","threat"] "event.type" => "detection" "event.kind" => "alert" } }
  }
  translate { field => "ThreatSeverity" destination => "event.severity" dictionary => { "1" => "2" "2" => "4" "3" => "6" "4" => "8" "5" => "10" } }
}

output {
  elasticsearch {
    hosts => ["https://es-cluster:9200"]
    index => "trellix-ens-%{+YYYY.MM.dd}"
    user => "elastic"
    password => "${ES_PASS}"
  }
}
```

### Graylog – Logstash GELF Output

Use the same Logstash configuration above, replacing the output:
```conf
output {
  gelf { host => "graylog-server" port => 12201 }
}
```
Configure Graylog extractors or processing pipelines for field mapping.

### Kafka Integration (Streaming Option)

**Kafka Connect JDBC Source Connector**:
```json
{
  "name": "trellix-ens-source",
  "config": {
    "connector.class": "io.confluent.connect.jdbc.JdbcSourceConnector",
    "connection.url": "jdbc:sqlserver://<server>:1433;databaseName=ConsolidatedEventsENS",
    "mode": "incrementing",
    "incrementing.column.name": "AutoID",
    "topic.prefix": "trellix-ens-",
    "poll.interval.ms": "3600000",
    "table.whitelist": "dbo.EPOEvents_Consolidated"
  }
}
```

Consumers:
- Splunk: Splunk Connect for Kafka
- Elastic: Filebeat Kafka input with ingest pipeline
- Graylog: Native Kafka input

## Troubleshooting

Common issues and resolutions for the ingestion pipeline:

- **Connectivity Failures**
  - Symptoms: Tool logs show connection refused, timeout, or authentication errors.
  - Resolution: Verify firewall rules allow access from the SIEM host to SQL Server port 1433. Confirm the readonly user has `CONNECT` and `SELECT` permissions on `ConsolidatedEventsENS`. Test connectivity with `sqlcmd` or SSMS from the SIEM server.

- **Incremental Sync Stalls or Duplicates**
  - Symptoms: No new events ingested despite source growth; or duplicate events appear.
  - Resolution: Check `SyncWatermark` table for stalled `LastSyncedAutoID`. Reset manually if corrupted: `UPDATE SyncWatermark SET LastSyncedAutoID = (SELECT MAX(AutoID)-10000 FROM EPOEvents_Consolidated)`. Ensure `AutoID` is strictly increasing.

- **Mapping/Transformation Errors**
  - Symptoms: Fields missing or incorrect in SIEM (e.g., empty `signature`, wrong severity).
  - Resolution: Validate source column names match configurations. Review tool logs (DB Connect inputs, Logstash stdout) for parse errors. Test transformations with sample queries.

- **Performance/Timeout Issues**
  - Symptoms: Partial batches, job timeouts, high CPU on SQL Server.
  - Resolution: Reduce batch size in tool config (e.g., add `fetch_size` in Logstash). Confirm indexes exist on `AutoID` and `ReceivedUTC`. Monitor SQL waits via `sp_WhoIsActive`.

- **Tool-Specific Errors**
  - Splunk DB Connect: Check `db_inputs.log` for JDBC driver issues; ensure 64-bit Java matches.
  - Logstash JDBC: Verify driver JAR version compatibility; add `jdbc_page_size` for large results.
  - Kafka Connect: Review connector logs for offset issues; use `timestamp` mode if `incrementing` unreliable.

- **General Monitoring**
  - Query `SELECT * FROM ConsolidatedEventsENS.dbo.SyncWatermark ORDER BY WatermarkID DESC` for sync history and duration.
  - Set up alerts on job failures via SQL Agent or SIEM monitoring.

Adjust configurations based on environment-specific schema variations and test thoroughly in a non-production setting prior to deployment.