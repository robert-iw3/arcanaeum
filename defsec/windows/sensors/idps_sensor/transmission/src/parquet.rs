use arrow::array::{StringBuilder, Int64Builder};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::{WriterProperties, WriterVersion};
use std::sync::Arc;
use crate::IDPSTelemetryRow;

pub fn serialize_to_parquet(rows: &[IDPSTelemetryRow]) -> Result<Vec<u8>, String> {
    // Bi-directional IDPS network telemetry schema (ingress + egress). "Image" is the
    // identifier_column for the downstream duck-typing worker.
    let schema = Arc::new(Schema::new(vec![
        Field::new("id",               DataType::Int64, false),
        Field::new("event_id",         DataType::Utf8,  true),
        Field::new("timestamp",        DataType::Int64, true),  // epoch_ms
        Field::new("computer_name",    DataType::Utf8,  true),
        Field::new("sensor_user",      DataType::Utf8,  true),
        Field::new("host_ip",          DataType::Utf8,  true),
        Field::new("provider",         DataType::Utf8,  true),
        Field::new("event_name",       DataType::Utf8,  true),
        Field::new("direction",        DataType::Utf8,  true),  // ingress / egress / lateral
        Field::new("source_ip",        DataType::Utf8,  true),
        Field::new("destination",      DataType::Utf8,  true),
        Field::new("port",             DataType::Utf8,  true),
        Field::new("query",            DataType::Utf8,  true),  // DNS
        Field::new("size",             DataType::Int64, true),  // bytes
        Field::new("Image",            DataType::Utf8,  true),  // identifier_column (process)
        Field::new("command_line",     DataType::Utf8,  true),
        Field::new("pid",              DataType::Utf8,  true),
        Field::new("event_type",       DataType::Utf8,  true),
        Field::new("threat_intel",     DataType::Utf8,  true),
        Field::new("suspicious_flags", DataType::Utf8,  true),
        Field::new("attck_mappings",   DataType::Utf8,  true),
        Field::new("confidence",       DataType::Int64, true),
        Field::new("action",           DataType::Utf8,  true),
        Field::new("payload_raw",      DataType::Utf8,  true),
    ]));

    let cap = rows.len();
    let mut id_b       = Int64Builder::with_capacity(cap);
    let mut ev_id_b    = StringBuilder::with_capacity(cap, cap * 36);
    let mut ts_b       = Int64Builder::with_capacity(cap);
    let mut comp_b     = StringBuilder::with_capacity(cap, cap * 16);
    let mut user_b     = StringBuilder::with_capacity(cap, cap * 32);
    let mut host_ip_b  = StringBuilder::with_capacity(cap, cap * 16);
    let mut provider_b = StringBuilder::with_capacity(cap, cap * 32);
    let mut evname_b   = StringBuilder::with_capacity(cap, cap * 32);
    let mut dir_b      = StringBuilder::with_capacity(cap, cap * 8);
    let mut src_b      = StringBuilder::with_capacity(cap, cap * 16);
    let mut dest_b     = StringBuilder::with_capacity(cap, cap * 32);
    let mut port_b     = StringBuilder::with_capacity(cap, cap * 8);
    let mut query_b    = StringBuilder::with_capacity(cap, cap * 64);
    let mut size_b     = Int64Builder::with_capacity(cap);
    let mut image_b    = StringBuilder::with_capacity(cap, cap * 64);
    let mut cmd_b      = StringBuilder::with_capacity(cap, cap * 128);
    let mut pid_b      = StringBuilder::with_capacity(cap, cap * 8);
    let mut evtype_b   = StringBuilder::with_capacity(cap, cap * 32);
    let mut ti_b       = StringBuilder::with_capacity(cap, cap * 64);
    let mut flags_b    = StringBuilder::with_capacity(cap, cap * 128);
    let mut attck_b    = StringBuilder::with_capacity(cap, cap * 32);
    let mut conf_b     = Int64Builder::with_capacity(cap);
    let mut action_b   = StringBuilder::with_capacity(cap, cap * 16);
    let mut payload_b  = StringBuilder::with_capacity(cap, cap * 512);

    for r in rows {
        id_b.append_value(r.id);
        ev_id_b.append_value(&r.event_id);
        ts_b.append_value(r.timestamp);
        comp_b.append_value(&r.computer_name);
        user_b.append_value(&r.sensor_user);
        host_ip_b.append_value(&r.host_ip);
        provider_b.append_value(&r.provider);
        evname_b.append_value(&r.event_name);
        dir_b.append_value(&r.direction);
        src_b.append_value(&r.source_ip);
        dest_b.append_value(&r.destination);
        port_b.append_value(&r.port);
        query_b.append_value(&r.query);
        size_b.append_value(r.size);
        image_b.append_value(&r.image);
        cmd_b.append_value(&r.command_line);
        pid_b.append_value(&r.pid);
        evtype_b.append_value(&r.event_type);
        ti_b.append_value(&r.threat_intel);
        flags_b.append_value(&r.suspicious_flags);
        attck_b.append_value(&r.attck_mappings);
        conf_b.append_value(r.confidence);
        action_b.append_value(&r.action);
        payload_b.append_value(&r.payload_raw);
    }

    let batch = match RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(id_b.finish()),
            Arc::new(ev_id_b.finish()),
            Arc::new(ts_b.finish()),
            Arc::new(comp_b.finish()),
            Arc::new(user_b.finish()),
            Arc::new(host_ip_b.finish()),
            Arc::new(provider_b.finish()),
            Arc::new(evname_b.finish()),
            Arc::new(dir_b.finish()),
            Arc::new(src_b.finish()),
            Arc::new(dest_b.finish()),
            Arc::new(port_b.finish()),
            Arc::new(query_b.finish()),
            Arc::new(size_b.finish()),
            Arc::new(image_b.finish()),
            Arc::new(cmd_b.finish()),
            Arc::new(pid_b.finish()),
            Arc::new(evtype_b.finish()),
            Arc::new(ti_b.finish()),
            Arc::new(flags_b.finish()),
            Arc::new(attck_b.finish()),
            Arc::new(conf_b.finish()),
            Arc::new(action_b.finish()),
            Arc::new(payload_b.finish()),
        ],
    ) {
        Ok(b) => b,
        Err(e) => return Err(format!("Arrow RecordBatch Error: {}", e)),
    };

    let mut buffer = Vec::new();
    let props = WriterProperties::builder()
        .set_writer_version(WriterVersion::PARQUET_2_0)
        .set_compression(Compression::ZSTD(Default::default()))
        .build();

    let mut writer = match ArrowWriter::try_new(&mut buffer, schema, Some(props)) {
        Ok(w) => w,
        Err(e) => return Err(format!("Parquet Writer Init Error: {}", e)),
    };

    if let Err(e) = writer.write(&batch) {
        return Err(format!("Parquet Row Write Error: {}", e));
    }
    if let Err(e) = writer.close() {
        return Err(format!("Parquet Stream Close Error: {}", e));
    }

    Ok(buffer)
}
