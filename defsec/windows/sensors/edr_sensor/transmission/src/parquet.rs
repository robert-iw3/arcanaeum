use arrow::array::{Float64Builder, StringBuilder, Int64Builder};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::{WriterProperties, WriterVersion};
use std::sync::Arc;
use crate::EDRTelemetryRow;

pub fn serialize_to_parquet(rows: &[EDRTelemetryRow]) -> Result<Vec<u8>, String> {
    // Sigma/TTP alert fields plus UEBA aggregation fields (count/avg_entropy/max_velocity/
    // rate_per_sec/unique_tids). "Image" is the identifier_column for the downstream
    // duck-typing worker, mirroring c2/idps.
    let schema = Arc::new(Schema::new(vec![
        Field::new("id",                DataType::Int64,   false),
        Field::new("event_id",          DataType::Utf8,    true),
        Field::new("timestamp",         DataType::Int64,   true),  // epoch_ms
        Field::new("computer_name",     DataType::Utf8,    true),
        Field::new("sensor_user",       DataType::Utf8,    true),
        Field::new("host_ip",           DataType::Utf8,    true),
        Field::new("event_type",        DataType::Utf8,    true),
        Field::new("destination",       DataType::Utf8,    true),
        Field::new("Image",             DataType::Utf8,    true),  // identifier_column (process path)
        Field::new("command_line",      DataType::Utf8,    true),
        Field::new("suspicious_flags",  DataType::Utf8,    true),
        Field::new("matched_indicator", DataType::Utf8,    true),
        Field::new("attck_mappings",    DataType::Utf8,    true),
        Field::new("confidence",        DataType::Int64,   true),
        Field::new("signature_name",    DataType::Utf8,    true),
        Field::new("tactic",            DataType::Utf8,    true),
        Field::new("technique",         DataType::Utf8,    true),
        Field::new("procedure",         DataType::Utf8,    true),
        Field::new("severity",          DataType::Utf8,    true),
        Field::new("action",            DataType::Utf8,    true),
        Field::new("count",             DataType::Int64,   true),
        Field::new("avg_entropy",       DataType::Float64, true),
        Field::new("max_velocity",      DataType::Float64, true),
        Field::new("rate_per_sec",      DataType::Float64, true),
        Field::new("unique_tids",       DataType::Int64,   true),
        Field::new("payload_raw",       DataType::Utf8,    true),
    ]));

    let cap = rows.len();
    let mut id_b        = Int64Builder::with_capacity(cap);
    let mut ev_id_b      = StringBuilder::with_capacity(cap, cap * 36);
    let mut ts_b         = Int64Builder::with_capacity(cap);
    let mut comp_b       = StringBuilder::with_capacity(cap, cap * 16);
    let mut user_b       = StringBuilder::with_capacity(cap, cap * 32);
    let mut host_ip_b    = StringBuilder::with_capacity(cap, cap * 16);
    let mut evtype_b     = StringBuilder::with_capacity(cap, cap * 32);
    let mut dest_b       = StringBuilder::with_capacity(cap, cap * 32);
    let mut image_b      = StringBuilder::with_capacity(cap, cap * 64);
    let mut cmd_b        = StringBuilder::with_capacity(cap, cap * 128);
    let mut flags_b      = StringBuilder::with_capacity(cap, cap * 128);
    let mut indicator_b  = StringBuilder::with_capacity(cap, cap * 64);
    let mut attck_b      = StringBuilder::with_capacity(cap, cap * 32);
    let mut conf_b       = Int64Builder::with_capacity(cap);
    let mut sig_b        = StringBuilder::with_capacity(cap, cap * 32);
    let mut tactic_b     = StringBuilder::with_capacity(cap, cap * 16);
    let mut technique_b  = StringBuilder::with_capacity(cap, cap * 16);
    let mut procedure_b  = StringBuilder::with_capacity(cap, cap * 16);
    let mut sev_b        = StringBuilder::with_capacity(cap, cap * 16);
    let mut action_b     = StringBuilder::with_capacity(cap, cap * 16);
    let mut count_b      = Int64Builder::with_capacity(cap);
    let mut avg_ent_b    = Float64Builder::with_capacity(cap);
    let mut max_vel_b    = Float64Builder::with_capacity(cap);
    let mut rate_b       = Float64Builder::with_capacity(cap);
    let mut uniq_tid_b   = Int64Builder::with_capacity(cap);
    let mut payload_b    = StringBuilder::with_capacity(cap, cap * 512);

    for r in rows {
        id_b.append_value(r.id);
        ev_id_b.append_value(&r.event_id);
        ts_b.append_value(r.timestamp);
        comp_b.append_value(&r.computer_name);
        user_b.append_value(&r.sensor_user);
        host_ip_b.append_value(&r.host_ip);
        evtype_b.append_value(&r.event_type);
        dest_b.append_value(&r.destination);
        image_b.append_value(&r.image);
        cmd_b.append_value(&r.command_line);
        flags_b.append_value(&r.suspicious_flags);
        indicator_b.append_value(&r.matched_indicator);
        attck_b.append_value(&r.attck_mappings);
        conf_b.append_value(r.confidence);
        sig_b.append_value(&r.signature_name);
        tactic_b.append_value(&r.tactic);
        technique_b.append_value(&r.technique);
        procedure_b.append_value(&r.procedure);
        sev_b.append_value(&r.severity);
        action_b.append_value(&r.action);
        count_b.append_value(r.count);
        avg_ent_b.append_value(r.avg_entropy);
        max_vel_b.append_value(r.max_velocity);
        rate_b.append_value(r.rate_per_sec);
        uniq_tid_b.append_value(r.unique_tids);
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
            Arc::new(evtype_b.finish()),
            Arc::new(dest_b.finish()),
            Arc::new(image_b.finish()),
            Arc::new(cmd_b.finish()),
            Arc::new(flags_b.finish()),
            Arc::new(indicator_b.finish()),
            Arc::new(attck_b.finish()),
            Arc::new(conf_b.finish()),
            Arc::new(sig_b.finish()),
            Arc::new(tactic_b.finish()),
            Arc::new(technique_b.finish()),
            Arc::new(procedure_b.finish()),
            Arc::new(sev_b.finish()),
            Arc::new(action_b.finish()),
            Arc::new(count_b.finish()),
            Arc::new(avg_ent_b.finish()),
            Arc::new(max_vel_b.finish()),
            Arc::new(rate_b.finish()),
            Arc::new(uniq_tid_b.finish()),
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
