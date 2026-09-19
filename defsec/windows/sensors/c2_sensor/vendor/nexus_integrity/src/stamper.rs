use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub struct BatchStamp {
    pub sequence: u64,
    pub timestamp: u64,
    pub sensor_id: String,
    pub hmac_hex: String,
}

pub struct LineageStamper {
    sensor_id: String,
    key: Vec<u8>,
    sequence: u64,
}

impl LineageStamper {
    pub fn new(sensor_id: String, key: &[u8], initial_seq: u64) -> Self {
        Self {
            sensor_id,
            key: key.to_vec(),
            sequence: initial_seq,
        }
    }

    pub fn stamp(&mut self, data: &[u8]) -> BatchStamp {
        self.sequence += 1;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Canonical HMAC order matching core_ingress/src/integrity.rs:
        //   parquet_bytes || seq.to_be_bytes() || sensor_id || ts.to_be_bytes()
        // Bug fixed: was seq_LE ‖ ts_LE ‖ sensor_id ‖ parquet — every batch rejected.
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .expect("HMAC key length is always valid");

        mac.update(data);                           // 1. parquet payload
        mac.update(&self.sequence.to_be_bytes());   // 2. big-endian u64
        mac.update(self.sensor_id.as_bytes());      // 3. sensor_id UTF-8
        mac.update(&timestamp.to_be_bytes());       // 4. big-endian u64

        BatchStamp {
            sequence: self.sequence,
            timestamp,
            sensor_id: self.sensor_id.clone(),
            hmac_hex: hex::encode(mac.finalize().into_bytes()),
        }
    }
}
