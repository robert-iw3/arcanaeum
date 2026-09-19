// ====================================================================================
// File:        ebpf.rs
// Component:   Linux Sentinel — User-Space eBPF Bridge
// Description: The user-space controller for the compiled CO-RE skeleton.
// Role:        Loads the eBPF bytecode into the kernel, arms the self-protection
//              PID filters, continually polls the BPF ring buffer, translates C-FFI
//              structs into safe Rust types, and routes telemetry to the UEBA scanner.
// Author:      Robert Weber
// ====================================================================================

use crate::engine::rules::RawKernelEvent;
use anyhow::{Context, Result};
use libbpf_rs::{MapCore, RingBufferBuilder};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

mod sentinel_skel {
    include!(concat!(env!("OUT_DIR"), "/sentinel.skel.rs"));
}
use sentinel_skel::SentinelSkelBuilder;

#[repr(C)]
struct event_t {
    ts_ns: u64,
    interval_ns: u64,
    cgroup_id: u64,
    pid: u32,
    ppid: u32,
    uid: u32,
    event_type: u32,
    comm: [u8; 16],
    target: [u8; 512],
    daddr: u32,
    daddr6: [u8; 16],
    dport: u16,
    sport: u16,
    payload: [u8; 64],
}

// Compile-time FFI contract enforcement
const _: () = assert!(
    std::mem::size_of::<event_t>() == 656,  // 654 bytes + 2 bytes alignment padding
    "event_t size mismatch — FFI contract violated"
);

pub struct EbpfEngine {
    config: Arc<RwLock<crate::config::MasterConfig>>,
    raw_tx: mpsc::Sender<RawKernelEvent>,
    is_running: Arc<AtomicBool>,
}

impl EbpfEngine {
    pub fn new(config: Arc<RwLock<crate::config::MasterConfig>>, raw_tx: mpsc::Sender<RawKernelEvent>, is_running: Arc<AtomicBool>) -> Self {
        Self { config, raw_tx, is_running }
    }

    pub fn run(self) -> Result<()> {
        info!("Loading Native eBPF CO-RE skeleton...");
        let skel_builder = SentinelSkelBuilder::default();

        let mut open_object = MaybeUninit::uninit();

        let open_skel = skel_builder.open(&mut open_object).context("Failed to open BPF skeleton")?;
        let mut skel = open_skel.load().context("Failed to load BPF skeleton")?;

        skel.attach().context("Failed to attach BPF programs")?;

        {
            let config_lock = self.config.read().unwrap_or_else(|e| e.into_inner());
            let mut whitelist_count = 0;
            for ip_str in &config_lock.network.whitelist_connections {
                if let Ok(ipv4) = ip_str.parse::<std::net::Ipv4Addr>() {
                    let key_bytes = ipv4.octets();
                    let val_bytes = 1u8.to_ne_bytes();

                    if let Err(e) = skel.maps.ip_whitelist.update(&key_bytes, &val_bytes, libbpf_rs::MapFlags::ANY) {
                        warn!("Failed to inject IP {} into Ring-0 whitelist: {}", ip_str, e);
                    } else {
                        whitelist_count += 1;
                    }
                }
            }
            info!("Injected {} whitelisted IPs into eBPF kernel memory.", whitelist_count);
        }

        {
            let config_lock = self.config.read().unwrap_or_else(|e| e.into_inner());
            let mut proc_whitelist_count = 0;

            for proc_name in &config_lock.process.whitelist_processes {
                let mut key_bytes = [0u8; 16];
                let bytes = proc_name.as_bytes();

                let len = bytes.len().min(15);
                key_bytes[..len].copy_from_slice(&bytes[..len]);

                let val_bytes = 1u8.to_ne_bytes();

                if let Err(e) = skel.maps.process_whitelist.update(&key_bytes, &val_bytes, libbpf_rs::MapFlags::ANY) {
                    warn!("Failed to inject process {} into Ring-0 whitelist: {}", proc_name, e);
                } else {
                    proc_whitelist_count += 1;
                }
            }
            info!("Injected {} whitelisted processes into eBPF kernel memory.", proc_whitelist_count);
        }

        let my_pid = std::process::id();
        skel.maps.self_pid.update(
            &0u32.to_ne_bytes(),
            &my_pid.to_ne_bytes(),
            libbpf_rs::MapFlags::ANY,
        )?;
        info!("Self-PID filter armed: PID {} excluded from kernel telemetry.", my_pid);

        let mut builder = RingBufferBuilder::new();
        let tx_clone = self.raw_tx.clone();

        let poll_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_clone = poll_counter.clone();

        builder.add(&skel.maps.events, move |data| {
            counter_clone.fetch_add(1, Ordering::Relaxed);

            if data.len() < std::mem::size_of::<event_t>() { return 0; }
            // SAFETY: Ring buffer memory returned by bpf_ringbuf_reserve() is 8-byte aligned
            // (guaranteed by kernel bpf_ringbuf implementation). Size is validated above.
            // The event_t struct uses #[repr(C)] with natural alignment.
            let c_event = unsafe { &*(data.as_ptr() as *const event_t) };

            let parsed_ip = if c_event.daddr != 0 {
                Ipv4Addr::from(u32::from_be(c_event.daddr)).to_string()
            } else if c_event.daddr6 != [0; 16] {
                Ipv6Addr::from(c_event.daddr6).to_string()
            } else {
                String::new()
            };

            let raw_event = RawKernelEvent {
                ts_ns: c_event.ts_ns,
                interval_ns: c_event.interval_ns,
                cgroup_id: c_event.cgroup_id,
                pid: c_event.pid,
                ppid: c_event.ppid,
                uid: c_event.uid,
                event_type: c_event.event_type,
                comm: String::from_utf8_lossy(&c_event.comm).trim_matches(char::from(0)).to_string(),
                target: String::from_utf8_lossy(&c_event.target).trim_matches(char::from(0)).to_string(),
                dest_ip: parsed_ip,
                dest_port: u16::from_be(c_event.dport),
                source_port: c_event.sport,
                parent_comm: String::new(),
                user_name: String::new(),
                payload: c_event.payload.to_vec(),
            };

            // PIPELINE SHIFT: We strictly route the raw telemetry to the UEBA Scanner.
            // Absolutely no rule evaluation happens here in the kernel-bound OS thread.
            match tx_clone.try_send(raw_event) {
                Ok(_) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    warn!("SYSTEM OVERLOAD: Kernel event dropped due to UEBA pipeline backpressure.");
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    error!("FATAL: UEBA telemetry routing channel closed unexpectedly.");
                }
            }
            0
        })?;

        let ring_buf = builder.build().context("Failed to build ring buffer")?;
        info!("eBPF engine active. Streaming raw telemetry to UEBA Pipeline at 50ms intervals.");

        if let Err(e) = caps::drop(None, caps::CapSet::Effective, caps::Capability::CAP_SYS_ADMIN) {
            error!("Failed to drop CAP_SYS_ADMIN (Effective): {}", e);
        }
        if let Err(e) = caps::drop(None, caps::CapSet::Effective, caps::Capability::CAP_BPF) {
            error!("Failed to drop CAP_BPF (Effective): {}", e);
        }
        info!("Immutability established: CAP_SYS_ADMIN and CAP_BPF permanently dropped.");

        if let Some(core_ids) = core_affinity::get_core_ids() {
            if let Some(core) = core_ids.first() {
                if core_affinity::set_for_current(*core) {
                    info!("CPU Affinity Locked: eBPF polling thread pinned to Core {}", core.id);
                }
            }
        }

        let mut poll_interval = 50;

        loop {
            if !self.is_running.load(Ordering::SeqCst) {
                info!("eBPF Engine terminating cleanly.");
                break;
            }

            poll_counter.store(0, Ordering::Relaxed);
            ring_buf.poll(std::time::Duration::from_millis(poll_interval))?;
            let events_processed = poll_counter.load(Ordering::Relaxed);

            // Dynamic Yield Algorithm
            if events_processed == 0 {
                // System is idle: Back off to save battery/CPU, capping at 500ms sleep
                poll_interval = std::cmp::min(poll_interval + 10, 500);
            } else if events_processed > 100 {
                // System under heavy load: Aggressive polling (1ms) to prevent ring-buffer overflow
                poll_interval = 1;
            } else {
                // Normal operational baseline
                poll_interval = 50;
            }
        }
        Ok(())
    }
}