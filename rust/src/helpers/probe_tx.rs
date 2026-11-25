// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;

use super::{emit, monotonic_ns, spec_read};

pub const HEADER_BYTES: usize = 16;

#[derive(Debug, Deserialize)]
pub struct TxSpec {
    pub dst_ip: String,
    pub port: u16,
    pub duration_s: f64,
    pub rate_pps: f64,
    #[serde(default = "two_hundred")]
    pub packet_size: usize,
    #[serde(default)]
    pub dscp: Option<u8>,
}

fn two_hundred() -> usize {
    200
}

/// Each datagram carries its sequence number and the sender's CLOCK_MONOTONIC
/// reading, which the receiver subtracts to get a true one-way delay.
pub fn payload_build(seq: u64, now_ns: u64, size: usize) -> Vec<u8> {
    let mut packet = Vec::with_capacity(size.max(HEADER_BYTES));
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&now_ns.to_be_bytes());
    packet.resize(size.max(HEADER_BYTES), 0);
    packet
}

pub fn run() -> anyhow::Result<()> {
    let spec: TxSpec = spec_read()?;
    let size = spec.packet_size.max(HEADER_BYTES);

    let bind = if spec.dst_ip.contains(':') { "[::]:0" } else { "0.0.0.0:0" };
    let socket = UdpSocket::bind(bind)?;
    socket.set_write_timeout(Some(Duration::from_millis(200)))?;
    if let Some(dscp) = spec.dscp {
        let tos = (dscp as libc::c_int) << 2;
        unsafe {
            libc::setsockopt(
                std::os::unix::io::AsRawFd::as_raw_fd(&socket),
                libc::IPPROTO_IP,
                libc::IP_TOS,
                &tos as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    let target = format!("{}:{}", spec.dst_ip, spec.port);
    let interval = 1.0 / spec.rate_pps;
    let started = Instant::now();
    let mut sent = 0u64;
    let mut seq = 0u64;

    loop {
        let elapsed = started.elapsed().as_secs_f64();
        if elapsed >= spec.duration_s {
            break;
        }
        // Pace against the start time rather than sleeping a fixed interval, so
        // scheduling delays do not accumulate into a slower actual rate.
        let due = seq as f64 * interval;
        if due > elapsed {
            std::thread::sleep(Duration::from_secs_f64((due - elapsed).min(0.05)));
            continue;
        }
        if socket
            .send_to(&payload_build(seq, monotonic_ns(), size), &target)
            .is_ok()
        {
            sent += 1;
        }
        seq += 1;
    }

    let actual = started.elapsed().as_secs_f64();
    emit(&json!({
        "packets_sent": sent,
        "sequence_numbers": seq,
        "duration_s": (actual * 1000.0).round() / 1000.0,
        "rate_pps_actual": (actual > 0.0).then(|| (sent as f64 / actual * 10.0).round() / 10.0),
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_carries_sequence_and_timestamp() {
        let packet = payload_build(42, 1_234_567_890, 200);
        assert_eq!(packet.len(), 200);
        assert_eq!(u64::from_be_bytes(packet[0..8].try_into().unwrap()), 42);
        assert_eq!(u64::from_be_bytes(packet[8..16].try_into().unwrap()), 1_234_567_890);
    }

    #[test]
    fn payload_never_shrinks_below_the_header() {
        assert_eq!(payload_build(1, 2, 4).len(), HEADER_BYTES);
        assert_eq!(payload_build(1, 2, 0).len(), HEADER_BYTES);
    }

    #[test]
    fn monotonic_clock_advances() {
        let first = monotonic_ns();
        std::thread::sleep(Duration::from_millis(5));
        assert!(monotonic_ns() > first);
    }
}
