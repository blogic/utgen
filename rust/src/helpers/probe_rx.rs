// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::collections::HashSet;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};

use super::{emit, monotonic_ns, spec_read};
use super::probe_tx::HEADER_BYTES;

const MAX_DELAYS: usize = 200_000;
const RECV_BUFFER: libc::c_int = 16 << 20;

#[derive(Debug, Deserialize)]
pub struct RxSpec {
    pub bind: String,
    pub port: u16,
    pub duration_s: f64,
}

#[derive(Default)]
pub struct Tally {
    pub seen: u64,
    pub highest: i64,
    pub reordered: u64,
    pub duplicates: u64,
    pub delays_ns: Vec<i64>,
}

impl Tally {
    pub fn new() -> Self {
        Self { highest: -1, ..Default::default() }
    }

    pub fn record(&mut self, seq: u64, delay_ns: i64, previous: &mut i64, seen_seqs: &mut HashSet<u64>) {
        self.seen += 1;
        if !seen_seqs.insert(seq) {
            self.duplicates += 1;
        }
        if (seq as i64) < *previous {
            self.reordered += 1;
        }
        *previous = seq as i64;
        self.highest = self.highest.max(seq as i64);
        if self.delays_ns.len() < MAX_DELAYS {
            self.delays_ns.push(delay_ns);
        }
    }

    pub fn stats(&self) -> Value {
        let expected = if self.seen > 0 { self.highest + 1 } else { 0 } as u64;
        let lost = expected.saturating_sub(self.seen).saturating_sub(self.duplicates);
        let mut out = json!({
            "packets_received": self.seen,
            "packets_expected": expected,
            "lost": lost,
            "reordered": self.reordered,
            "duplicates": self.duplicates,
        });
        if expected > 0 {
            out["loss_percent"] =
                (((100.0 * lost as f64 / expected as f64) * 10000.0).round() / 10000.0).into();
        }
        if self.delays_ns.is_empty() {
            return out;
        }

        let mut ordered = self.delays_ns.clone();
        ordered.sort_unstable();
        let ms = |ns: i64| ((ns as f64 / 1e6) * 10000.0).round() / 10000.0;
        let percentile = |fraction: f64| {
            let index = ((fraction * (ordered.len() - 1) as f64).round() as usize).min(ordered.len() - 1);
            ordered[index]
        };
        let sum: i64 = ordered.iter().sum();

        out["owd_min_ms"] = ms(ordered[0]).into();
        out["owd_mean_ms"] = ms(sum / ordered.len() as i64).into();
        out["owd_p50_ms"] = ms(percentile(0.50)).into();
        out["owd_p99_ms"] = ms(percentile(0.99)).into();
        out["owd_max_ms"] = ms(ordered[ordered.len() - 1]).into();
        out["owd_samples"] = ordered.len().into();

        // Mean absolute difference between consecutive one-way delays, which is
        // the IPDV form of jitter rather than iperf3's smoothed estimate.
        if self.delays_ns.len() > 1 {
            let total: i64 = self
                .delays_ns
                .windows(2)
                .map(|pair| (pair[1] - pair[0]).abs())
                .sum();
            out["ipdv_mean_ms"] = ms(total / (self.delays_ns.len() as i64 - 1)).into();
        }
        out
    }
}

pub fn run() -> anyhow::Result<()> {
    let spec: RxSpec = spec_read()?;
    let bind = if spec.bind.contains(':') {
        format!("[{}]:{}", spec.bind, spec.port)
    } else {
        format!("{}:{}", spec.bind, spec.port)
    };
    let socket = UdpSocket::bind(&bind)?;
    unsafe {
        libc::setsockopt(
            std::os::unix::io::AsRawFd::as_raw_fd(&socket),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &RECV_BUFFER as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;

    // Announced before the sender starts, so the opening packets are not
    // counted as loss.
    emit(&json!({"ready": true}));

    let mut tally = Tally::new();
    let mut previous: i64 = -1;
    let mut seen_seqs: HashSet<u64> = HashSet::new();
    let mut buffer = vec![0u8; 65535];
    let deadline = Instant::now() + Duration::from_secs_f64(spec.duration_s);

    while Instant::now() < deadline {
        let Ok((length, _)) = socket.recv_from(&mut buffer) else {
            continue;
        };
        if length < HEADER_BYTES {
            continue;
        }
        let now_ns = monotonic_ns();
        let seq = u64::from_be_bytes(buffer[0..8].try_into().unwrap());
        let tx_ns = u64::from_be_bytes(buffer[8..16].try_into().unwrap());
        tally.record(seq, now_ns as i64 - tx_ns as i64, &mut previous, &mut seen_seqs);
    }

    emit(&tally.stats());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(sequence: &[u64]) -> Tally {
        let mut tally = Tally::new();
        let mut previous = -1i64;
        let mut seen = HashSet::new();
        for (index, seq) in sequence.iter().enumerate() {
            tally.record(*seq, 10_000 * (index as i64 + 1), &mut previous, &mut seen);
        }
        tally
    }

    #[test]
    fn clean_sequence_has_no_loss_or_reordering() {
        let stats = feed(&[0, 1, 2, 3, 4]).stats();
        assert_eq!(stats["packets_received"], 5);
        assert_eq!(stats["lost"], 0);
        assert_eq!(stats["reordered"], 0);
        assert_eq!(stats["duplicates"], 0);
        assert_eq!(stats["loss_percent"], 0.0);
    }

    #[test]
    fn a_gap_counts_as_loss() {
        let stats = feed(&[0, 1, 4]).stats();
        assert_eq!(stats["packets_expected"], 5);
        assert_eq!(stats["packets_received"], 3);
        assert_eq!(stats["lost"], 2);
        assert_eq!(stats["loss_percent"], 40.0);
    }

    #[test]
    fn a_lower_sequence_than_its_predecessor_is_reordering() {
        let stats = feed(&[0, 1, 3, 2, 4]).stats();
        assert_eq!(stats["reordered"], 1);
        assert_eq!(stats["lost"], 0);
    }

    #[test]
    fn a_repeated_sequence_is_a_duplicate_not_a_loss() {
        let stats = feed(&[0, 1, 1, 2]).stats();
        assert_eq!(stats["duplicates"], 1);
        assert_eq!(stats["packets_received"], 4);
        assert_eq!(stats["lost"], 0);
    }

    #[test]
    fn delay_percentiles_and_ipdv() {
        let tally = feed(&[0, 1, 2, 3, 4]);
        let stats = tally.stats();
        assert_eq!(stats["owd_min_ms"], 0.01);
        assert_eq!(stats["owd_max_ms"], 0.05);
        assert_eq!(stats["owd_p50_ms"], 0.03);
        assert_eq!(stats["owd_samples"], 5);
        // Each step is 10 us, so the mean absolute change is 10 us.
        assert_eq!(stats["ipdv_mean_ms"], 0.01);
    }

    #[test]
    fn nothing_received_reports_no_delay_fields() {
        let stats = Tally::new().stats();
        assert_eq!(stats["packets_received"], 0);
        assert_eq!(stats["packets_expected"], 0);
        assert!(stats.get("owd_mean_ms").is_none());
    }
}
