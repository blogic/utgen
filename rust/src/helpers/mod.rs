// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

//! Helpers that run inside a port's network namespace.
//!
//! Each is the same binary re-invoked as a subcommand under `ip netns exec`,
//! reading one JSON spec on stdin and printing JSON on stdout. Entering a
//! namespace from a running process means `setns`, which would move the whole
//! daemon, so a child process is the only clean way in.

pub mod echo;
pub mod flow_sink;
pub mod inject;
pub mod flow_source;
pub mod probe_rx;
pub mod probe_tx;

use std::io::Read;

/// CLOCK_MONOTONIC in nanoseconds.
///
/// Both ends of a flow are namespaces on one host, so this is the same clock at
/// both, and a receiver can subtract a sender's reading to get a true one-way
/// delay with no PTP synchronisation. That stops being true the moment the ends
/// are separate machines.
pub fn monotonic_ns() -> u64 {
    let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now);
    }
    now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
}

pub fn spec_read<T: serde::de::DeserializeOwned>() -> anyhow::Result<T> {
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text)?;
    Ok(serde_json::from_str(&text)?)
}

pub fn emit(value: &serde_json::Value) {
    println!("{value}");
}

/// Raise the descriptor limit towards `wanted`, since hitting it looks like
/// connection failure rather than a limit.
pub fn fd_limit_raise(wanted: u64) -> u64 {
    const HEADROOM: u64 = 4096;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return 0;
        }
    }
    let target = (wanted + HEADROOM).max(limit.rlim_cur).min(limit.rlim_max);
    if target > limit.rlim_cur {
        limit.rlim_cur = target;
        unsafe {
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
        }
    }
    target
}
