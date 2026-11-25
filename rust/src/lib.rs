// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

//! traffic-generator: a multi-port traffic generator driven over MCP.
//!
//! The daemon owns a pool of physical NICs and nothing else; it never logs into
//! the device under test. Each port lives in its own network namespace so a flow
//! between two ports must leave the host and cross the device.

pub mod capture;
pub mod config;
pub mod core;
pub mod echo;
pub mod engines;
pub mod helpers;
pub mod leases;
pub mod mcp;
pub mod netns;
pub mod runs;
pub mod shell;
pub mod web;
