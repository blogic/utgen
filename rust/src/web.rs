// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

//! A read-only status page: ports, leases, endpoints, runs and recent logs.
//!
//! Separate listener from the MCP endpoint, and deliberately unauthenticated so
//! a browser can just open it. It exposes no mutating route: everything that
//! changes hardware goes through MCP, which needs the bearer token.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::core::Core;
use crate::shell::command_run;

const JOURNALCTL: &str = "/usr/bin/journalctl";
const PAGE: &str = include_str!("web/index.html");
const MAX_LOG_LINES: usize = 500;

#[derive(Debug, Deserialize)]
pub struct LogQuery {
    #[serde(default = "default_lines")]
    lines: usize,
}

fn default_lines() -> usize {
    80
}

pub fn router(core: Arc<Core>) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/guide.md", get(guide))
        .route("/api/status", get(status))
        .route("/api/logs", get(logs))
        .with_state(core)
}

async fn page() -> impl IntoResponse {
    Html(PAGE)
}

/// The same guide the MCP resource serves, for a client that would rather fetch
/// a URL than speak MCP.
async fn guide() -> impl IntoResponse {
    ([(axum::http::header::CONTENT_TYPE, "text/markdown; charset=utf-8")], crate::mcp::GUIDE)
}

async fn status(State(core): State<Arc<Core>>) -> Json<Value> {
    let ports = core.ports_list().await.unwrap_or_default();
    let endpoints = core.endpoints_list().await.unwrap_or_default();
    Json(json!({
        "ports": ports,
        "leases": core.leases_list().await,
        "endpoints": endpoints,
        "runs": core.runs.list(15).iter().map(|r| r.public()).collect::<Vec<_>>(),
        "captures": core.captures_list().await,
        "echoes": core.echoes_list().await,
        "mcp": format!("{}:{}{}", core.cfg.mcp.host, core.cfg.mcp.port, core.cfg.mcp.path),
        "config": core.cfg.path.display().to_string(),
    }))
}

async fn logs(Query(query): Query<LogQuery>) -> Json<Value> {
    let lines = query.lines.clamp(1, MAX_LOG_LINES);
    let out = command_run(
        &crate::argv![
            JOURNALCTL, "-u", "tgend", "-n", lines, "--no-pager", "-o", "short-iso"
        ],
        Duration::from_secs(15),
        None,
    )
    .await;
    Json(json!({
        "lines": out.stdout.lines().map(str::to_string).collect::<Vec<_>>(),
        "source": "journalctl -u tgend",
        "available": out.ok(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_is_embedded_and_self_contained() {
        // Served from the binary, so there is no asset directory to install and
        // no framework to fetch at runtime.
        assert!(PAGE.contains("<!doctype html>"));
        assert!(PAGE.contains("/api/status"));
        assert!(PAGE.contains("/api/logs"));
        assert!(!PAGE.contains("http://"), "no external asset should be fetched");
        assert!(!PAGE.contains("https://"), "no external asset should be fetched");
    }

    #[test]
    fn the_guide_travels_with_the_binary() {
        // A session driving this is on another machine and cannot read the
        // repository, so a stale copy on disk would be worse than none.
        assert!(crate::mcp::GUIDE.contains("Call order"));
        assert!(crate::mcp::GUIDE.contains("never logs into the device"));
        assert!(crate::mcp::GUIDE.len() > 2000, "guide looks truncated");
    }

    #[test]
    fn log_line_counts_are_clamped() {
        // Straight from a query string, and journalctl is happy to return
        // everything it has.
        assert_eq!(0usize.clamp(1, MAX_LOG_LINES), 1);
        assert_eq!(100_000usize.clamp(1, MAX_LOG_LINES), MAX_LOG_LINES);
        assert_eq!(80usize.clamp(1, MAX_LOG_LINES), 80);
    }
}
