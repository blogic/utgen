// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::Json;
use clap::Parser;
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

use tgend::config::{config_load, ConfigError, CONFIG_ENV_VAR};
use tgend::core::Core;
use tgend::mcp::TgenServer;

const SWEEP_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Parser, Debug)]
#[command(name = "tgend", about = "traffic-generator MCP daemon")]
struct Args {
    /// Helper mode. Each runs inside a port's namespace under `ip netns exec`,
    /// reading one JSON spec on stdin, because entering a namespace needs setns
    /// and that would move the whole daemon.
    #[command(subcommand)]
    helper: Option<Helper>,
    /// Config path. Defaults to $TGEN_CONFIG, then /etc/traffic-generator/config.json.
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    /// Override the configured bind address.
    #[arg(long)]
    host: Option<String>,
    /// Override the configured bind port.
    #[arg(long)]
    port: Option<u16>,
    #[arg(long, default_value = "info")]
    log_level: String,
}

/// Guards the MCP endpoint with a shared bearer token.
///
/// rmcp's own auth is a full OAuth 2.1 resource server and needs an issuer; a
/// lab tool on a private network wants one static credential.
async fn bearer_auth(
    State(expected): State<Arc<String>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let offered = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    if !constant_time_eq(offered.as_bytes(), expected.as_bytes()) {
        tracing::warn!(
            method = %request.method(),
            path = %request.uri().path(),
            "rejected unauthenticated request"
        );
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(serde_json::json!({
                "error": "unauthorized",
                "detail": "send 'Authorization: Bearer <token>'",
            })),
        )
            .into_response();
    }
    next.run(request).await
}

/// Compare without leaking the matching prefix length through timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Make lease expiry reclaim hardware by itself.
///
/// Sweeping only on API entry means a client that crashes without releasing
/// holds its physical ports until some unrelated call happens to sweep.
async fn sweep_loop(core: Arc<Core>) {
    let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let expired = core.sweep().await;
        if !expired.is_empty() {
            tracing::warn!(count = expired.len(), "swept expired leases");
        }
    }
}

#[derive(clap::Subcommand, Debug)]
enum Helper {
    /// Sequence-numbered UDP sender.
    ProbeTx,
    /// Sequence-numbered UDP receiver; prints readiness then the statistics.
    ProbeRx,
    /// Connection generator for flow-table tests.
    FlowSource,
    /// Counting sink for flow-table tests.
    FlowSink,
    /// Echo service reporting the source address it observed.
    Echo,
    /// Crafted frame injection over AF_PACKET.
    Inject,
}

async fn helper_run(helper: Helper) -> anyhow::Result<()> {
    match helper {
        Helper::ProbeTx => tgend::helpers::probe_tx::run(),
        Helper::ProbeRx => tgend::helpers::probe_rx::run(),
        Helper::FlowSource => tgend::helpers::flow_source::run().await,
        Helper::FlowSink => tgend::helpers::flow_sink::run().await,
        Helper::Echo => tgend::helpers::echo::run().await,
        Helper::Inject => tgend::helpers::inject::run(),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if let Some(helper) = args.helper {
        return helper_run(helper).await;
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("tgend={},rmcp=info", args.log_level).into()),
        )
        .init();

    let cfg = match config_load(args.config) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("tgend: {err}");
            if matches!(err, ConfigError::Missing { .. }) {
                eprintln!("tgend: set ${CONFIG_ENV_VAR} or pass --config");
            }
            std::process::exit(2);
        }
    };

    let host = args.host.unwrap_or_else(|| cfg.mcp.host.clone());
    let port = args.port.unwrap_or(cfg.mcp.port);
    let path = cfg.mcp.path.clone();
    let token = Arc::new(format!("Bearer {}", cfg.mcp.token));
    let allowed_hosts = cfg.mcp.allowed_hosts.clone();
    let allowed_origins = cfg.mcp.allowed_origins.clone();
    let web = cfg.web.clone();
    let labels: Vec<&str> = cfg.ports.iter().map(|p| p.label.as_str()).collect();
    tracing::info!(config = %cfg.path.display(), ports = ?labels, "loaded");

    let core = Arc::new(Core::new(cfg)?);
    let state = core.reconcile().await;
    if state["orphans_cleaned"].as_array().is_some_and(|a| !a.is_empty()) {
        tracing::warn!(
            ports = %state["orphans_cleaned"],
            "released stranded ports from a previous run"
        );
    }
    if state["teardown_failed"].as_array().is_some_and(|a| !a.is_empty()) {
        tracing::error!(
            ports = %state["teardown_failed"],
            "could not release stranded ports; they stay out of the pool"
        );
    }
    if state["foreign"].as_array().is_some_and(|a| !a.is_empty()) {
        tracing::error!(
            namespaces = %state["foreign"],
            "namespaces named like ours but holding another device, left alone; \
             another daemon is probably sharing netns_prefix"
        );
    }
    if state["strays"].as_array().is_some_and(|a| !a.is_empty()) {
        tracing::warn!(
            namespaces = %state["strays"],
            "namespaces matching our prefix but not in the pool, left alone"
        );
    }

    tokio::spawn(sweep_loop(Arc::clone(&core)));

    // json_response keeps replies a single JSON body rather than SSE, and
    // NeverSessionManager with legacy_session_mode off means a client reconnect
    // needs no session recovery: the state that matters lives in the lease.
    let service_core = Arc::clone(&core);
    let service = StreamableHttpService::new(
        move || Ok(TgenServer::new(Arc::clone(&service_core))),
        Arc::new(NeverSessionManager::default()),
        {
            // StreamableHttpServerConfig is #[non_exhaustive], so it is mutated
            // from Default rather than built with a struct literal.
            let mut http = StreamableHttpServerConfig::default();
            http.json_response = true;
            http.legacy_session_mode = false;
            http.allowed_hosts = allowed_hosts;
            http.allowed_origins = allowed_origins;
            http
        },
    );

    let app = axum::Router::new()
        .route_service(&path, service)
        .layer(middleware::from_fn_with_state(token, bearer_auth));

    // The status page is a separate listener on purpose: it is read-only and
    // unauthenticated, so it must not sit behind the same router as the MCP
    // endpoint, which needs the token.
    if let Some(web) = web {
        let address = format!("{}:{}", web.host, web.port);
        let listener = tokio::net::TcpListener::bind(&address).await?;
        let router = tgend::web::router(Arc::clone(&core));
        tracing::info!("status page http://{address}/ (read-only, no auth)");
        tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, router).await {
                tracing::error!(%err, "status page stopped");
            }
        });
    }

    let address = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&address).await?;
    tracing::info!("MCP endpoint http://{address}{path} (bearer token required)");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn token_comparison_rejects_differences_and_lengths() {
        assert!(constant_time_eq(b"Bearer abc", b"Bearer abc"));
        assert!(!constant_time_eq(b"Bearer abc", b"Bearer abd"));
        assert!(!constant_time_eq(b"Bearer abc", b"Bearer ab"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }
}
