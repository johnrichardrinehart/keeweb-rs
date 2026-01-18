//! keeweb-server - Optional backend for keeweb-rs
//!
//! Provides:
//! - Directory monitoring for KDBX files
//! - Syncthing conflict detection
//! - File serving API
//! - SSE for real-time updates

mod config;
mod routes;
mod services;
mod state;

use axum::{
    Router,
    routing::{get, post},
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "keeweb_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = config::Config::load()?;
    tracing::info!("Loaded configuration");

    // Create application state
    let state = Arc::new(AppState::new(config.clone()));

    // Start file watcher
    if !config.storage.watch_directories.is_empty() {
        services::watcher::start_watcher(state.clone()).await?;
        tracing::info!(
            "Started watching {} directories",
            config.storage.watch_directories.len()
        );
    }

    // Build router
    let app = Router::new()
        .route("/health", get(routes::health))
        .route("/api/files", get(routes::files::list_files))
        .route("/api/files/:path", get(routes::files::download_file))
        .route("/api/conflicts", get(routes::files::list_conflicts))
        .route("/api/events", get(routes::sse::events))
        .route("/api/settings", get(routes::settings::get_settings))
        .route("/api/argon2", post(routes::argon2::compute_argon2))
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http());

    // Start server
    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .expect("Invalid server address");

    tracing::info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

mod anyhow {
    pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
}
