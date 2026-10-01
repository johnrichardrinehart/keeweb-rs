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
    http::{HeaderValue, header::ETAG},
    routing::{get, post, put},
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
                .unwrap_or_else(|_| "warn,keeweb_server=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = config::Config::load()?;
    tracing::info!("Loaded configuration");

    // Create application state and prepare its single top-level database path.
    if let Some(directory) = &config.storage.database_directory {
        tokio::fs::create_dir_all(directory).await?;
    }
    let state = Arc::new(AppState::new(config.clone()));

    if config.storage.database_directory.is_some() {
        services::watcher::start_watcher(state.clone()).await?;
        tracing::info!("Started database directory watcher");
    }

    // Build router. Storage deployments can disable native key derivation.
    let mut app = Router::new()
        .route("/health", get(routes::health))
        .route("/api/files", get(routes::files::list_files))
        .route(
            "/api/files/:path",
            get(routes::files::download_file).put(routes::files::upload_file),
        )
        .route("/api/files/:id/content", put(routes::files::replace_file))
        .route("/api/conflicts", get(routes::files::list_conflicts))
        .route("/api/events", get(routes::sse::events))
        .route("/api/settings", get(routes::settings::get_settings));
    if config.server.argon2_enabled {
        app = app.route("/api/argon2", post(routes::argon2::compute_argon2));
    }
    let mut app = app.with_state(state).layer(TraceLayer::new_for_http());
    if let Some(origin) = &config.server.cors_origin {
        let origin = HeaderValue::from_str(origin)?;
        app = app.layer(
            CorsLayer::new()
                .allow_origin(origin)
                .allow_methods(Any)
                .allow_headers(Any)
                .expose_headers([ETAG]),
        );
    }

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
