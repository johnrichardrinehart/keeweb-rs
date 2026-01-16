//! Server-Sent Events for real-time updates

use crate::state::{AppState, FileEvent};
use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::stream::Stream;
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

/// SSE endpoint for file events
pub async fn events(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.events_tx.subscribe();

    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let data = match &event {
                FileEvent::FileChanged { path } => {
                    serde_json::json!({
                        "type": "file_changed",
                        "path": path
                    })
                }
                FileEvent::FileDeleted { path } => {
                    serde_json::json!({
                        "type": "file_deleted",
                        "path": path
                    })
                }
                FileEvent::ConflictDetected { original, conflict } => {
                    serde_json::json!({
                        "type": "conflict_detected",
                        "original": original,
                        "conflict": conflict
                    })
                }
            };

            Some(Ok(Event::default().data(data.to_string())))
        }
        Err(_) => None,
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}
