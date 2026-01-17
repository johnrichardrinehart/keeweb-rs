//! KeeWeb-RS Frontend
//!
//! A Leptos-based web frontend for the KeeWeb-RS password manager.

mod app;
mod argon2_client;
mod components;
pub mod helper_client;
mod state;
mod utils;
mod worker_client;

use wasm_bindgen::prelude::*;

/// Initialize the application
#[wasm_bindgen(start)]
pub fn main() {
    // Set up panic hook for better error messages
    console_error_panic_hook::set_once();

    // Initialize logging
    console_log::init_with_level(log::Level::Debug).expect("Failed to initialize logger");

    log::info!("KeeWeb-RS starting...");

    // Mount the Leptos app
    leptos::mount_to_body(app::App);

    log::info!("KeeWeb-RS mounted");
}
