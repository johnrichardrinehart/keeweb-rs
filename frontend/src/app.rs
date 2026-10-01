//! Main application component

use leptos::*;
use wasm_bindgen_futures::spawn_local;

use crate::components::{
    auto_lock::AutoLock, entry_detail::EntryDetail, entry_list::EntryList, file_picker::FilePicker,
    sidebar::Sidebar, theme_toggle::ThemeToggle, unlock_dialog::UnlockDialog,
};
use crate::helper_client;
use crate::state::{AppState, AppView, HelperStatus, init_argon2, init_theme};

/// Root application component
#[component]
pub fn App() -> impl IntoView {
    // Log git revision on startup
    let git_rev = option_env!("GIT_REVISION").unwrap_or("unknown");
    log::info!("keeweb-rs revision: {}", git_rev);

    // Create the global application state
    let state = AppState::new();
    provide_context(state);

    // Initialize theme (applies CSS)
    init_theme(state.theme.get());

    // Initialize argon2-pthread worker in background (for parallel KDF)
    // Note: The wasm-bindgen-rayon thread pool is initialized by initializer.js
    // before this code runs, so is_rayon_ready() will return true if it succeeded
    init_argon2(|result| match result {
        Ok(()) => {
            #[cfg(debug_assertions)]
            log::info!("Argon2-pthread initialized (parallel KDF ready)");
        }
        Err(_e) => {
            #[cfg(debug_assertions)]
            log::warn!("Argon2-pthread init failed: {} (will use fallback)", _e);
        }
    });

    // Probe the localhost helper once at startup. UnlockDialog keeps it fresh.
    spawn_local(async move {
        let status = if helper_client::try_auto_connect().await {
            HelperStatus::Connected
        } else {
            HelperStatus::Unavailable
        };
        state.helper_status.set(status);
    });

    view! {
        <div class="app">
            <Header />
            <main class="app-main">
                <div
                    class="app-content"
                    inert=move || state.current_view.get() == AppView::Unlock
                    aria-hidden=move || if state.current_view.get() == AppView::Unlock { "true" } else { "false" }
                >
                    <Show
                        when=move || state.current_view.get() != AppView::Database
                        fallback=move || view! { <DatabaseView /> }
                    >
                        <FilePicker />
                    </Show>
                </div>

                // Unlock dialog overlay
                <Show when=move || state.current_view.get() == AppView::Unlock>
                    <UnlockDialog />
                </Show>

                // Auto-lock countdown modal
                <AutoLock />
            </main>
        </div>
    }
}

/// Header component with app title and actions
#[component]
fn Header() -> impl IntoView {
    let state = expect_context::<AppState>();

    view! {
        <header class="app-header">
            <div class="header-left">
                <div class="brand-mark" aria-hidden="true">
                    <svg viewBox="0 0 24 24" width="22" height="22">
                        <path fill="currentColor" d="M12 2 4.5 5v5.8c0 4.7 3.2 9.1 7.5 10.2 4.3-1.1 7.5-5.5 7.5-10.2V5L12 2Zm0 4.1a3 3 0 0 1 1 5.8v3.6h-2v-3.6a3 3 0 0 1 1-5.8Z"/>
                    </svg>
                </div>
                <div class="brand-copy">
                    <h1 class="app-title">"KeeWeb RS"</h1>
                    <span class="app-subtitle">"A private KeePass reader"</span>
                </div>
                <Show when=move || state.current_view.get() == AppView::Database>
                    <span class="database-name">
                        {move || state.database_name.get()}
                    </span>
                </Show>
            </div>
            <div class="header-right">
                <span
                    class="helper-pill"
                    class:helper-pill-connected=move || state.helper_status.get() == HelperStatus::Connected
                    aria-live="polite"
                >
                    <span class="status-dot"></span>
                    {move || match state.helper_status.get() {
                        HelperStatus::Checking => "Checking helper",
                        HelperStatus::Connected => "Native helper ready",
                        HelperStatus::Unavailable => "Browser mode",
                    }}
                </span>
                <ThemeToggle />
                <Show when=move || state.current_view.get() == AppView::Database>
                    <button
                        class="btn btn-secondary btn-lock"
                        on:click=move |_| state.close_database()
                        title="Lock database"
                    >
                        <svg viewBox="0 0 24 24" width="16" height="16">
                            <path fill="currentColor" d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
                        </svg>
                        "Lock"
                    </button>
                </Show>
            </div>
        </header>
    }
}

/// Main database view with sidebar, entry list, and detail panel
#[component]
fn DatabaseView() -> impl IntoView {
    let state = expect_context::<AppState>();

    view! {
        <div class="database-view">
            <Sidebar />
            <div class="content-area">
                <EntryList />
                <Show when=move || state.selected_entry.get().is_some()>
                    <EntryDetail />
                </Show>
            </div>
        </div>
    }
}
