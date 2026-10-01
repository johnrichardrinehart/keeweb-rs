//! Main application component

use leptos::*;
use wasm_bindgen_futures::spawn_local;

use crate::components::{
    auto_lock::AutoLock,
    database_settings::DatabaseSettings,
    entry_detail::EntryPanel,
    entry_list::EntryList,
    file_picker::FilePicker,
    guard::{
        ChangesDialog, DepartureGuard, MergeConflicts, install_save_shortcut, install_unload_guard,
    },
    sidebar::Sidebar,
    theme_toggle::ThemeToggle,
    unlock_dialog::UnlockDialog,
};
use crate::helper_client;
use crate::kdf::init_argon2;
use crate::state::{AppState, AppView, Departure, HelperStatus, init_theme};

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

    install_unload_guard(state);
    install_save_shortcut(state);

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

                <DepartureGuard />
                <ChangesDialog />
                <MergeConflicts />
                <DatabaseSettings />

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
    let in_database = move || state.current_view.get() == AppView::Database;

    view! {
        <header class="app-header" class:in-database=in_database>
            <div class="header-left">
                <div class="brand-mark" aria-hidden="true">
                    <svg viewBox="0 0 24 24" width="22" height="22">
                        <path fill="currentColor" d="M12 2 4.5 5v5.8c0 4.7 3.2 9.1 7.5 10.2 4.3-1.1 7.5-5.5 7.5-10.2V5L12 2Zm0 4.1a3 3 0 0 1 1 5.8v3.6h-2v-3.6a3 3 0 0 1 1-5.8Z"/>
                    </svg>
                </div>
                <div class="brand-copy">
                    <h1 class="app-title">"KeeWeb RS"</h1>
                    <span class="app-subtitle">"A private KeePass vault"</span>
                </div>
                <Show when=in_database>
                    <span class="database-name">
                        {move || state.database_name.get()}
                    </span>
                </Show>
            </div>
            <div class="header-right">
                <Show when=in_database>
                    <SaveControls />
                </Show>
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
                <Show when=in_database>
                    <button
                        class="theme-toggle"
                        on:click=move |_| state.show_settings.set(true)
                        title="Database settings"
                        aria-label="Database settings"
                    >
                        <svg viewBox="0 0 24 24" width="19" height="19">
                            <path fill="currentColor" d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94L14.4 2.81c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41L9.25 5.35c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/>
                        </svg>
                    </button>
                    <button
                        class="btn btn-secondary btn-lock"
                        on:click=move |_| state.request_departure(Departure::Close)
                        title="Close this vault and open another"
                        aria-label="Close vault"
                    >
                        <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
                            <path fill="currentColor" d="M10.09 15.59 11.5 17l5-5-5-5-1.41 1.41L12.67 11H3v2h9.67l-2.58 2.59ZM19 3H5a2 2 0 0 0-2 2v4h2V5h14v14H5v-4H3v4a2 2 0 0 0 2 2h14c1.1 0 2-.9 2-2V5a2 2 0 0 0-2-2Z"/>
                        </svg>
                        "Close"
                    </button>
                    <button
                        class="btn btn-secondary btn-lock"
                        on:click=move |_| state.request_departure(Departure::Lock)
                        title="Lock database"
                        aria-label="Lock vault"
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

/// Unsaved-change count and the Save button.
#[component]
fn SaveControls() -> impl IntoView {
    let state = expect_context::<AppState>();
    let count = move || state.changes.with(Vec::len);

    view! {
        <div class="save-controls">
            {move || {
                if count() > 0 {
                    view! {
                        <button
                            class="unsaved-pill"
                            on:click=move |_| state.show_changes.set(true)
                            title="Show unsaved changes"
                        >
                            {format!("{} unsaved", count())}
                        </button>
                    }.into_view()
                } else {
                    state.save_notice.get().map(|notice| view! {
                        <span class="save-notice" role="status">{notice}</span>
                    }).into_view()
                }
            }}
            <button
                class="btn btn-primary btn-save"
                disabled=move || count() == 0 || state.saving.get()
                on:click=move |_| state.save_in_background()
                title="Save (Ctrl+S)"
            >
                {move || if state.saving.get() { "Saving…" } else { "Save" }}
            </button>
        </div>
    }
}

/// Open state of the group drawer that replaces the sidebar on narrow screens.
#[derive(Clone, Copy)]
pub struct GroupsDrawer(pub RwSignal<bool>);

/// Main database view with sidebar, entry list, and detail panel
#[component]
fn DatabaseView() -> impl IntoView {
    let state = expect_context::<AppState>();

    let groups_open = create_rw_signal(false);
    provide_context(GroupsDrawer(groups_open));
    // Choosing a group or tag in the narrow-screen drawer closes it.
    create_effect(move |_| {
        state.selected_group.track();
        state.selected_tag.track();
        groups_open.set(false);
    });
    let has_panel = move || state.selected_entry.get().is_some() || state.editor.get().is_some();

    view! {
        <div
            class="database-view"
            class:groups-open=move || groups_open.get()
            class:has-panel=has_panel
        >
            <Sidebar />
            <div class="groups-backdrop" on:click=move |_| groups_open.set(false)></div>
            <div class="content-area">
                <EntryList />
                <Show when=has_panel>
                    <EntryPanel />
                </Show>
            </div>
            <Show when=move || state.error_message.get().is_some()>
                <div class="toast toast-error" role="alert">
                    <span>{move || state.error_message.get().unwrap_or_default()}</span>
                    <button
                        class="btn-icon"
                        on:click=move |_| state.error_message.set(None)
                        aria-label="Dismiss"
                    >
                        <svg viewBox="0 0 24 24" width="18" height="18">
                            <path fill="currentColor" d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
                        </svg>
                    </button>
                </div>
            </Show>
        </div>
    }
}
