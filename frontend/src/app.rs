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
        ChangesDialog, LockGuard, MergeConflicts, install_save_shortcut, install_unload_guard,
    },
    icons::{Icon, UiIcon},
    panes::{Pane, Splitter, fit, viewport_width},
    sidebar::Sidebar,
    theme_toggle::ThemeToggle,
    unlock_dialog::UnlockDialog,
};
use crate::helper_client;
use crate::kdf::init_argon2;
use crate::state::{AppState, AppView, HelperStatus, init_theme, load_pane_widths};

/// Root application component
#[component]
pub fn App() -> impl IntoView {
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

    let unlocking = move || state.view() == AppView::Unlock;
    // Each vault gets fresh components, so per-component state never leaks between tabs.
    let active = create_memo(move |_| state.active.get());

    view! {
        <div class="app">
            <Header />
            <VaultTabs />
            <main class="app-main">
                <div
                    class="app-content"
                    inert=unlocking
                    aria-hidden=move || if unlocking() { "true" } else { "false" }
                >
                    {move || match active.get() {
                        Some(_) => view! { <DatabaseView /> }.into_view(),
                        None => view! { <FilePicker /> }.into_view(),
                    }}
                </div>

                // Unlock dialog overlay
                <Show when=unlocking>
                    <UnlockDialog />
                </Show>

                <LockGuard />
                <ChangesDialog />
                <MergeConflicts />
                <DatabaseSettings />

                // Auto-lock countdown modal
                <AutoLock />
            </main>
            <BuildFooter />
        </div>
    }
}

/// Source revision of this build and its commit time.
#[component]
fn BuildFooter() -> impl IntoView {
    let revision = option_env!("GIT_REVISION").unwrap_or("dev");
    let committed = option_env!("GIT_COMMITTED_AT")
        .and_then(|seconds| seconds.parse::<i64>().ok())
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
        .map(crate::model::format_local);

    view! {
        <footer class="app-footer">
            "keeweb-rs "
            <span class="app-footer-revision">{revision}</span>
            {committed.map(|time| format!(" · built on {time}"))}
        </footer>
    }
}

/// Header component with app title and actions
#[component]
fn Header() -> impl IntoView {
    let state = expect_context::<AppState>();
    let in_database = move || state.active.with(Option::is_some);

    view! {
        <header class="app-header" class:in-database=in_database>
            <div class="header-left">
                <div class="brand-mark" aria-hidden="true">
                    <svg viewBox="0 0 24 24" width="22" height="22">
                        <path fill="currentColor" d="M12 2 4.5 5v5.8c0 4.7 3.2 9.1 7.5 10.2 4.3-1.1 7.5-5.5 7.5-10.2V5L12 2Zm0 4.1a3 3 0 0 1 1 5.8v3.6h-2v-3.6a3 3 0 0 1 1-5.8Z"/>
                    </svg>
                </div>
                <Show when=in_database>
                    <SaveControls />
                </Show>
                <div class="brand-copy">
                    <h1 class="app-title">"KeeWeb RS"</h1>
                    <span class="app-subtitle">"A private KeePass vault"</span>
                </div>
                <Show when=in_database>
                    <span class="database-name">
                        {move || state.active_name().unwrap_or_default()}
                    </span>
                </Show>
            </div>
            <div class="header-right">
                <span
                    class="helper-status"
                    class:helper-status-connected=move || state.helper_status.get() == HelperStatus::Connected
                    aria-live="polite"
                >
                    <span class="status-dot"></span>
                    <span class="helper-status-text">
                        {move || match state.helper_status.get() {
                            HelperStatus::Checking => "Checking helper",
                            HelperStatus::Connected => "Native helper ready",
                            HelperStatus::Unavailable => "Browser mode",
                        }}
                    </span>
                </span>
                <div class="header-actions">
                    <ThemeToggle />
                    <Show when=in_database>
                        <button
                            type="button"
                            class="btn-icon"
                            on:click=move |_| state.show_settings.set(true)
                            title="Database settings"
                            aria-label="Database settings"
                        >
                            <UiIcon icon=Icon::Settings />
                        </button>
                        <button
                            type="button"
                            class="btn-icon"
                            on:click=move |_| state.show_picker()
                            title="Close vault (it stays unlocked in its tab)"
                            aria-label="Close vault"
                        >
                            <UiIcon icon=Icon::LogOut />
                        </button>
                        <button
                            type="button"
                            class="btn-icon"
                            on:click=move |_| state.request_lock()
                            title="Lock this vault and forget its keys"
                            aria-label="Lock vault"
                        >
                            <UiIcon icon=Icon::Lock />
                        </button>
                    </Show>
                </div>
            </div>
        </header>
    }
}

/// Tabs of the unlocked vaults, and one that shows the vault picker.
#[component]
fn VaultTabs() -> impl IntoView {
    let state = expect_context::<AppState>();

    view! {
        <Show when=move || state.tabs.with(|tabs| !tabs.is_empty())>
            // Narrow screens hide the strip while the only unlocked vault is open: the
            // header's close button already leads back to the picker.
            <nav
                class="vault-tabs"
                class:single-open=move || {
                    state.tabs.with(|tabs| tabs.len() == 1) && state.active.with(Option::is_some)
                }
                aria-label="Unlocked vaults"
                inert=move || state.view() == AppView::Unlock
            >
                <For
                    each=move || state.tabs.get()
                    key=|tab| (tab.id, tab.name.clone(), tab.dirty)
                    children=move |tab| {
                        let id = tab.id;
                        let selected = move || state.active.get() == Some(id);
                        view! {
                            <button
                                type="button"
                                class="vault-tab"
                                class:active=selected
                                aria-current=move || selected().then_some("true")
                                title=tab.name.clone()
                                on:click=move |_| state.activate(id)
                            >
                                <span class="vault-tab-name">{tab.name}</span>
                                {tab.dirty.then(|| view! {
                                    <span class="vault-tab-dirty" aria-hidden="true"></span>
                                    <span class="visually-hidden">" (unsaved changes)"</span>
                                })}
                            </button>
                        }
                    }
                />
                <button
                    type="button"
                    class="vault-tab vault-tab-new"
                    class:active=move || state.active.with(Option::is_none)
                    aria-current=move || state.active.with(Option::is_none).then_some("true")
                    title="Open another vault"
                    aria-label="Open another vault"
                    on:click=move |_| state.show_picker()
                >
                    <UiIcon icon=Icon::Plus size=16 />
                </button>
            </nav>
        </Show>
    }
}

/// Unsaved-change count and the Save button.
#[component]
fn SaveControls() -> impl IntoView {
    let state = expect_context::<AppState>();
    let count = move || state.changes.with(Vec::len);

    view! {
        <div class="save-controls">
            {move || (count() == 0).then(|| state.save_notice.get().map(|notice| view! {
                <span class="save-notice" role="status">{notice}</span>
            }))}
            <div class="save-split">
                <button
                    type="button"
                    class="btn btn-primary btn-save"
                    disabled=move || count() == 0 || state.saving.get()
                    on:click=move |_| state.save_in_background()
                    title="Save (Ctrl+S)"
                >
                    <UiIcon icon=Icon::Save size=16 />
                    <span class="btn-label">{move || if state.saving.get() { "Saving…" } else { "Save" }}</span>
                </button>
                <Show when=move || count() != 0>
                    <button
                        type="button"
                        class="btn btn-primary save-count"
                        on:click=move |_| state.show_changes.set(true)
                        title="Show unsaved changes"
                        aria-label=move || format!("Show {} unsaved changes", count())
                    >
                        {count}
                    </button>
                </Show>
            </div>
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

    // A new view per vault, so this loads the widths of the vault becoming active.
    state.pane_widths.set(
        state
            .active_vault_key()
            .map(|vault| load_pane_widths(&vault))
            .unwrap_or_default(),
    );
    let viewport = create_rw_signal(viewport_width());
    let resize_listener =
        window_event_listener(ev::resize, move |_| viewport.set(viewport_width()));
    on_cleanup(move || resize_listener.remove());
    let resizing = create_rw_signal(false);
    let column_widths = move || {
        let (sidebar, list) = fit(state.pane_widths.get(), viewport.get());
        format!("--sidebar-width: {sidebar}px; --list-width: {list}px")
    };

    view! {
        <div
            class="database-view"
            class:groups-open=move || groups_open.get()
            class:has-panel=has_panel
            class:resizing=move || resizing.get()
            class:two-column=move || state.two_column.get()
            style=column_widths
        >
            <Sidebar />
            <Splitter pane=Pane::Sidebar viewport=viewport.read_only() resizing=resizing />
            <div class="groups-backdrop" on:click=move |_| groups_open.set(false)></div>
            <div class="content-area">
                <EntryList />
                <Splitter pane=Pane::List viewport=viewport.read_only() resizing=resizing />
                <Show when=has_panel>
                    <EntryPanel />
                </Show>
            </div>
            <Show when=move || state.error_message.get().is_some()>
                <div class="toast toast-error" role="alert">
                    <UiIcon icon=Icon::CircleAlert />
                    <span>{move || state.error_message.get().unwrap_or_default()}</span>
                    <button
                        type="button"
                        class="btn-icon btn-icon-sm"
                        on:click=move |_| state.error_message.set(None)
                        title="Dismiss"
                        aria-label="Dismiss"
                    >
                        <UiIcon icon=Icon::X size=16 />
                    </button>
                </div>
            </Show>
        </div>
    }
}
