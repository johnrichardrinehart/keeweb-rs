//! Main application component

use leptos::*;

use crate::components::{
    entry_detail::EntryDetail, entry_list::EntryList, file_picker::FilePicker, sidebar::Sidebar,
    unlock_dialog::UnlockDialog,
};
use crate::state::{AppState, AppView};

/// Root application component
#[component]
pub fn App() -> impl IntoView {
    // Create the global application state
    let state = AppState::new();
    provide_context(state);

    view! {
        <div class="app">
            <Header />
            <main class="app-main">
                <Show
                    when=move || state.current_view.get() == AppView::FilePicker
                    fallback=move || view! { <DatabaseView /> }
                >
                    <FilePicker />
                </Show>

                // Unlock dialog overlay
                <Show when=move || state.current_view.get() == AppView::Unlock>
                    <UnlockDialog />
                </Show>
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
                <h1 class="app-title">"KeeWeb-RS"</h1>
                <Show when=move || state.current_view.get() == AppView::Database>
                    <span class="database-name">
                        {move || state.database_name.get()}
                    </span>
                </Show>
            </div>
            <div class="header-right">
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
