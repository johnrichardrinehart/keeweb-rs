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
                <Show when=move || state.database.get().is_some()>
                    <span class="database-name">
                        {move || state.database_name.get()}
                    </span>
                </Show>
            </div>
            <div class="header-right">
                <Show when=move || state.database.get().is_some()>
                    <button
                        class="btn btn-secondary"
                        on:click=move |_| state.close_database()
                    >
                        "Close"
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
