//! Entry list component

use leptos::*;

use crate::state::AppState;

/// Entry list component
#[component]
pub fn EntryList() -> impl IntoView {
    let state = expect_context::<AppState>();

    // Search input handler
    let on_search = move |ev| {
        state.search_query.set(event_target_value(&ev));
    };

    view! {
        <div class="entry-list">
            <div class="entry-list-header">
                <div class="search-box">
                    <svg class="search-icon" viewBox="0 0 24 24" width="18" height="18">
                        <path fill="currentColor" d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/>
                    </svg>
                    <input
                        type="text"
                        class="search-input"
                        placeholder="Search entries..."
                        prop:value=move || state.search_query.get()
                        on:input=on_search
                    />
                </div>
                <span class="entry-count">
                    {move || {
                        let total = state.entries.get().len();
                        let filtered = state.filtered_entries().len();
                        if total == filtered {
                            format!("{} entries", total)
                        } else {
                            format!("{} of {} entries", filtered, total)
                        }
                    }}
                </span>
            </div>

            <div class="entry-list-items">
                <Show
                    when=move || !state.filtered_entries().is_empty()
                    fallback=|| view! {
                        <div class="empty-state">
                            <p>"No entries found"</p>
                        </div>
                    }
                >
                    <For
                        each=move || state.filtered_entries()
                        key=|entry| entry.uuid.clone()
                        children=move |entry| {
                            let uuid = entry.uuid.clone();
                            let title = entry.title.clone();
                            let username = entry.username.clone();
                            let icon_letter = title.chars().next().unwrap_or('?').to_uppercase().to_string();

                            view! {
                                <EntryListItem
                                    uuid=uuid
                                    title=title
                                    username=username
                                    icon_letter=icon_letter
                                />
                            }
                        }
                    />
                </Show>
            </div>

            <div class="entry-list-footer">
                <button class="btn btn-primary btn-small" disabled=true title="Coming soon">
                    "+ New Entry"
                </button>
            </div>
        </div>
    }
}

/// A single entry in the list
#[component]
fn EntryListItem(
    uuid: String,
    title: String,
    username: String,
    icon_letter: String,
) -> impl IntoView {
    let state = expect_context::<AppState>();
    let uuid_for_selected = uuid.clone();
    let uuid_for_click = uuid.clone();
    let has_username = !username.is_empty();

    view! {
        <div
            class="entry-item"
            class:selected=move || state.selected_entry.get().as_ref() == Some(&uuid_for_selected)
            on:click=move |_| state.selected_entry.set(Some(uuid_for_click.clone()))
        >
            <div class="entry-icon">
                {icon_letter}
            </div>
            <div class="entry-info">
                <div class="entry-title">{title}</div>
                <div class="entry-username">
                    {if has_username {
                        view! { <span>{username}</span> }.into_view()
                    } else {
                        view! { <span class="no-username">"No username"</span> }.into_view()
                    }}
                </div>
            </div>
        </div>
    }
}
