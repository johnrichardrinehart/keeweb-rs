//! Entry list component

use leptos::*;
use uuid::Uuid;

use crate::components::icons::KeepassIcon;
use crate::model::{self, USER_NAME};
use crate::state::{AppState, EntryEditor};

/// What a list row shows. Used as the `<For>` key so edits re-render the row.
#[derive(Clone, PartialEq, Eq, Hash)]
struct EntryRow {
    uuid: Uuid,
    title: String,
    username: String,
    icon_id: u32,
    custom_icon: Option<Uuid>,
}

/// Entry list component
#[component]
pub fn EntryList() -> impl IntoView {
    let state = expect_context::<AppState>();

    let rows = create_memo(move |_| {
        state
            .filtered_entries()
            .iter()
            .map(|entry| EntryRow {
                uuid: entry.uuid,
                title: model::display_title(entry),
                username: model::field(entry, USER_NAME).to_string(),
                icon_id: entry.icon_id,
                custom_icon: entry.custom_icon,
            })
            .collect::<Vec<_>>()
    });
    let total = create_memo(move |_| {
        state
            .entries
            .with(|entries| entries.iter().filter(|entry| !entry.in_recycle_bin).count())
    });

    let on_search = move |ev| {
        state.search_query.set(event_target_value(&ev));
    };

    let new_entry = move |_| {
        if let Some(group) = state.target_group() {
            state.selected_entry.set(None);
            state.editor.set(Some(EntryEditor::Create { group }));
        }
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
                        let shown = rows.with(Vec::len);
                        let total = total.get();
                        if shown == total {
                            format!("{total} entries")
                        } else {
                            format!("{shown} of {total} entries")
                        }
                    }}
                </span>
            </div>

            <div class="entry-list-items">
                <Show
                    when=move || rows.with(|rows| !rows.is_empty())
                    fallback=|| view! {
                        <div class="empty-state">
                            <p>"No entries found"</p>
                        </div>
                    }
                >
                    <For
                        each=move || rows.get()
                        key=|row| row.clone()
                        children=move |row| view! { <EntryListItem row=row /> }
                    />
                </Show>
            </div>

            <div class="entry-list-footer">
                <button
                    class="btn btn-primary btn-small"
                    disabled=move || state.saving.get() || state.groups.with(|groups| groups.is_empty())
                    on:click=new_entry
                >
                    "+ New Entry"
                </button>
            </div>
        </div>
    }
}

/// A single entry in the list
#[component]
fn EntryListItem(row: EntryRow) -> impl IntoView {
    let state = expect_context::<AppState>();
    let uuid = row.uuid;
    let has_username = !row.username.is_empty();
    let letter = row
        .title
        .chars()
        .next()
        .unwrap_or('?')
        .to_uppercase()
        .to_string();
    view! {
        <div
            class="entry-item"
            class:selected=move || state.selected_entry.get() == Some(uuid)
            on:click=move |_| {
                state.editor.set(None);
                state.selected_entry.set(Some(uuid));
            }
        >
            <div class="entry-icon">
                <KeepassIcon icon_id=row.icon_id custom_icon=row.custom_icon fallback=letter />
            </div>
            <div class="entry-info">
                <div class="entry-title">{row.title}</div>
                <div class="entry-username">
                    {if has_username {
                        view! { <span>{row.username}</span> }.into_view()
                    } else {
                        view! { <span class="no-username">"No username"</span> }.into_view()
                    }}
                </div>
            </div>
        </div>
    }
}
