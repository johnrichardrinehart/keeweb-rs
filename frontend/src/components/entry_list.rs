//! Entry list component

use leptos::*;
use uuid::Uuid;

use crate::app::GroupsDrawer;
use crate::components::icons::{Icon, KeepassIcon, UiIcon};
use crate::model::{self, USER_NAME};
use crate::state::{AppState, EntryEditor};
use keeweb_wasm::document::GroupView;

/// What a list row shows. Used as the `<For>` key so edits re-render the row.
#[derive(Clone, PartialEq, Eq, Hash)]
struct EntryRow {
    uuid: Uuid,
    title: String,
    username: String,
    /// Group path below the root, empty for entries in the root group.
    path: String,
    icon_id: u32,
    custom_icon: Option<Uuid>,
}

/// Entry list component
#[component]
pub fn EntryList() -> impl IntoView {
    let state = expect_context::<AppState>();

    let rows = create_memo(move |_| {
        state.groups.with(|groups| {
            state
                .filtered_entries()
                .iter()
                .map(|entry| EntryRow {
                    uuid: entry.uuid,
                    title: model::display_title(entry),
                    username: model::field(entry, USER_NAME).to_string(),
                    path: location(groups, entry.group),
                    icon_id: entry.icon_id,
                    custom_icon: entry.custom_icon,
                })
                .collect::<Vec<_>>()
        })
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
    let drawer = expect_context::<GroupsDrawer>();
    let scope_label = move || {
        if let Some(tag) = state.selected_tag.get() {
            return format!("#{tag}");
        }
        state
            .selected_group
            .get()
            .and_then(|uuid| {
                state.groups.with(|groups| {
                    groups
                        .iter()
                        .find(|g| g.uuid == uuid)
                        .map(|g| g.name.clone())
                })
            })
            .unwrap_or_else(|| "All Entries".to_string())
    };

    let count_label = move || {
        let shown = rows.with(Vec::len);
        let total = total.get();
        if shown == total {
            format!("{total} entries")
        } else {
            format!("{shown} of {total} entries")
        }
    };
    // Narrow screens drop the count row, so the placeholder carries the count.
    let placeholder = move || format!("Search {} entries", rows.with(Vec::len));
    let groups_label = move || format!("Groups (showing {})", scope_label());

    view! {
        <div class="entry-list">
            <div class="entry-list-header">
                <div class="entry-list-toolbar">
                    <button
                        type="button"
                        class="btn btn-secondary groups-toggle"
                        on:click=move |_| drawer.0.set(true)
                        title=groups_label
                        aria-label=groups_label
                    >
                        <UiIcon icon=Icon::Folder size=16 />
                        <span class="groups-toggle-label" aria-hidden="true">{scope_label}</span>
                    </button>
                    <div class="search-box">
                        <span class="search-icon">
                            <UiIcon icon=Icon::Search size=16 />
                        </span>
                        <input
                            type="text"
                            class="search-input"
                            placeholder=placeholder
                            aria-label="Search entries"
                            prop:value=move || state.search_query.get()
                            on:input=on_search
                        />
                        <Show when=move || state.search_query.with(|query| !query.is_empty())>
                            <span class="search-count" aria-hidden="true">
                                {move || format!("{}/{}", rows.with(Vec::len), total.get())}
                            </span>
                        </Show>
                    </div>
                    <button
                        type="button"
                        class="btn btn-primary new-entry-button"
                        title="New entry in the selected group"
                        aria-label="New entry"
                        disabled=move || state.saving.get() || state.groups.with(|groups| groups.is_empty())
                        on:click=new_entry
                    >
                        <UiIcon icon=Icon::Plus />
                        <span class="btn-label">"New"</span>
                    </button>
                </div>
                <div class="entry-list-meta">
                    <span class="entry-scope">{scope_label}</span>
                    <span class="entry-count">{count_label}</span>
                </div>
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
        </div>
    }
}

/// A single entry in the list: title, then username and group path on one line.
#[component]
fn EntryListItem(row: EntryRow) -> impl IntoView {
    let state = expect_context::<AppState>();
    let uuid = row.uuid;
    let selected = move || state.selected_entry.get() == Some(uuid);
    let letter = row
        .title
        .chars()
        .next()
        .unwrap_or('?')
        .to_uppercase()
        .to_string();
    let username = (!row.username.is_empty()).then(|| {
        view! { <span class="entry-username">{row.username.clone()}</span> }
    });
    let path = (!row.path.is_empty()).then(|| {
        view! {
            <span class="entry-path">
                <UiIcon icon=Icon::Folder size=12 />
                {row.path.clone()}
            </span>
        }
    });
    let neither = username.is_none() && path.is_none();
    view! {
        <button
            type="button"
            class="entry-item"
            class:selected=selected
            aria-current=move || selected().then_some("true")
            title=row.title.clone()
            on:click=move |_| {
                state.editor.set(None);
                state.selected_entry.set(Some(uuid));
            }
        >
            <span class="entry-icon">
                <KeepassIcon icon_id=row.icon_id custom_icon=row.custom_icon fallback=letter />
            </span>
            <span class="entry-info">
                <span class="entry-title">{row.title}</span>
                <span class="entry-sub">
                    {username}
                    {path}
                    {neither.then(|| view! { <span class="no-username">"No username"</span> })}
                </span>
            </span>
        </button>
    }
}

/// Group path without the root group name, which every entry shares.
fn location(groups: &[GroupView], group: Uuid) -> String {
    let path = model::group_path(groups, group);
    match path.split_once(" / ") {
        Some((_, below_root)) => below_root.to_string(),
        None => String::new(),
    }
}
