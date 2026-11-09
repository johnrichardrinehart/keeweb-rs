//! Entry list component

use leptos::*;
use uuid::Uuid;

use crate::app::GroupsDrawer;
use crate::components::icons::{Icon, KeepassIcon, UiIcon};
use crate::components::shortcuts::SEARCH_SHORTCUT;
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

    // The cursor starts on the best match whenever the query changes, and stays put
    // while only the rows change, e.g. after an edit, as long as its row remains.
    let cursor = state.search_cursor;
    create_effect(move |previous: Option<String>| {
        let query = state.search_query.get();
        rows.with(|rows| {
            let kept = previous.as_deref() == Some(query.as_str())
                && cursor
                    .get_untracked()
                    .is_some_and(|uuid| rows.iter().any(|row| row.uuid == uuid));
            if crate::search::Query::parse(&query).is_none() {
                if !kept {
                    cursor.set(None);
                }
            } else if !kept {
                cursor.set(rows.first().map(|row| row.uuid));
            }
        });
        query
    });
    let searching = create_rw_signal(false);
    let move_cursor = move |step: isize| {
        rows.with_untracked(|rows| {
            let Some(last) = rows.len().checked_sub(1) else {
                return;
            };
            let current = cursor
                .get_untracked()
                .and_then(|uuid| rows.iter().position(|row| row.uuid == uuid));
            let next = match current {
                Some(index) => index.saturating_add_signed(step).min(last),
                None if step < 0 => last,
                None => 0,
            };
            cursor.set(Some(rows[next].uuid));
        });
    };
    let on_search_key = move |event: web_sys::KeyboardEvent| {
        if event.is_composing() || event.ctrl_key() || event.meta_key() || event.alt_key() {
            return;
        }
        match event.key().as_str() {
            "ArrowDown" => move_cursor(1),
            "ArrowUp" => move_cursor(-1),
            "Enter" => {
                let Some(uuid) = cursor.get_untracked() else {
                    return;
                };
                state.editor.set(None);
                state.selected_entry.set(Some(uuid));
            }
            "Escape" if state.search_query.with_untracked(|query| !query.is_empty()) => {
                state.search_query.set(String::new());
            }
            _ => return,
        }
        event.prevent_default();
    };
    let active_row = move || searching.get().then(|| cursor.get()).flatten().map(row_id);

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
                            title=format!("Search entries ({})", SEARCH_SHORTCUT.label())
                            aria-keyshortcuts=SEARCH_SHORTCUT.aria()
                            role="combobox"
                            aria-autocomplete="list"
                            aria-expanded="true"
                            aria-controls="entry-results"
                            aria-activedescendant=active_row
                            prop:value=move || state.search_query.get()
                            on:input=on_search
                            on:keydown=on_search_key
                            on:focus=move |_| searching.set(true)
                            on:blur=move |_| searching.set(false)
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

            <div class="entry-list-items" id="entry-results">
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
                        children=move |row| view! { <EntryListItem row=row searching=searching /> }
                    />
                </Show>
            </div>
        </div>
    }
}

/// Element ID of the list row of entry `uuid`.
fn row_id(uuid: Uuid) -> String {
    format!("entry-{uuid}")
}

/// A single entry in the list: title, then username and group path on one line.
/// `searching` is whether the search box has focus, which shows the search cursor.
#[component]
fn EntryListItem(row: EntryRow, searching: RwSignal<bool>) -> impl IntoView {
    let state = expect_context::<AppState>();
    let uuid = row.uuid;
    let selected = move || state.selected_entry.get() == Some(uuid);
    let at_cursor = create_memo(move |_| state.search_cursor.get() == Some(uuid));
    let shows_cursor = move || searching.get() && at_cursor.get();
    let node = create_node_ref::<html::Button>();
    // Keeps the cursor row on screen as the arrow keys move it. Tracks the node too,
    // since the row mounts after this first runs.
    create_effect(move |_| {
        let element = node.get();
        if let (true, Some(element)) = (at_cursor.get(), element) {
            let options = web_sys::ScrollIntoViewOptions::new();
            options.set_block(web_sys::ScrollLogicalPosition::Nearest);
            element.scroll_into_view_with_scroll_into_view_options(&options);
        }
    });
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
            class:cursor=shows_cursor
            id=row_id(uuid)
            node_ref=node
            aria-current=move || selected().then_some("true")
            title=row.title.clone()
            // Copy shortcuts act on the row with focus, see `shortcuts::ENTRY_ATTRIBUTE`.
            data-entry=uuid.to_string()
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
