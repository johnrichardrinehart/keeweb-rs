//! Sidebar component with group tree navigation and group actions

use keeweb_wasm::document::{Change, GroupEdit, GroupView};
use leptos::*;
use std::collections::{BTreeSet, HashSet};
use uuid::Uuid;

use crate::components::dialog::{ConfirmDialog, Dialog, GroupPicker};
use crate::components::icons::{IconPicker, KeepassIcon};
use crate::model;
use crate::state::AppState;

/// Group dialog the sidebar shows.
#[derive(Clone, Copy, PartialEq, Eq)]
enum GroupModal {
    Create { parent: Uuid },
    Edit(Uuid),
    Move(Uuid),
    Delete(Uuid),
    EmptyBin,
}

/// Sidebar component
#[component]
pub fn Sidebar() -> impl IntoView {
    let state = expect_context::<AppState>();
    let modal = create_rw_signal(Option::<GroupModal>::None);

    // Collect all unique tags from entries outside the recycle bin
    let all_tags = create_memo(move |_| {
        state.entries.with(|entries| {
            entries
                .iter()
                .filter(|entry| !entry.in_recycle_bin)
                .flat_map(|entry| entry.tags.iter())
                .filter(|tag| !tag.is_empty())
                .cloned()
                .collect::<BTreeSet<String>>()
                .into_iter()
                .collect::<Vec<_>>()
        })
    });

    let selected = move || {
        state
            .selected_group
            .get()
            .and_then(|uuid| state.group(uuid))
    };
    let is_root = move |group: &GroupView| group.parent.is_none();
    let located = create_memo(move |_| {
        let entry = state.selected_entry.get()?;
        state
            .entries
            .with(|entries| entries.iter().find(|e| e.uuid == entry).map(|e| e.group))
    });
    provide_context(LocatedGroup(located));
    // Start from the IsExpanded flags stored in the vault.
    let collapsed = create_rw_signal(state.groups.with_untracked(|groups| {
        groups
            .iter()
            .filter(|group| !group.is_expanded && group.parent.is_some())
            .map(|group| group.uuid)
            .collect::<HashSet<Uuid>>()
    }));
    provide_context(CollapsedGroups(collapsed));
    // Expand the folders above the open entry so its folder stays visible.
    create_effect(move |_| {
        let Some(group) = located.get() else {
            return;
        };
        let ancestors = state.groups.with_untracked(|groups| {
            let mut found = Vec::new();
            let mut current = groups
                .iter()
                .find(|g| g.uuid == group)
                .and_then(|g| g.parent);
            while let Some(uuid) = current {
                found.push(uuid);
                current = groups
                    .iter()
                    .find(|g| g.uuid == uuid)
                    .and_then(|g| g.parent);
                if found.len() > groups.len() {
                    break;
                }
            }
            found
        });
        if collapsed.with_untracked(|set| ancestors.iter().any(|uuid| set.contains(uuid))) {
            collapsed.update(|set| {
                ancestors.iter().for_each(|uuid| {
                    set.remove(uuid);
                })
            });
        }
    });

    view! {
        <aside class="sidebar">
            <nav class="sidebar-nav">
                <div class="sidebar-section">
                    <AllEntriesItem />
                </div>

                <div class="sidebar-divider"></div>

                <div class="sidebar-section">
                    <div class="sidebar-section-header">
                        <h3>"Groups"</h3>
                    </div>
                    <div class="group-tree">
                        {move || {
                            let groups = state.groups.get();
                            groups
                                .iter()
                                .filter(|group| group.parent.is_none())
                                .map(|root| view! { <GroupTreeNode groups=groups.clone() group=root.clone() depth=0 /> })
                                .collect_view()
                        }}
                    </div>
                </div>

                <Show when=move || all_tags.with(|tags| !tags.is_empty())>
                    <div class="sidebar-divider"></div>
                    <div class="sidebar-section">
                        <div class="sidebar-section-header">
                            <h3>"Tags"</h3>
                        </div>
                        <div class="tag-list">
                            <For
                                each=move || all_tags.get()
                                key=|tag| tag.clone()
                                children=move |tag| view! { <TagItem tag=tag /> }
                            />
                        </div>
                    </div>
                </Show>
            </nav>

            <div class="sidebar-footer">
                <button
                    class="btn btn-small btn-secondary"
                    disabled=move || state.saving.get()
                    on:click=move |_| {
                        if let Some(parent) = state.target_group() {
                            modal.set(Some(GroupModal::Create { parent }));
                        }
                    }
                >
                    "+ New Group"
                </button>
                {move || selected().map(|group| {
                    let uuid = group.uuid;
                    if group.is_recycle_bin {
                        view! {
                            <button
                                class="btn btn-small btn-danger"
                                disabled=move || state.saving.get()
                                on:click=move |_| modal.set(Some(GroupModal::EmptyBin))
                            >
                                "Empty bin"
                            </button>
                        }.into_view()
                    } else {
                        let root = is_root(&group);
                        view! {
                            <button
                                class="btn btn-small btn-secondary"
                                disabled=move || state.saving.get()
                                on:click=move |_| modal.set(Some(GroupModal::Edit(uuid)))
                            >
                                "Edit"
                            </button>
                            {(!root).then(|| view! {
                                <button
                                    class="btn btn-small btn-secondary"
                                    disabled=move || state.saving.get()
                                    on:click=move |_| modal.set(Some(GroupModal::Move(uuid)))
                                >
                                    "Move"
                                </button>
                                <button
                                    class="btn btn-small btn-danger"
                                    disabled=move || state.saving.get()
                                    on:click=move |_| modal.set(Some(GroupModal::Delete(uuid)))
                                >
                                    "Delete"
                                </button>
                            })}
                        }.into_view()
                    }
                })}
            </div>

            {move || modal.get().map(|current| {
                let close = Callback::new(move |_| modal.set(None));
                match current {
                    GroupModal::Create { parent } => view! {
                        <GroupEditor parent=Some(parent) group=None on_close=close />
                    }.into_view(),
                    GroupModal::Edit(uuid) => view! {
                        <GroupEditor parent=None group=Some(uuid) on_close=close />
                    }.into_view(),
                    GroupModal::Move(uuid) => {
                        let name = state.group(uuid).map(|group| model::group_display_name(&group)).unwrap_or_default();
                        let current = state.group(uuid).and_then(|group| group.parent);
                        let excluded = state.groups.with_untracked(|groups| model::subtree(groups, uuid));
                        view! {
                            <GroupPicker
                                title=format!("Move “{name}”")
                                current=current
                                excluded=excluded
                                on_pick=move |parent| {
                                    modal.set(None);
                                    state.apply_or_report(Change::MoveGroup { uuid, parent });
                                }
                                on_close=close
                            />
                        }.into_view()
                    }
                    GroupModal::Delete(uuid) => {
                        let Some(group) = state.group(uuid) else {
                            return ().into_view();
                        };
                        let name = model::group_display_name(&group);
                        let to_bin = !group.in_recycle_bin
                            && state.meta.with_untracked(|meta| meta.as_ref().is_some_and(|meta| meta.recycle_bin_enabled));
                        let message = if to_bin {
                            format!("“{name}” and everything in it will move to the recycle bin.")
                        } else {
                            format!("“{name}” and everything in it will be deleted permanently when you save.")
                        };
                        view! {
                            <ConfirmDialog
                                title="Delete group?"
                                message=message
                                confirm_label={if to_bin { "Move to recycle bin" } else { "Delete permanently" }}
                                on_confirm=move |_| {
                                    modal.set(None);
                                    if state.apply_or_report(Change::DeleteGroup { uuid }).is_some() {
                                        state.selected_group.set(None);
                                    }
                                }
                                on_close=close
                            />
                        }.into_view()
                    }
                    GroupModal::EmptyBin => view! {
                        <ConfirmDialog
                            title="Empty the recycle bin?"
                            message="Everything in the recycle bin will be deleted permanently when you save."
                            confirm_label="Empty recycle bin"
                            on_confirm=move |_| {
                                modal.set(None);
                                state.apply_or_report(Change::EmptyRecycleBin);
                            }
                            on_close=close
                        />
                    }.into_view(),
                }
            })}
        </aside>
    }
}

#[component]
fn AllEntriesItem() -> impl IntoView {
    let state = expect_context::<AppState>();
    let is_selected =
        move || state.selected_group.get().is_none() && state.selected_tag.get().is_none();
    view! {
        <div
            class="group-item"
            class:selected=is_selected
            style="padding-left: 0.5rem"
            on:click=move |_| {
                state.selected_group.set(None);
                state.selected_tag.set(None);
                state.selected_entry.set(None);
                state.editor.set(None);
            }
        >
            <span class="group-icon">
                <svg viewBox="0 0 24 24" width="16" height="16">
                    <path fill="currentColor" d="M20 6h-8l-2-2H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2zm0 12H4V8h16v10z"/>
                </svg>
            </span>
            <span class="group-name">"All Entries"</span>
        </div>
    }
}

/// Group that holds the entry open in the detail panel.
#[derive(Clone, Copy)]
struct LocatedGroup(Memo<Option<Uuid>>);

/// Folders the user collapsed in this view. View state only: it never edits the vault.
#[derive(Clone, Copy)]
struct CollapsedGroups(RwSignal<HashSet<Uuid>>);

/// A group and its children
#[component]
fn GroupTreeNode(
    groups: std::rc::Rc<Vec<GroupView>>,
    group: GroupView,
    depth: usize,
) -> impl IntoView {
    let state = expect_context::<AppState>();
    let uuid = group.uuid;
    let children: Vec<GroupView> = groups
        .iter()
        .filter(|child| child.parent == Some(uuid))
        .cloned()
        .collect();
    // Leaf folders get the toggle's width as extra indent so names line up.
    let indent = format!(
        "padding-left: {}rem",
        depth as f32 + if children.is_empty() { 1.6 } else { 0.5 }
    );
    let located = expect_context::<LocatedGroup>().0;
    let is_located = move || located.get() == Some(uuid);
    let item_ref = create_node_ref::<html::Div>();
    create_effect(move |_| {
        if is_located() {
            if let Some(item) = item_ref.get() {
                let options = web_sys::ScrollIntoViewOptions::new();
                options.set_block(web_sys::ScrollLogicalPosition::Nearest);
                item.scroll_into_view_with_scroll_into_view_options(&options);
            }
        }
    });
    let is_selected =
        move || state.selected_group.get() == Some(uuid) && state.selected_tag.get().is_none();
    let collapsed = expect_context::<CollapsedGroups>().0;
    let is_collapsed = move || collapsed.with(|set| set.contains(&uuid));

    view! {
        <div class="group-node">
            <div
                class="group-item"
                class:located=is_located
                node_ref=item_ref
                class:selected=is_selected
                class:recycle-bin=group.is_recycle_bin
                style=indent
                title=group.notes.clone()
                on:click=move |_| {
                    state.selected_group.set(Some(uuid));
                    state.selected_tag.set(None);
                    state.selected_entry.set(None);
                    state.editor.set(None);
                }
            >
                {(!children.is_empty()).then(|| view! {
                    <button
                        type="button"
                        class="group-toggle"
                        class:collapsed=is_collapsed
                        aria-label=move || if is_collapsed() { "Expand folder" } else { "Collapse folder" }
                        aria-expanded=move || if is_collapsed() { "false" } else { "true" }
                        on:click=move |event| {
                            // Toggling does not select the folder.
                            event.stop_propagation();
                            collapsed.update(|set| {
                                if !set.remove(&uuid) {
                                    set.insert(uuid);
                                }
                            });
                        }
                    >
                        <svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true">
                            <path fill="currentColor" d="M8.6 16.6 13.2 12 8.6 7.4 10 6l6 6-6 6-1.4-1.4Z"/>
                        </svg>
                    </button>
                })}
                <span class="group-icon">
                    <KeepassIcon icon_id=group.icon_id custom_icon=group.custom_icon />
                </span>
                <span class="group-name">{model::group_display_name(&group)}</span>
            </div>
            {(!children.is_empty()).then(|| view! {
                <div class="group-children" class:hidden=is_collapsed>
                    {children.into_iter().map(|child| view! {
                        <GroupTreeNode groups=groups.clone() group=child depth=depth + 1 />
                    }).collect_view()}
                </div>
            })}
        </div>
    }
}

/// A clickable tag item
#[component]
fn TagItem(tag: String) -> impl IntoView {
    let state = expect_context::<AppState>();
    let tag_for_selected = tag.clone();
    let tag_for_click = tag.clone();

    let is_selected = move || state.selected_tag.get().as_ref() == Some(&tag_for_selected);

    view! {
        <div
            class="group-item tag-item"
            class:selected=is_selected
            on:click=move |_| {
                state.selected_tag.set(Some(tag_for_click.clone()));
                state.selected_group.set(None);
                state.selected_entry.set(None);
                state.editor.set(None);
            }
        >
            <span class="group-icon tag-icon">
                <svg viewBox="0 0 24 24" width="16" height="16">
                    <path fill="currentColor" d="M21.41 11.58l-9-9C12.05 2.22 11.55 2 11 2H4c-1.1 0-2 .9-2 2v7c0 .55.22 1.05.59 1.42l9 9c.36.36.86.58 1.41.58.55 0 1.05-.22 1.41-.59l7-7c.37-.36.59-.86.59-1.41 0-.55-.23-1.06-.59-1.42zM5.5 7C4.67 7 4 6.33 4 5.5S4.67 4 5.5 4 7 4.67 7 5.5 6.33 7 5.5 7z"/>
                </svg>
            </span>
            <span class="group-name">{tag}</span>
        </div>
    }
}

/// Create a group under `parent`, or edit `group`.
#[component]
fn GroupEditor(
    parent: Option<Uuid>,
    group: Option<Uuid>,
    #[prop(into)] on_close: Callback<()>,
) -> impl IntoView {
    let state = expect_context::<AppState>();
    let existing = group.and_then(|uuid| state.group(uuid));
    let initial = existing
        .as_ref()
        .map(GroupView::to_edit)
        .unwrap_or_else(|| GroupEdit {
            icon_id: 48,
            ..GroupEdit::default()
        });
    let title = match &existing {
        Some(view) => format!("Edit “{}”", model::group_display_name(view)),
        None => "New group".to_string(),
    };

    let name = create_rw_signal(initial.name.clone());
    let notes = create_rw_signal(initial.notes.clone());
    let icon_id = create_rw_signal(initial.icon_id);
    let custom_icon = create_rw_signal(initial.custom_icon);
    let error = create_rw_signal(Option::<String>::None);
    let initial = store_value(initial);

    let submit = move || {
        if name.get_untracked().trim().is_empty() {
            error.set(Some("The group needs a name.".to_string()));
            return;
        }
        let edit = GroupEdit {
            name: name.get_untracked(),
            notes: notes.get_untracked(),
            icon_id: icon_id.get_untracked(),
            custom_icon: custom_icon.get_untracked(),
            ..initial.get_value()
        };
        let change = match (group, parent) {
            (Some(uuid), _) => Change::UpdateGroup { uuid, group: edit },
            (None, Some(parent)) => Change::CreateGroup {
                parent,
                group: edit,
            },
            (None, None) => return,
        };
        match state.apply(change) {
            Ok(outcome) => {
                if let Some(created) = outcome.created {
                    state.selected_group.set(Some(created));
                    state.selected_tag.set(None);
                    state.selected_entry.set(None);
                }
                on_close.call(());
            }
            Err(message) => error.set(Some(message)),
        }
    };

    view! {
        <Dialog title=title on_close=on_close class="group-dialog">
            <form on:submit=move |event| {
                event.prevent_default();
                submit();
            }>
                <div class="dialog-body">
                    <div class="form-group">
                        <label for="group-name">"Name"</label>
                        <input
                            id="group-name"
                            type="text"
                            class="form-input"
                            autofocus=true
                            prop:value=move || name.get()
                            on:input=move |event| name.set(event_target_value(&event))
                        />
                    </div>
                    <div class="form-group">
                        <label for="group-notes">"Notes"</label>
                        <textarea
                            id="group-notes"
                            class="form-input form-textarea"
                            prop:value=move || notes.get()
                            on:input=move |event| notes.set(event_target_value(&event))
                        ></textarea>
                    </div>
                    <div class="form-group">
                        <label>"Icon"</label>
                        <IconPicker icon_id=icon_id custom_icon=custom_icon />
                    </div>
                    <Show when=move || error.get().is_some()>
                        <div class="error-message" role="alert">{move || error.get().unwrap_or_default()}</div>
                    </Show>
                </div>
                <div class="dialog-footer">
                    <button type="button" class="btn btn-secondary" on:click=move |_| on_close.call(())>"Cancel"</button>
                    <button type="submit" class="btn btn-primary" disabled=move || state.saving.get()>
                        {if group.is_some() { "Apply" } else { "Create" }}
                    </button>
                </div>
            </form>
        </Dialog>
    }
}
