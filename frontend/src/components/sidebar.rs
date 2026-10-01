//! Sidebar component with group tree navigation and group actions

use keeweb_wasm::document::{Change, GroupEdit, GroupView};
use leptos::*;
use std::collections::{BTreeSet, HashSet};
use uuid::Uuid;
use wasm_bindgen::{JsCast, JsValue};

use crate::components::dialog::{ConfirmDialog, Dialog, GroupPicker};
use crate::components::icons::{Icon, IconPicker, KeepassIcon, UiIcon};
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

/// Action menu of one group row.
#[derive(Clone)]
struct OpenMenu {
    group: Uuid,
    /// Fixed-position placement next to the button that opened the menu.
    style: String,
    /// Takes the focus back when the menu is dismissed.
    trigger: web_sys::HtmlElement,
}

/// Group dialog and row menu state shared by the tree rows.
#[derive(Clone, Copy)]
struct GroupActions {
    modal: RwSignal<Option<GroupModal>>,
    menu: RwSignal<Option<OpenMenu>>,
}

/// Sidebar component
#[component]
pub fn Sidebar() -> impl IntoView {
    let state = expect_context::<AppState>();
    let modal = create_rw_signal(Option::<GroupModal>::None);
    let menu = create_rw_signal(Option::<OpenMenu>::None);
    provide_context(GroupActions { modal, menu });

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
            <nav class="sidebar-nav" aria-label="Groups and tags">
                <div class="sidebar-section">
                    <AllEntriesItem />
                </div>

                <div class="sidebar-section">
                    <div class="sidebar-section-header">
                        <h3>"Groups"</h3>
                        <button
                            type="button"
                            class="btn btn-ghost btn-sm"
                            title="New group in the selected group"
                            disabled=move || state.saving.get()
                            on:click=move |_| {
                                if let Some(parent) = state.target_group() {
                                    modal.set(Some(GroupModal::Create { parent }));
                                }
                            }
                        >
                            <UiIcon icon=Icon::FolderPlus size=16 />
                            "New group"
                        </button>
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

            {move || menu.get().map(|open| view! { <GroupMenu open=open /> })}

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
            on:click=move |_| {
                state.selected_group.set(None);
                state.selected_tag.set(None);
                state.selected_entry.set(None);
                state.editor.set(None);
            }
        >
            <span class="group-icon">
                <UiIcon icon=Icon::Layers size=16 />
            </span>
            // Gives the row keyboard focus; its click bubbles to the row handler.
            <button type="button" class="group-name" aria-current=move || is_selected().then_some("true")>
                "All Entries"
            </button>
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
    let name = model::group_display_name(&group);
    let children: Vec<GroupView> = groups
        .iter()
        .filter(|child| child.parent == Some(uuid))
        .cloned()
        .collect();
    let indent = format!("padding-left: {}px", 8 + depth * 16);
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
                {if children.is_empty() {
                    // Keeps leaf names aligned with the names of folders that have a toggle.
                    view! { <span class="group-toggle-space" aria-hidden="true"></span> }.into_view()
                } else {
                    view! {
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
                            <UiIcon icon=Icon::ChevronRight size=16 />
                        </button>
                    }.into_view()
                }}
                <span class="group-icon">
                    <KeepassIcon icon_id=group.icon_id custom_icon=group.custom_icon />
                </span>
                <button type="button" class="group-name" aria-current=move || is_selected().then_some("true")>
                    {name.clone()}
                </button>
                <GroupMenuButton group=uuid name=name />
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

/// The actions a group's menu offers, as (icon, label, dialog, destructive).
fn group_menu_items(group: &GroupView) -> Vec<(Icon, &'static str, GroupModal, bool)> {
    let uuid = group.uuid;
    if group.is_recycle_bin {
        return vec![(
            Icon::Trash,
            "Empty recycle bin…",
            GroupModal::EmptyBin,
            true,
        )];
    }
    let mut items = Vec::with_capacity(4);
    if !group.in_recycle_bin {
        items.push((
            Icon::FolderPlus,
            "New subgroup",
            GroupModal::Create { parent: uuid },
            false,
        ));
    }
    items.push((Icon::Pencil, "Edit", GroupModal::Edit(uuid), false));
    if group.parent.is_some() {
        items.push((Icon::FolderInput, "Move…", GroupModal::Move(uuid), false));
        items.push((Icon::Trash, "Delete…", GroupModal::Delete(uuid), true));
    }
    items
}

/// Button that opens the action menu of a group row.
#[component]
fn GroupMenuButton(group: Uuid, name: String) -> impl IntoView {
    let state = expect_context::<AppState>();
    let actions = expect_context::<GroupActions>();
    let open = move || {
        actions
            .menu
            .with(|menu| menu.as_ref().is_some_and(|menu| menu.group == group))
    };
    let button_ref = create_node_ref::<html::Button>();

    view! {
        <button
            type="button"
            class="btn-icon btn-icon-sm group-menu-button"
            node_ref=button_ref
            class:open=open
            title="Group actions"
            aria-label=format!("Actions for {name}")
            aria-haspopup="menu"
            aria-expanded=move || open().to_string()
            on:click=move |event| {
                // Opening the menu does not select the folder.
                event.stop_propagation();
                let Some(button) = button_ref.get_untracked() else {
                    return;
                };
                let trigger: &web_sys::HtmlElement = &button;
                let trigger = trigger.clone();
                let items = state.group(group).map_or(0, |group| group_menu_items(&group).len());
                let style = menu_position(&trigger, items);
                actions.menu.set(Some(OpenMenu { group, style, trigger }));
            }
        >
            <UiIcon icon=Icon::Ellipsis size=16 />
        </button>
    }
}

/// Fixed-position style that right-aligns the menu with `trigger` and opens it below,
/// or above when the viewport has no room below.
fn menu_position(trigger: &web_sys::HtmlElement, items: usize) -> String {
    let Some([top, right, bottom]) = viewport_rect(trigger) else {
        return String::new();
    };
    let window = web_sys::window();
    let viewport = |size: Option<Result<JsValue, JsValue>>| {
        size.and_then(Result::ok)
            .and_then(|value| value.as_f64())
            .unwrap_or_default()
    };
    let width = viewport(window.as_ref().map(web_sys::Window::inner_width));
    let height = viewport(window.as_ref().map(web_sys::Window::inner_height));
    // Upper bound of the menu height: touch-sized items plus the menu padding.
    let menu_height = items as f64 * 44.0 + 12.0;
    let horizontal = format!("right: {:.0}px", (width - right).max(8.0));
    if bottom + 4.0 + menu_height > height && top - 4.0 - menu_height >= 0.0 {
        format!("{horizontal}; bottom: {:.0}px", height - top + 4.0)
    } else {
        format!("{horizontal}; top: {:.0}px", bottom + 4.0)
    }
}

/// Viewport position of `element` as [top, right, bottom]. Goes through `js_sys`
/// because the crate does not enable the `DomRect` binding of `web_sys`.
fn viewport_rect(element: &web_sys::HtmlElement) -> Option<[f64; 3]> {
    let measure = js_sys::Reflect::get(element, &JsValue::from_str("getBoundingClientRect"))
        .ok()?
        .dyn_into::<js_sys::Function>()
        .ok()?;
    let rect = measure.call0(element).ok()?;
    let side = |name: &str| {
        js_sys::Reflect::get(&rect, &JsValue::from_str(name))
            .ok()?
            .as_f64()
    };
    Some([side("top")?, side("right")?, side("bottom")?])
}

/// Menu of one group's actions. Arrow keys move between items; Escape, Tab, or a click
/// outside closes it.
#[component]
fn GroupMenu(open: OpenMenu) -> impl IntoView {
    let state = expect_context::<AppState>();
    let actions = expect_context::<GroupActions>();
    let Some(group) = state.group(open.group) else {
        return ().into_view();
    };
    let items = group_menu_items(&group);
    let menu_ref = create_node_ref::<html::Div>();
    let trigger = store_value(open.trigger);

    let close = move |refocus: bool| {
        // Closing disposes this component and its stored values, so take the trigger first.
        let trigger = refocus.then(|| trigger.get_value());
        actions.menu.set(None);
        if let Some(trigger) = trigger {
            let _ = trigger.focus();
        }
    };
    menu_ref.on_load(move |menu| {
        request_animation_frame(move || focus_item(&menu, |_, _| Some(0)));
    });
    let on_keydown = move |event: web_sys::KeyboardEvent| {
        let Some(menu) = menu_ref.get_untracked() else {
            return;
        };
        let step = |current: Option<usize>, count: usize| match event.key().as_str() {
            "ArrowDown" => Some(current.map_or(0, |index| (index + 1) % count)),
            "ArrowUp" => Some(current.map_or(count - 1, |index| (index + count - 1) % count)),
            "Home" => Some(0),
            "End" => Some(count - 1),
            _ => None,
        };
        match event.key().as_str() {
            "Escape" => {
                event.prevent_default();
                event.stop_propagation();
                close(true);
            }
            "Tab" => close(false),
            "ArrowDown" | "ArrowUp" | "Home" | "End" => {
                event.prevent_default();
                focus_item(&menu, step);
            }
            _ => {}
        }
    };

    view! {
        <div class="menu-backdrop" on:click=move |_| close(false)></div>
        <div
            class="menu"
            role="menu"
            aria-label=format!("Actions for {}", model::group_display_name(&group))
            style=open.style
            node_ref=menu_ref
            on:keydown=on_keydown
        >
            {items.into_iter().map(|(icon, label, action, destructive)| view! {
                <button
                    type="button"
                    role="menuitem"
                    tabindex="-1"
                    class="menu-item"
                    class:menu-item-danger=destructive
                    disabled=move || state.saving.get()
                    on:click=move |_| {
                        close(false);
                        actions.modal.set(Some(action));
                    }
                >
                    <UiIcon icon=icon size=16 />
                    <span>{label}</span>
                </button>
            }).collect_view()}
        </div>
    }
    .into_view()
}

/// Focuses the menu item that `pick` chooses from the index of the focused item and
/// the number of enabled items.
fn focus_item(menu: &web_sys::HtmlElement, pick: impl Fn(Option<usize>, usize) -> Option<usize>) {
    let Ok(nodes) = menu.query_selector_all("[role=menuitem]:not(:disabled)") else {
        return;
    };
    let items: Vec<web_sys::HtmlElement> = (0..nodes.length())
        .filter_map(|index| nodes.item(index))
        .filter_map(|node| node.dyn_into::<web_sys::HtmlElement>().ok())
        .collect();
    if items.is_empty() {
        return;
    }
    let focused = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.active_element());
    let current = focused.and_then(|focused| {
        items
            .iter()
            .position(|item| AsRef::<web_sys::Element>::as_ref(item) == &focused)
    });
    if let Some(item) = pick(current, items.len()).and_then(|index| items.get(index)) {
        let _ = item.focus();
    }
}

/// A clickable tag item
#[component]
fn TagItem(tag: String) -> impl IntoView {
    let state = expect_context::<AppState>();
    let tag_for_selected = tag.clone();
    let tag_for_click = tag.clone();

    let selected = create_memo(move |_| {
        state
            .selected_tag
            .with(|selected| selected.as_ref() == Some(&tag_for_selected))
    });
    let is_selected = move || selected.get();

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
                <UiIcon icon=Icon::Tag size=16 />
            </span>
            <button type="button" class="group-name" aria-current=move || is_selected().then_some("true")>
                {tag}
            </button>
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
