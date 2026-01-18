//! Sidebar component with group tree navigation

use leptos::*;
use std::collections::BTreeSet;

use crate::state::{AppState, GroupInfo};

/// Sidebar component
#[component]
pub fn Sidebar() -> impl IntoView {
    let state = expect_context::<AppState>();

    // Build a tree of groups from flat list
    let group_tree = move || {
        let groups = state.groups.get();
        build_group_tree(&groups)
    };

    // Collect all unique tags from entries
    let all_tags = move || {
        let entries = state.entries.get();
        let mut tags: BTreeSet<String> = BTreeSet::new();
        for entry in entries {
            for tag in entry.tags {
                if !tag.is_empty() {
                    tags.insert(tag);
                }
            }
        }
        tags.into_iter().collect::<Vec<_>>()
    };

    view! {
        <aside class="sidebar">
            <nav class="sidebar-nav">
                // All Entries at the top
                <div class="sidebar-section">
                    <GroupItem
                        uuid=None
                        name="All Entries".to_string()
                        depth=0
                        has_children=false
                        is_tag=false
                    />
                </div>

                <div class="sidebar-divider"></div>

                // Groups section
                <div class="sidebar-section">
                    <div class="sidebar-section-header">
                        <h3>"Groups"</h3>
                    </div>
                    <div class="group-tree">
                        <For
                            each=group_tree
                            key=|group| group.uuid.clone()
                            children=move |group| {
                                view! {
                                    <GroupTreeNode group=group depth=0 />
                                }
                            }
                        />
                    </div>
                </div>

                // Tags section (only show if there are tags)
                <Show when=move || !all_tags().is_empty()>
                    <div class="sidebar-divider"></div>
                    <div class="sidebar-section">
                        <div class="sidebar-section-header">
                            <h3>"Tags"</h3>
                        </div>
                        <div class="tag-list">
                            <For
                                each=all_tags
                                key=|tag| tag.clone()
                                children=move |tag| {
                                    view! {
                                        <TagItem tag=tag />
                                    }
                                }
                            />
                        </div>
                    </div>
                </Show>
            </nav>

            <div class="sidebar-footer">
                <button class="btn btn-small btn-secondary" disabled=true title="Coming soon">
                    "+ New Group"
                </button>
            </div>
        </aside>
    }
}

/// A single group in the tree
#[component]
fn GroupTreeNode(group: GroupNode, depth: usize) -> impl IntoView {
    let has_children = !group.children.is_empty();
    let children = group.children.clone();

    view! {
        <div class="group-node">
            <GroupItem
                uuid=Some(group.uuid.clone())
                name=group.name.clone()
                depth=depth
                has_children=has_children
                is_tag=false
            />
            {if has_children {
                let children = children.clone();
                view! {
                    <div class="group-children">
                        <For
                            each=move || children.clone()
                            key=|child| child.uuid.clone()
                            children=move |child| {
                                view! {
                                    <GroupTreeNode group=child depth=depth + 1 />
                                }
                            }
                        />
                    </div>
                }.into_view()
            } else {
                view! { <span></span> }.into_view()
            }}
        </div>
    }
}

/// A clickable group item
#[component]
fn GroupItem(
    uuid: Option<String>,
    name: String,
    depth: usize,
    has_children: bool,
    #[prop(default = false)] is_tag: bool,
) -> impl IntoView {
    let state = expect_context::<AppState>();
    let uuid_for_selected = uuid.clone();
    let uuid_for_click = uuid.clone();

    let indent = format!("padding-left: {}rem", depth as f32 * 1.0 + 0.5);

    // Check if this item is selected (for groups, not tags)
    let is_selected = move || {
        !is_tag
            && state.selected_group.get() == uuid_for_selected
            && state.selected_tag.get().is_none()
    };

    view! {
        <div
            class="group-item"
            class:selected=is_selected
            style=indent
            on:click=move |_| {
                state.selected_group.set(uuid_for_click.clone());
                state.selected_tag.set(None);
                state.selected_entry.set(None);
            }
        >
            <span class="group-icon">
                {if has_children {
                    view! {
                        <svg viewBox="0 0 24 24" width="16" height="16">
                            <path fill="currentColor" d="M20 6h-8l-2-2H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2zm0 12H4V8h16v10z"/>
                        </svg>
                    }.into_view()
                } else {
                    view! {
                        <svg viewBox="0 0 24 24" width="16" height="16">
                            <path fill="currentColor" d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/>
                        </svg>
                    }.into_view()
                }}
            </span>
            <span class="group-name">{name}</span>
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

/// Tree node for groups
#[derive(Clone)]
struct GroupNode {
    uuid: String,
    name: String,
    children: Vec<GroupNode>,
}

/// Build a tree structure from flat group list
fn build_group_tree(groups: &[GroupInfo]) -> Vec<GroupNode> {
    use std::collections::HashMap;

    // Build a map of uuid -> GroupInfo
    let group_map: HashMap<String, &GroupInfo> =
        groups.iter().map(|g| (g.uuid.clone(), g)).collect();

    // Find root groups (no parent or parent not in list)
    let root_groups: Vec<&GroupInfo> = groups
        .iter()
        .filter(|g| g.parent.is_none() || !group_map.contains_key(g.parent.as_ref().unwrap()))
        .collect();

    // Recursively build tree
    fn build_node(group: &GroupInfo, all_groups: &[GroupInfo]) -> GroupNode {
        let children: Vec<GroupNode> = all_groups
            .iter()
            .filter(|g| g.parent.as_ref() == Some(&group.uuid))
            .map(|g| build_node(g, all_groups))
            .collect();

        GroupNode {
            uuid: group.uuid.clone(),
            name: group.name.clone(),
            children,
        }
    }

    root_groups
        .into_iter()
        .map(|g| build_node(g, groups))
        .collect()
}
