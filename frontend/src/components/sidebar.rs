//! Sidebar component with group tree navigation

use leptos::*;

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

    view! {
        <aside class="sidebar">
            <div class="sidebar-header">
                <h3>"Groups"</h3>
            </div>

            <nav class="group-tree">
                // All entries option
                <GroupItem
                    uuid=None
                    name="All Entries".to_string()
                    depth=0
                    has_children=false
                />

                // Group tree
                <For
                    each=group_tree
                    key=|group| group.uuid.clone()
                    children=move |group| {
                        view! {
                            <GroupTreeNode group=group depth=0 />
                        }
                    }
                />
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
) -> impl IntoView {
    let state = expect_context::<AppState>();
    let uuid_for_selected = uuid.clone();
    let uuid_for_click = uuid.clone();

    let indent = format!("padding-left: {}rem", depth as f32 * 1.0 + 0.5);

    view! {
        <div
            class="group-item"
            class:selected=move || state.selected_group.get() == uuid_for_selected
            style=indent
            on:click=move |_| {
                state.selected_group.set(uuid_for_click.clone());
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
