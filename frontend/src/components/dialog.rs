//! Shared dialog building blocks.

use leptos::*;
use uuid::Uuid;

use crate::components::icons::{Icon, UiIcon};
use crate::model;
use crate::state::AppState;

/// Modal frame with a title bar. Children supply `.dialog-body` and `.dialog-footer`.
/// Escape and the close button call `on_close`; clicking the backdrop does not, so
/// half-filled forms are not lost by a stray click.
#[component]
pub fn Dialog(
    #[prop(into)] title: MaybeSignal<String>,
    #[prop(into)] on_close: Callback<()>,
    #[prop(optional, into)] class: String,
    children: Children,
) -> impl IntoView {
    view! {
        <div class="dialog-overlay">
            <div
                class=format!("dialog {class}")
                role="dialog"
                aria-modal="true"
                on:keydown=move |event| {
                    if event.key() == "Escape" {
                        event.stop_propagation();
                        on_close.call(());
                    }
                }
            >
                <div class="dialog-header">
                    <h2>{move || title.get()}</h2>
                    <button
                        type="button"
                        class="btn-icon dialog-close"
                        on:click=move |_| on_close.call(())
                        title="Close"
                        aria-label="Close"
                    >
                        <UiIcon icon=Icon::X />
                    </button>
                </div>
                {children()}
            </div>
        </div>
    }
}

/// Yes/no question for destructive actions.
#[component]
pub fn ConfirmDialog(
    #[prop(into)] title: String,
    #[prop(into)] message: String,
    #[prop(into)] confirm_label: String,
    #[prop(into)] on_confirm: Callback<()>,
    #[prop(into)] on_close: Callback<()>,
) -> impl IntoView {
    view! {
        <Dialog title=title on_close=on_close>
            <div class="dialog-body">
                <p class="dialog-lead">{message}</p>
            </div>
            <div class="dialog-footer">
                <button type="button" class="btn btn-secondary" on:click=move |_| on_close.call(())>"Cancel"</button>
                <button type="button" class="btn btn-danger-solid" on:click=move |_| on_confirm.call(())>{confirm_label}</button>
            </div>
        </Dialog>
    }
}

/// Picks a destination group. `excluded` groups (e.g. a moved group's own subtree)
/// and the recycle bin are not selectable.
#[component]
pub fn GroupPicker(
    #[prop(into)] title: String,
    #[prop(into)] current: Option<Uuid>,
    #[prop(into)] excluded: Vec<Uuid>,
    #[prop(into)] on_pick: Callback<Uuid>,
    #[prop(into)] on_close: Callback<()>,
) -> impl IntoView {
    let state = expect_context::<AppState>();
    let chosen = create_rw_signal(Option::<Uuid>::None);

    let rows = move || {
        state.groups.with(|groups| {
            groups
                .iter()
                .filter(|group| !group.in_recycle_bin && !group.is_recycle_bin)
                .map(|group| {
                    let depth = depth_of(groups, group.uuid);
                    (
                        group.uuid,
                        model::group_display_name(group),
                        depth,
                        excluded.contains(&group.uuid) || Some(group.uuid) == current,
                    )
                })
                .collect::<Vec<_>>()
        })
    };

    view! {
        <Dialog title=title on_close=on_close class="picker-dialog">
            <div class="dialog-body">
                <div class="group-picker" role="listbox">
                    {move || rows().into_iter().map(|(uuid, name, depth, disabled)| {
                        view! {
                            <button
                                type="button"
                                class="group-picker-row"
                                class:selected=move || chosen.get() == Some(uuid)
                                style=format!("padding-left: {}px", 12 + depth * 20)
                                disabled=disabled
                                on:click=move |_| chosen.set(Some(uuid))
                            >
                                <UiIcon icon=Icon::Folder size=16 />
                                <span>{name}</span>
                            </button>
                        }
                    }).collect_view()}
                </div>
            </div>
            <div class="dialog-footer">
                <button type="button" class="btn btn-secondary" on:click=move |_| on_close.call(())>"Cancel"</button>
                <button type="button"
                    class="btn btn-primary"
                    disabled=move || chosen.get().is_none()
                    on:click=move |_| {
                        if let Some(uuid) = chosen.get_untracked() {
                            on_pick.call(uuid);
                        }
                    }
                >
                    "Move here"
                </button>
            </div>
        </Dialog>
    }
}

fn depth_of(groups: &[keeweb_wasm::document::GroupView], group: Uuid) -> usize {
    let mut depth = 0;
    let mut current = groups
        .iter()
        .find(|candidate| candidate.uuid == group)
        .and_then(|view| view.parent);
    while let Some(parent) = current {
        depth += 1;
        if depth > groups.len() {
            break;
        }
        current = groups
            .iter()
            .find(|candidate| candidate.uuid == parent)
            .and_then(|view| view.parent);
    }
    depth
}
