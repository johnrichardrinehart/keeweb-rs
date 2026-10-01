//! Resizable columns of the database view on desktop screens. Narrow screens hide the
//! splitters and lay the columns out in CSS.

use leptos::*;

use crate::state::{AppState, PaneWidths, save_pane_widths};

const SIDEBAR_MIN: i32 = 180;
const SIDEBAR_MAX: i32 = 480;
const SIDEBAR_DEFAULT: i32 = 264;
const LIST_MIN: i32 = 260;
const LIST_MAX: i32 = 720;
/// Width the detail panel keeps beside the sidebar and the entry list.
const DETAIL_MIN: i32 = 420;
const STEP: i32 = 16;
const LARGE_STEP: i32 = 64;

/// A column resized by the splitter on its right edge.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Sidebar,
    List,
}

impl Pane {
    fn min(self) -> i32 {
        match self {
            Pane::Sidebar => SIDEBAR_MIN,
            Pane::List => LIST_MIN,
        }
    }

    fn max(self) -> i32 {
        match self {
            Pane::Sidebar => SIDEBAR_MAX,
            Pane::List => LIST_MAX,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Pane::Sidebar => "Resize the groups column",
            Pane::List => "Resize the entry list",
        }
    }

    fn set(self, widths: &mut PaneWidths, width: Option<i32>) {
        match self {
            Pane::Sidebar => widths.sidebar = width,
            Pane::List => widths.list = width,
        }
    }
}

/// Entry list width when none is stored: clamp(340px, 22vw, 520px).
fn default_list(viewport: i32) -> i32 {
    (viewport * 22 / 100).clamp(340, 520)
}

/// Column widths on screen for `viewport` pixels: the stored or default widths within
/// their limits, narrowed (entry list first) until the detail panel keeps `DETAIL_MIN`.
pub fn fit(widths: PaneWidths, viewport: i32) -> (i32, i32) {
    let mut sidebar = widths
        .sidebar
        .unwrap_or(SIDEBAR_DEFAULT)
        .clamp(SIDEBAR_MIN, SIDEBAR_MAX);
    let mut list = widths
        .list
        .unwrap_or_else(|| default_list(viewport))
        .clamp(LIST_MIN, LIST_MAX);
    let mut excess = sidebar + list + DETAIL_MIN - viewport;
    if excess > 0 {
        let cut = excess.min(list - LIST_MIN);
        list -= cut;
        excess -= cut;
        sidebar -= excess.min(sidebar - SIDEBAR_MIN);
    }
    (sidebar, list)
}

/// Widest `pane` may get without moving the other column or squeezing the detail panel.
fn max_width(pane: Pane, widths: PaneWidths, viewport: i32) -> i32 {
    let (sidebar, list) = fit(widths, viewport);
    let other = match pane {
        Pane::Sidebar => list,
        Pane::List => sidebar,
    };
    (viewport - DETAIL_MIN - other).clamp(pane.min(), pane.max())
}

pub fn viewport_width() -> i32 {
    web_sys::window()
        .and_then(|window| window.inner_width().ok())
        .and_then(|width| width.as_f64())
        .map_or(1280, |width| width as i32)
}

/// Stores the widths of the vault on screen on this browser.
fn persist(state: AppState) {
    if let Some(vault) = state.active_vault_key() {
        save_pane_widths(&vault, state.pane_widths.get_untracked());
    }
}

/// Draggable and keyboard-operable border on the right edge of `pane`. Double-click
/// restores the default width.
#[component]
pub fn Splitter(pane: Pane, viewport: ReadSignal<i32>, resizing: RwSignal<bool>) -> impl IntoView {
    let state = expect_context::<AppState>();
    let width = move || {
        let (sidebar, list) = fit(state.pane_widths.get(), viewport.get());
        match pane {
            Pane::Sidebar => sidebar,
            Pane::List => list,
        }
    };
    let max = move || max_width(pane, state.pane_widths.get(), viewport.get());
    let resize = move |target: i32| {
        let limit = max_width(
            pane,
            state.pane_widths.get_untracked(),
            viewport.get_untracked(),
        );
        let target = target.clamp(pane.min(), limit);
        state
            .pane_widths
            .update(|widths| pane.set(widths, Some(target)));
    };
    // Pointer x and column width when the drag started.
    let drag = create_rw_signal(Option::<(i32, i32)>::None);
    let node = create_node_ref::<html::Div>();

    let end_drag = move || {
        if drag.get_untracked().is_some() {
            drag.set(None);
            resizing.set(false);
            persist(state);
        }
    };

    view! {
        <div
            node_ref=node
            class="pane-splitter"
            class:dragging=move || drag.with(Option::is_some)
            role="separator"
            tabindex="0"
            aria-orientation="vertical"
            aria-label=pane.label()
            aria-valuemin=pane.min()
            aria-valuemax=max
            aria-valuenow=width
            title="Drag to resize, double-click to reset"
            on:pointerdown=move |event| {
                if event.button() != 0 {
                    return;
                }
                // Keeps the press from selecting text or starting a native drag.
                event.prevent_default();
                if let Some(node) = node.get_untracked() {
                    let _ = node.set_pointer_capture(event.pointer_id());
                }
                drag.set(Some((event.client_x(), width())));
                resizing.set(true);
            }
            on:pointermove=move |event| {
                if let Some((start_x, start_width)) = drag.get_untracked() {
                    resize(start_width + event.client_x() - start_x);
                }
            }
            // Capture ends on pointerup and on pointercancel.
            on:lostpointercapture=move |_| end_drag()
            on:dblclick=move |_| {
                state.pane_widths.update(|widths| pane.set(widths, None));
                persist(state);
            }
            on:keydown=move |event| {
                let step = if event.shift_key() { LARGE_STEP } else { STEP };
                let target = match event.key().as_str() {
                    "ArrowLeft" => width() - step,
                    "ArrowRight" => width() + step,
                    "Home" => pane.min(),
                    "End" => max(),
                    _ => return,
                };
                event.prevent_default();
                resize(target);
            }
            on:keyup=move |event| {
                if matches!(event.key().as_str(), "ArrowLeft" | "ArrowRight" | "Home" | "End") {
                    persist(state);
                }
            }
        ></div>
    }
}
