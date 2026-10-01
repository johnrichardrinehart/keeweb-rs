//! Theme toggle component

use leptos::*;

use crate::components::icons::{Icon, UiIcon};
use crate::state::{AppState, Theme};

/// Theme toggle button that switches between light and dark modes
#[component]
pub fn ThemeToggle() -> impl IntoView {
    let state = expect_context::<AppState>();

    let on_click = move |_| {
        state.cycle_theme();
    };

    // Get the current theme for display
    let theme_label = move || match state.theme.get() {
        Theme::Light => "Light",
        Theme::Dark => "Dark",
    };

    // Show the icon for the CURRENT theme (sun for light, moon for dark)
    let theme_icon = move || {
        let icon = match state.theme.get() {
            Theme::Light => Icon::Sun,
            Theme::Dark => Icon::Moon,
        };
        view! { <UiIcon icon=icon /> }
    };

    view! {
        <button
            type="button"
            class="btn-icon"
            on:click=on_click
            title=move || format!("Theme: {} (click to toggle)", theme_label())
            aria-label=move || format!("Current theme: {}. Change theme", theme_label())
        >
            {theme_icon}
        </button>
    }
}
