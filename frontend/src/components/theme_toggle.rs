//! Theme toggle component

use leptos::*;

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
    let theme_icon = move || match state.theme.get() {
        Theme::Light => view! { <SunIcon /> }.into_view(),
        Theme::Dark => view! { <MoonIcon /> }.into_view(),
    };

    view! {
        <button
            class="theme-toggle"
            on:click=on_click
            title=move || format!("Theme: {} (click to toggle)", theme_label())
        >
            {theme_icon}
        </button>
    }
}

/// Sun icon for light mode
#[component]
fn SunIcon() -> impl IntoView {
    view! {
        <svg
            xmlns="http://www.w3.org/2000/svg"
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <circle cx="12" cy="12" r="5"></circle>
            <line x1="12" y1="1" x2="12" y2="3"></line>
            <line x1="12" y1="21" x2="12" y2="23"></line>
            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
            <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
            <line x1="1" y1="12" x2="3" y2="12"></line>
            <line x1="21" y1="12" x2="23" y2="12"></line>
            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
            <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
        </svg>
    }
}

/// Moon icon for dark mode
#[component]
fn MoonIcon() -> impl IntoView {
    view! {
        <svg
            xmlns="http://www.w3.org/2000/svg"
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
        </svg>
    }
}
