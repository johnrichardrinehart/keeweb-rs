//! Entry list component

use leptos::*;

use crate::state::AppState;

/// Entry list component
#[component]
pub fn EntryList() -> impl IntoView {
    let state = expect_context::<AppState>();

    // Search input handler
    let on_search = move |ev| {
        state.search_query.set(event_target_value(&ev));
    };

    view! {
        <div class="entry-list">
            <div class="entry-list-header">
                <div class="search-box">
                    <svg class="search-icon" viewBox="0 0 24 24" width="18" height="18">
                        <path fill="currentColor" d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/>
                    </svg>
                    <input
                        type="text"
                        class="search-input"
                        placeholder="Search entries..."
                        prop:value=move || state.search_query.get()
                        on:input=on_search
                    />
                </div>
                <span class="entry-count">
                    {move || {
                        let total = state.entries.get().len();
                        let filtered = state.filtered_entries().len();
                        if total == filtered {
                            format!("{} entries", total)
                        } else {
                            format!("{} of {} entries", filtered, total)
                        }
                    }}
                </span>
            </div>

            <div class="entry-list-items">
                <Show
                    when=move || !state.filtered_entries().is_empty()
                    fallback=|| view! {
                        <div class="empty-state">
                            <p>"No entries found"</p>
                        </div>
                    }
                >
                    <For
                        each=move || state.filtered_entries()
                        key=|entry| entry.uuid.clone()
                        children=move |entry| {
                            let uuid = entry.uuid.clone();
                            let title = entry.title.clone();
                            let username = entry.username.clone();
                            let icon_id = entry.icon_id;
                            let icon_letter = title.chars().next().unwrap_or('?').to_uppercase().to_string();

                            view! {
                                <EntryListItem
                                    uuid=uuid
                                    title=title
                                    username=username
                                    icon_id=icon_id
                                    icon_letter=icon_letter
                                />
                            }
                        }
                    />
                </Show>
            </div>

            <div class="entry-list-footer">
                <button class="btn btn-primary btn-small" disabled=true title="Coming soon">
                    "+ New Entry"
                </button>
            </div>
        </div>
    }
}

/// A single entry in the list
#[component]
fn EntryListItem(
    uuid: String,
    title: String,
    username: String,
    icon_id: Option<u32>,
    icon_letter: String,
) -> impl IntoView {
    let state = expect_context::<AppState>();
    let uuid_for_selected = uuid.clone();
    let uuid_for_click = uuid.clone();
    let has_username = !username.is_empty();

    // Get icon display - either standard KeePass icon or fallback to letter
    let icon_display = get_standard_icon(icon_id, &icon_letter);

    view! {
        <div
            class="entry-item"
            class:selected=move || state.selected_entry.get().as_ref() == Some(&uuid_for_selected)
            on:click=move |_| state.selected_entry.set(Some(uuid_for_click.clone()))
        >
            <div class="entry-icon" inner_html=icon_display></div>
            <div class="entry-info">
                <div class="entry-title">{title}</div>
                <div class="entry-username">
                    {if has_username {
                        view! { <span>{username}</span> }.into_view()
                    } else {
                        view! { <span class="no-username">"No username"</span> }.into_view()
                    }}
                </div>
            </div>
        </div>
    }
}

/// Get the display content for a standard KeePass icon
/// Returns SVG string for common icons, or fallback letter
fn get_standard_icon(icon_id: Option<u32>, fallback: &str) -> String {
    match icon_id {
        Some(0) => svg_icon(
            "M12 17c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm6-9h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM8.9 6c0-1.71 1.39-3.1 3.1-3.1s3.1 1.39 3.1 3.1v2H8.9V6zM18 20H6V10h12v10z",
        ), // Key
        Some(1) => svg_icon(
            "M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z",
        ), // World/Globe
        Some(2) => svg_icon(
            "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z",
        ), // Warning
        Some(9) => svg_icon(
            "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z",
        ), // Check/OK
        Some(10) => svg_icon(
            "M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z",
        ), // Note/Paper
        Some(12) => svg_icon(
            "M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z",
        ), // Email
        Some(16) => svg_icon(
            "M17 1.01L7 1c-1.1 0-2 .9-2 2v18c0 1.1.9 2 2 2h10c1.1 0 2-.9 2-2V3c0-1.1-.9-1.99-2-1.99zM17 19H7V5h10v14z",
        ), // Phone
        Some(23) => svg_icon("M3 18h18v-2H3v2zm0-5h18v-2H3v2zm0-7v2h18V6H3z"), // Menu/List
        Some(25) => svg_icon(
            "M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z",
        ), // Cloud
        Some(27) => svg_icon(
            "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z",
        ), // Internet/WWW
        Some(30) => svg_icon(
            "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z",
        ), // User/Person
        Some(41) => svg_icon(
            "M21 3H3c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h5v2h8v-2h5c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 14H3V5h18v12z",
        ), // Computer/Desktop
        Some(62) => svg_icon(
            "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z",
        ), // Shield
        Some(68) => svg_icon(
            "M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z",
        ), // Key with card
        _ => fallback.to_string(),                                             // Fallback to letter
    }
}

/// Create an SVG icon with the given path
fn svg_icon(path: &str) -> String {
    format!(
        r#"<svg viewBox="0 0 24 24" width="20" height="20"><path fill="currentColor" d="{}"/></svg>"#,
        path
    )
}
