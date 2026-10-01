//! Interface icons, and KeePass icons: display and selection, including custom PNG icons.

use keeweb_wasm::document::Change;
use leptos::*;
use uuid::Uuid;

use crate::model::MAX_STANDARD_ICON;
use crate::state::AppState;
use crate::utils::files;

const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

/// Interface icons on a 24 px grid, drawn with a 2 px stroke in the current text color.
/// Path data from Lucide (https://lucide.dev), ISC license.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    ArrowLeft,
    Check,
    ChevronRight,
    CircleAlert,
    Clock,
    Copy,
    CopyPlus,
    Database,
    Download,
    Ellipsis,
    ExternalLink,
    Eye,
    EyeOff,
    Fingerprint,
    Folder,
    FolderInput,
    FolderPlus,
    History,
    KeyRound,
    Layers,
    Lock,
    LogOut,
    Moon,
    Paperclip,
    Pencil,
    Plus,
    RefreshCw,
    Save,
    Search,
    Settings,
    Sun,
    Tag,
    Trash,
    Undo,
    Upload,
    X,
}

impl Icon {
    /// SVG child elements of the icon.
    fn markup(self) -> &'static str {
        match self {
            Icon::ArrowLeft => r#"<path d="m12 19-7-7 7-7"/><path d="M19 12H5"/>"#,
            Icon::Check => r#"<path d="M20 6 9 17l-5-5"/>"#,
            Icon::ChevronRight => r#"<path d="m9 18 6-6-6-6"/>"#,
            Icon::CircleAlert => {
                r#"<circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/>"#
            }
            Icon::Clock => r#"<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>"#,
            Icon::Copy => {
                r#"<rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>"#
            }
            Icon::CopyPlus => {
                r#"<path d="M15 12v6"/><path d="M12 15h6"/><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>"#
            }
            Icon::Database => {
                r#"<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5V19A9 3 0 0 0 21 19V5"/><path d="M3 12A9 3 0 0 0 21 12"/>"#
            }
            Icon::Download => {
                r#"<path d="M12 15V3"/><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/>"#
            }
            Icon::Ellipsis => {
                r#"<circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/>"#
            }
            Icon::ExternalLink => {
                r#"<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>"#
            }
            Icon::Eye => {
                r#"<path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"/><circle cx="12" cy="12" r="3"/>"#
            }
            Icon::EyeOff => {
                r#"<path d="M10.733 5.076a10.744 10.744 0 0 1 11.205 6.575 1 1 0 0 1 0 .696 10.747 10.747 0 0 1-1.444 2.49"/><path d="M14.084 14.158a3 3 0 0 1-4.242-4.242"/><path d="M17.479 17.499a10.75 10.75 0 0 1-15.417-5.151 1 1 0 0 1 0-.696 10.75 10.75 0 0 1 4.446-5.143"/><path d="m2 2 20 20"/>"#
            }
            Icon::Fingerprint => {
                r#"<path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M2 12a10 10 0 0 1 18-6"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .131-5.354 0-6"/><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M9 6.8a6 6 0 0 1 9 5.2v2"/>"#
            }
            Icon::Folder => {
                r#"<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>"#
            }
            Icon::FolderInput => {
                r#"<path d="M2 9V5a2 2 0 0 1 2-2h3.9a2 2 0 0 1 1.69.9l.81 1.2a2 2 0 0 0 1.67.9H20a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-1"/><path d="M2 13h10"/><path d="m9 16 3-3-3-3"/>"#
            }
            Icon::FolderPlus => {
                r#"<path d="M12 10v6"/><path d="M9 13h6"/><path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>"#
            }
            Icon::History => {
                r#"<path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l4 2"/>"#
            }
            Icon::KeyRound => {
                r#"<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/>"#
            }
            Icon::Layers => {
                r#"<path d="M12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83z"/><path d="M2 12a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 12"/><path d="M2 17a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 17"/>"#
            }
            Icon::Lock => {
                r#"<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>"#
            }
            Icon::LogOut => {
                r#"<path d="m16 17 5-5-5-5"/><path d="M21 12H9"/><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>"#
            }
            Icon::Moon => {
                r#"<path d="M20.985 12.486a9 9 0 1 1-9.473-9.472c.405-.022.617.46.402.803a6 6 0 0 0 8.268 8.268c.344-.215.825-.004.803.401"/>"#
            }
            Icon::Paperclip => {
                r#"<path d="m16 6-8.414 8.586a2 2 0 0 0 2.829 2.829l8.414-8.586a4 4 0 1 0-5.657-5.657l-8.379 8.551a6 6 0 1 0 8.485 8.485l8.379-8.551"/>"#
            }
            Icon::Pencil => {
                r#"<path d="M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z"/><path d="m15 5 4 4"/>"#
            }
            Icon::Plus => r#"<path d="M5 12h14"/><path d="M12 5v14"/>"#,
            Icon::RefreshCw => {
                r#"<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>"#
            }
            Icon::Save => {
                r#"<path d="M15.2 3a2 2 0 0 1 1.4.6l3.8 3.8a2 2 0 0 1 .6 1.4V19a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"/><path d="M17 21v-7a1 1 0 0 0-1-1H8a1 1 0 0 0-1 1v7"/><path d="M7 3v4a1 1 0 0 0 1 1h7"/>"#
            }
            Icon::Search => r#"<path d="m21 21-4.34-4.34"/><circle cx="11" cy="11" r="8"/>"#,
            Icon::Settings => {
                r#"<path d="M9.671 4.136a2.34 2.34 0 0 1 4.659 0 2.34 2.34 0 0 0 3.319 1.915 2.34 2.34 0 0 1 2.33 4.033 2.34 2.34 0 0 0 0 3.831 2.34 2.34 0 0 1-2.33 4.033 2.34 2.34 0 0 0-3.319 1.915 2.34 2.34 0 0 1-4.659 0 2.34 2.34 0 0 0-3.32-1.915 2.34 2.34 0 0 1-2.33-4.033 2.34 2.34 0 0 0 0-3.831A2.34 2.34 0 0 1 6.35 6.051a2.34 2.34 0 0 0 3.319-1.915"/><circle cx="12" cy="12" r="3"/>"#
            }
            Icon::Sun => {
                r#"<circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/>"#
            }
            Icon::Tag => {
                r#"<path d="M12.586 2.586A2 2 0 0 0 11.172 2H4a2 2 0 0 0-2 2v7.172a2 2 0 0 0 .586 1.414l8.704 8.704a2.426 2.426 0 0 0 3.42 0l6.58-6.58a2.426 2.426 0 0 0 0-3.42z"/><circle cx="7.5" cy="7.5" r=".5" fill="currentColor"/>"#
            }
            Icon::Trash => {
                r#"<path d="M10 11v6"/><path d="M14 11v6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>"#
            }
            Icon::Undo => {
                r#"<path d="M9 14 4 9l5-5"/><path d="M4 9h10.5a5.5 5.5 0 0 1 5.5 5.5a5.5 5.5 0 0 1-5.5 5.5H11"/>"#
            }
            Icon::Upload => {
                r#"<path d="M12 3v12"/><path d="m17 8-5-5-5 5"/><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>"#
            }
            Icon::X => r#"<path d="M18 6 6 18"/><path d="m6 6 12 12"/>"#,
        }
    }
}

/// Decorative interface icon; the control around it carries the accessible name.
#[component]
pub fn UiIcon(icon: Icon, #[prop(default = 18)] size: u32) -> impl IntoView {
    view! {
        <svg
            class="ui-icon"
            width=size
            height=size
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
            focusable="false"
            inner_html=icon.markup()
        ></svg>
    }
}

/// Custom icon if it exists, else the standard icon, else `fallback` text.
#[component]
pub fn KeepassIcon(
    icon_id: u32,
    custom_icon: Option<Uuid>,
    #[prop(optional, into)] fallback: String,
) -> impl IntoView {
    let state = expect_context::<AppState>();
    move || {
        let custom = custom_icon.and_then(|uuid| {
            state
                .custom_icons
                .with(|icons| icons.iter().find(|icon| icon.uuid == uuid).cloned())
        });
        if let Some(icon) = custom {
            view! { <img class="kp-icon" src=icon.url alt="" /> }.into_view()
        } else if icon_id <= MAX_STANDARD_ICON {
            let src = format!("icons/database/{icon_id}.svg");
            view! { <img class="kp-icon" src=src alt="" /> }.into_view()
        } else {
            fallback.clone().into_view()
        }
    }
}

/// Grid of the standard icons and the database's custom icons, plus PNG upload.
/// Uploading adds the icon to the database right away (a recorded change).
#[component]
pub fn IconPicker(icon_id: RwSignal<u32>, custom_icon: RwSignal<Option<Uuid>>) -> impl IntoView {
    let state = expect_context::<AppState>();
    let error = create_rw_signal(Option::<String>::None);
    let upload_ref = create_node_ref::<html::Input>();

    let on_upload = move |event: web_sys::Event| {
        let Some(file) = files::take_input_files(&event).into_iter().next() else {
            return;
        };
        spawn_local(async move {
            let png = match files::read_file(&file).await {
                Ok(bytes) => bytes,
                Err(message) => {
                    error.set(Some(message));
                    return;
                }
            };
            if !png.starts_with(PNG_SIGNATURE) {
                error.set(Some("Custom icons must be PNG images.".to_string()));
                return;
            }
            match state.apply(Change::AddCustomIcon { png }) {
                Ok(outcome) => {
                    error.set(None);
                    custom_icon.set(outcome.created);
                }
                Err(message) => error.set(Some(message)),
            }
        });
    };

    view! {
        <div class="icon-picker">
            <div class="icon-grid" role="listbox" aria-label="Standard icons">
                {(0..=MAX_STANDARD_ICON).map(|id| view! {
                    <button
                        type="button"
                        class="icon-choice"
                        class:selected=move || custom_icon.get().is_none() && icon_id.get() == id
                        title=format!("Icon {id}")
                        on:click=move |_| {
                            icon_id.set(id);
                            custom_icon.set(None);
                        }
                    >
                        <img src=format!("icons/database/{id}.svg") alt="" />
                    </button>
                }).collect_view()}
            </div>
            <Show when=move || state.custom_icons.with(|icons| !icons.is_empty())>
                <div class="icon-grid" role="listbox" aria-label="Custom icons">
                    {move || state.custom_icons.get().iter().map(|icon| {
                        let uuid = icon.uuid;
                        view! {
                            <button
                                type="button"
                                class="icon-choice"
                                class:selected=move || custom_icon.get() == Some(uuid)
                                title="Custom icon"
                                on:click=move |_| custom_icon.set(Some(uuid))
                            >
                                <img src=icon.url.clone() alt="" />
                            </button>
                        }
                    }).collect_view()}
                </div>
            </Show>
            <div class="icon-picker-actions">
                <button
                    type="button"
                    class="btn btn-secondary btn-sm"
                    on:click=move |_| {
                        if let Some(input) = upload_ref.get_untracked() {
                            input.click();
                        }
                    }
                >
                    <UiIcon icon=Icon::Upload size=16 />
                    "Upload PNG icon"
                </button>
                <input
                    type="file"
                    accept="image/png"
                    class="visually-hidden"
                    node_ref=upload_ref
                    on:change=on_upload
                />
            </div>
            <Show when=move || error.get().is_some()>
                <p class="form-error" role="alert">{move || error.get().unwrap_or_default()}</p>
            </Show>
        </div>
    }
}
