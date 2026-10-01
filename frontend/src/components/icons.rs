//! KeePass icons: display and selection, including custom PNG icons.

use keeweb_wasm::document::Change;
use leptos::*;
use uuid::Uuid;

use crate::model::MAX_STANDARD_ICON;
use crate::state::AppState;
use crate::utils::files;

const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

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
                    class="btn btn-secondary btn-small"
                    on:click=move |_| {
                        if let Some(input) = upload_ref.get_untracked() {
                            input.click();
                        }
                    }
                >
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
