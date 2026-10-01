//! Entry history: browse previous versions, restore one, or delete one.

use keeweb_wasm::document::{Change, EntryView};
use leptos::*;

use super::reveal_glyph;
use crate::components::dialog::Dialog;
use crate::components::icons::{Icon, UiIcon};
use crate::model;
use crate::state::AppState;
use crate::utils::files;

/// History viewer dialog. Indexes are positions in `EntryView::history` (oldest
/// first), as expected by `RestoreHistory` / `DeleteHistory`.
#[component]
pub fn HistoryViewer(entry: EntryView, #[prop(into)] on_close: Callback<()>) -> impl IntoView {
    let state = expect_context::<AppState>();
    let selected = create_rw_signal(Option::<usize>::None);
    let show_protected = create_rw_signal(false);
    let uuid = entry.uuid;
    let title = format!("History: {}", model::display_title(&entry));
    let history = store_value(entry.history);

    let restore = move |index: usize| {
        if state
            .apply_or_report(Change::RestoreHistory { uuid, index })
            .is_some()
        {
            on_close.call(());
        }
    };
    let delete = move |index: usize| {
        if state
            .apply_or_report(Change::DeleteHistory { uuid, index })
            .is_some()
        {
            selected.set(None);
            on_close.call(());
        }
    };

    view! {
        <Dialog title=title on_close=on_close class="history-dialog">
            <div class="dialog-body">
                <div class="history-list">
                    {history.with_value(|versions| {
                        versions.iter().enumerate().rev().map(|(index, version)| {
                            let (relative, exact) = version
                                .times
                                .last_modification
                                .map(|time| (model::format_relative(time), model::format_local(time)))
                                .unwrap_or_else(|| ("Unknown date".to_string(), String::new()));
                            view! {
                                <button
                                    type="button"
                                    class="history-item"
                                    class:selected=move || selected.get() == Some(index)
                                    on:click=move |_| selected.set(Some(index))
                                >
                                    <div class="history-item-date" title=exact>{relative}</div>
                                    <div class="history-item-title">{model::display_title(version)}</div>
                                </button>
                            }
                        }).collect_view()
                    })}
                </div>

                <div class="history-detail">
                    {move || {
                        let Some(index) = selected.get() else {
                            return view! {
                                <div class="history-no-selection">"Select a version to view details"</div>
                            }.into_view();
                        };
                        let Some(version) = history.with_value(|versions| versions.get(index).cloned()) else {
                            return view! {
                                <div class="history-no-selection">"Version not found"</div>
                            }.into_view();
                        };
                        view! {
                            <div class="history-entry-detail">
                                {version.strings.iter().map(|field| {
                                    let value = field.value.clone();
                                    let protected = field.protected;
                                    view! {
                                        <div class="history-field">
                                            <label>{field.key.clone()}</label>
                                            <div class="history-field-value" class:password-field=protected class:notes=field.key == model::NOTES>
                                                {move || if protected && !show_protected.get() {
                                                    "••••••••".to_string()
                                                } else {
                                                    value.clone()
                                                }}
                                                {protected.then(|| view! {
                                                    <button
                                                        type="button"
                                                        class="btn-icon btn-icon-sm"
                                                        on:click=move |_| show_protected.update(|v| *v = !*v)
                                                        title=move || if show_protected.get() { "Hide" } else { "Show" }
                                                        aria-label=move || if show_protected.get() { "Hide protected values" } else { "Show protected values" }
                                                    >
                                                        {reveal_glyph(move || show_protected.get())}
                                                    </button>
                                                })}
                                            </div>
                                        </div>
                                    }
                                }).collect_view()}
                                {(!version.tags.is_empty()).then(|| view! {
                                    <div class="history-field">
                                        <label>"Tags"</label>
                                        <div class="history-field-value">{version.tags.join(", ")}</div>
                                    </div>
                                })}
                                {(!version.attachments.is_empty()).then(|| view! {
                                    <div class="history-field">
                                        <label>"Attachments"</label>
                                        {version.attachments.iter().map(|attachment| {
                                            let name = attachment.name.clone();
                                            let name_for_download = attachment.name.clone();
                                            view! {
                                                <div class="history-field-value password-field">
                                                    <span>{name}" ("{model::format_size(attachment.size)}")"</span>
                                                    <button
                                                        type="button"
                                                        class="btn-icon btn-icon-sm"
                                                        title="Download"
                                                        aria-label="Download"
                                                        on:click=move |_| {
                                                            let result = state
                                                                .history_attachment(uuid, index, &name_for_download)
                                                                .ok_or_else(|| "Attachment not found.".to_string())
                                                                .and_then(|bytes| files::download_bytes(&name_for_download, &bytes));
                                                            if let Err(error) = result {
                                                                state.error_message.set(Some(error));
                                                            }
                                                        }
                                                    >
                                                        <UiIcon icon=Icon::Download size=16 />
                                                    </button>
                                                </div>
                                            }
                                        }).collect_view()}
                                    </div>
                                })}
                                <div class="history-field">
                                    <label>"Modified"</label>
                                    <div class="history-field-value">
                                        {version.times.last_modification.map(model::format_local).unwrap_or_else(|| "Unknown".to_string())}
                                    </div>
                                </div>
                                <div class="history-actions">
                                    <button
                                        type="button"
                                        class="btn btn-primary"
                                        disabled=move || state.saving.get()
                                        on:click=move |_| restore(index)
                                    >
                                        <UiIcon icon=Icon::Undo size=16 />
                                        "Restore this version"
                                    </button>
                                    <button
                                        type="button"
                                        class="btn btn-danger"
                                        disabled=move || state.saving.get()
                                        on:click=move |_| delete(index)
                                    >
                                        <UiIcon icon=Icon::Trash size=16 />
                                        "Delete version"
                                    </button>
                                </div>
                            </div>
                        }.into_view()
                    }}
                </div>
            </div>
        </Dialog>
    }
}
