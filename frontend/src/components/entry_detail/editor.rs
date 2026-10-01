//! Entry editor for new and existing entries.

use keeweb_wasm::document::{
    AttachmentData, AttachmentEdit, AutoTypeAssociation, AutoTypeEdit, Change, EntryEdit,
    StringField,
};
use leptos::*;
use std::rc::Rc;
use uuid::Uuid;

use super::{AttachmentIcon, CloseIcon, DownloadIcon, EyeIcon, EyeOffIcon, GenerateIcon};
use crate::components::icons::{IconPicker, KeepassIcon};
use crate::components::password_generator::PasswordGenerator;
use crate::model::{self, NOTES, PASSWORD, STANDARD_FIELDS, TITLE, URL, USER_NAME};
use crate::state::{AppState, EntryEditor};
use crate::utils::files;

#[derive(Clone, Copy)]
struct FieldRow {
    id: usize,
    key: RwSignal<String>,
    value: RwSignal<String>,
    protected: RwSignal<bool>,
    shown: RwSignal<bool>,
}

#[derive(Clone)]
enum AttachmentSource {
    /// Content of the attachment currently stored under this name.
    Existing {
        stored_name: String,
        size: u64,
    },
    New(Rc<Vec<u8>>),
}

#[derive(Clone)]
struct AttachmentRow {
    id: usize,
    name: RwSignal<String>,
    source: AttachmentSource,
}

#[derive(Clone, Copy)]
struct AssociationRow {
    id: usize,
    window: RwSignal<String>,
    sequence: RwSignal<String>,
}

/// Form state of one entry.
#[derive(Clone, Copy)]
struct EntryForm {
    next_id: StoredValue<usize>,
    title: RwSignal<String>,
    username: RwSignal<String>,
    password: RwSignal<String>,
    url: RwSignal<String>,
    notes: RwSignal<String>,
    /// Protected flags of the five standard fields, in [`STANDARD_FIELDS`] order.
    standard_protected: StoredValue<[bool; 5]>,
    custom: RwSignal<Vec<FieldRow>>,
    tags: RwSignal<String>,
    icon_id: RwSignal<u32>,
    custom_icon: RwSignal<Option<Uuid>>,
    foreground: RwSignal<String>,
    background: RwSignal<String>,
    override_url: RwSignal<String>,
    expires: RwSignal<bool>,
    expiry: RwSignal<String>,
    /// `expiry` as first shown; while unchanged the stored time (with its seconds) is kept.
    expiry_initial: StoredValue<String>,
    attachments: RwSignal<Vec<AttachmentRow>>,
    auto_type_enabled: RwSignal<bool>,
    auto_type_obfuscation: RwSignal<bool>,
    default_sequence: RwSignal<String>,
    associations: RwSignal<Vec<AssociationRow>>,
}

impl EntryForm {
    fn new(edit: &EntryEdit, sizes: &[(String, u64)]) -> Self {
        let value_of = |key: &str| {
            edit.strings
                .iter()
                .find(|field| field.key == key)
                .map(|field| field.value.clone())
                .unwrap_or_default()
        };
        let mut standard_protected = [false, false, true, false, false];
        for (index, key) in STANDARD_FIELDS.iter().enumerate() {
            if let Some(field) = edit.strings.iter().find(|field| field.key == *key) {
                standard_protected[index] = field.protected;
            }
        }
        let expiry_input = edit
            .expiry_time
            .map(model::to_datetime_local)
            .unwrap_or_default();
        let form = Self {
            next_id: store_value(0),
            title: create_rw_signal(value_of(TITLE)),
            username: create_rw_signal(value_of(USER_NAME)),
            password: create_rw_signal(value_of(PASSWORD)),
            url: create_rw_signal(value_of(URL)),
            notes: create_rw_signal(value_of(NOTES)),
            standard_protected: store_value(standard_protected),
            custom: create_rw_signal(Vec::new()),
            tags: create_rw_signal(edit.tags.join(", ")),
            icon_id: create_rw_signal(edit.icon_id),
            custom_icon: create_rw_signal(edit.custom_icon),
            foreground: create_rw_signal(edit.foreground_color.clone()),
            background: create_rw_signal(edit.background_color.clone()),
            override_url: create_rw_signal(edit.override_url.clone()),
            expires: create_rw_signal(edit.expires),
            expiry: create_rw_signal(expiry_input.clone()),
            expiry_initial: store_value(expiry_input),
            attachments: create_rw_signal(Vec::new()),
            auto_type_enabled: create_rw_signal(edit.auto_type.enabled),
            auto_type_obfuscation: create_rw_signal(edit.auto_type.obfuscation != 0),
            default_sequence: create_rw_signal(edit.auto_type.default_sequence.clone()),
            associations: create_rw_signal(Vec::new()),
        };
        for field in edit
            .strings
            .iter()
            .filter(|field| !model::is_standard_field(&field.key))
        {
            form.add_field(field.key.clone(), field.value.clone(), field.protected);
        }
        for attachment in &edit.attachments {
            let size = sizes
                .iter()
                .find(|(name, _)| *name == attachment.name)
                .map(|(_, size)| *size)
                .unwrap_or_default();
            if let AttachmentData::Existing(stored_name) = &attachment.data {
                form.add_attachment(
                    attachment.name.clone(),
                    AttachmentSource::Existing {
                        stored_name: stored_name.clone(),
                        size,
                    },
                );
            }
        }
        for association in &edit.auto_type.associations {
            form.add_association(association.window.clone(), association.sequence.clone());
        }
        form
    }

    fn next_id(&self) -> usize {
        let id = self.next_id.get_value();
        self.next_id.set_value(id + 1);
        id
    }

    fn add_field(&self, key: String, value: String, protected: bool) {
        let row = FieldRow {
            id: self.next_id(),
            key: create_rw_signal(key),
            value: create_rw_signal(value),
            protected: create_rw_signal(protected),
            shown: create_rw_signal(!protected),
        };
        self.custom.update(|rows| rows.push(row));
    }

    fn add_attachment(&self, name: String, source: AttachmentSource) {
        let row = AttachmentRow {
            id: self.next_id(),
            name: create_rw_signal(name),
            source,
        };
        self.attachments.update(|rows| rows.push(row));
    }

    fn add_association(&self, window: String, sequence: String) {
        let row = AssociationRow {
            id: self.next_id(),
            window: create_rw_signal(window),
            sequence: create_rw_signal(sequence),
        };
        self.associations.update(|rows| rows.push(row));
    }

    /// The edit to apply, or a message naming the first invalid input.
    fn build_edit(&self) -> Result<EntryEdit, String> {
        let protected = self.standard_protected.get_value();
        let standard_values = [
            self.title.get_untracked(),
            self.username.get_untracked(),
            self.password.get_untracked(),
            self.url.get_untracked(),
            self.notes.get_untracked(),
        ];
        let mut strings: Vec<StringField> = STANDARD_FIELDS
            .iter()
            .zip(standard_values)
            .zip(protected)
            .map(|((key, value), protected)| StringField {
                key: key.to_string(),
                value,
                protected,
            })
            .collect();

        for row in self.custom.get_untracked() {
            let key = row.key.get_untracked();
            let value = row.value.get_untracked();
            if key.trim().is_empty() {
                if value.is_empty() {
                    continue;
                }
                return Err("Every custom field with a value needs a name.".to_string());
            }
            if model::is_standard_field(&key) {
                return Err(format!("“{key}” is a standard field name."));
            }
            if strings.iter().any(|field| field.key == key) {
                return Err(format!("There are two fields named “{key}”."));
            }
            strings.push(StringField {
                key,
                value,
                protected: row.protected.get_untracked(),
            });
        }

        let mut tags: Vec<String> = Vec::new();
        for tag in self.tags.get_untracked().split([',', ';']) {
            let tag = tag.trim();
            if !tag.is_empty() && !tags.iter().any(|existing| existing == tag) {
                tags.push(tag.to_string());
            }
        }

        let expires = self.expires.get_untracked();
        let expiry_input = self.expiry.get_untracked();
        let expiry_time = if !expires
            || (!expiry_input.is_empty() && expiry_input == self.expiry_initial.get_value())
        {
            None
        } else {
            Some(
                model::from_datetime_local(&expiry_input)
                    .ok_or("Choose when the entry expires.")?,
            )
        };

        let mut attachments: Vec<AttachmentEdit> = Vec::new();
        for row in self.attachments.get_untracked() {
            let name = row.name.get_untracked();
            if name.trim().is_empty() {
                return Err("Every attachment needs a name.".to_string());
            }
            if attachments.iter().any(|attachment| attachment.name == name) {
                return Err(format!("There are two attachments named “{name}”."));
            }
            let data = match row.source {
                AttachmentSource::Existing { stored_name, .. } => {
                    AttachmentData::Existing(stored_name)
                }
                AttachmentSource::New(bytes) => AttachmentData::New((*bytes).clone()),
            };
            attachments.push(AttachmentEdit { name, data });
        }

        let associations = self
            .associations
            .get_untracked()
            .into_iter()
            .map(|row| AutoTypeAssociation {
                window: row.window.get_untracked(),
                sequence: row.sequence.get_untracked(),
            })
            .filter(|association| !association.window.trim().is_empty())
            .collect();

        Ok(EntryEdit {
            strings,
            tags,
            icon_id: self.icon_id.get_untracked(),
            custom_icon: self.custom_icon.get_untracked(),
            foreground_color: self.foreground.get_untracked(),
            background_color: self.background.get_untracked(),
            override_url: self.override_url.get_untracked(),
            expires,
            expiry_time,
            attachments,
            auto_type: AutoTypeEdit {
                enabled: self.auto_type_enabled.get_untracked(),
                obfuscation: u32::from(self.auto_type_obfuscation.get_untracked()),
                default_sequence: self.default_sequence.get_untracked(),
                associations,
            },
        })
    }
}

/// Editor in the detail panel.
#[component]
pub fn EntryEditorPanel(mode: EntryEditor) -> impl IntoView {
    let state = expect_context::<AppState>();

    let (edit, sizes, heading) = match mode {
        EntryEditor::Edit(uuid) => match state.entry(uuid) {
            Some(entry) => (
                entry.to_edit(),
                entry
                    .attachments
                    .iter()
                    .map(|attachment| (attachment.name.clone(), attachment.size))
                    .collect(),
                format!("Edit “{}”", model::display_title(&entry)),
            ),
            None => (EntryEdit::default(), Vec::new(), "Edit entry".to_string()),
        },
        EntryEditor::Create { group } => (
            EntryEdit::default(),
            Vec::new(),
            format!(
                "New entry in {}",
                state
                    .groups
                    .with_untracked(|groups| model::group_path(groups, group))
            ),
        ),
    };
    let form = EntryForm::new(&edit, &sizes);
    let error = create_rw_signal(Option::<String>::None);
    let show_generator = create_rw_signal(false);
    let show_icons = create_rw_signal(false);
    let show_password = create_rw_signal(false);
    let attachment_input = create_node_ref::<html::Input>();

    let cancel = move || state.editor.set(None);
    let submit = move || {
        let edit = match form.build_edit() {
            Ok(edit) => edit,
            Err(message) => {
                error.set(Some(message));
                return;
            }
        };
        let change = match mode {
            EntryEditor::Edit(uuid) => Change::UpdateEntry { uuid, entry: edit },
            EntryEditor::Create { group } => Change::CreateEntry { group, entry: edit },
        };
        match state.apply(change) {
            Ok(outcome) => {
                if let Some(created) = outcome.created {
                    state.selected_entry.set(Some(created));
                }
                state.editor.set(None);
            }
            Err(message) => error.set(Some(message)),
        }
    };

    let on_add_files = move |event: web_sys::Event| {
        for file in files::take_input_files(&event) {
            spawn_local(async move {
                match files::read_file(&file).await {
                    Ok(bytes) => {
                        form.add_attachment(file.name(), AttachmentSource::New(Rc::new(bytes)))
                    }
                    Err(message) => error.set(Some(message)),
                }
            });
        }
    };

    view! {
        <form
            class="entry-detail entry-editor"
            on:submit=move |event| {
                event.prevent_default();
                submit();
            }
        >
            <div class="entry-detail-header">
                <button
                    type="button"
                    class="entry-detail-icon icon-button"
                    title="Change icon"
                    on:click=move |_| show_icons.update(|shown| *shown = !*shown)
                >
                    {move || view! {
                        <KeepassIcon icon_id=form.icon_id.get() custom_icon=form.custom_icon.get() fallback="" />
                    }}
                </button>
                <div class="entry-detail-title-row">
                    <h2>{heading}</h2>
                </div>
                <button type="button" class="btn-icon" on:click=move |_| cancel() title="Cancel">
                    <CloseIcon />
                </button>
            </div>

            <div class="entry-detail-body">
                <Show when=move || show_icons.get()>
                    <section class="editor-section">
                        <h3 class="section-header">"Icon"</h3>
                        <IconPicker icon_id=form.icon_id custom_icon=form.custom_icon />
                    </section>
                </Show>

                <TextField label="Title" value=form.title />
                <TextField label="Username" value=form.username />
                <div class="field-group">
                    <label>"Password"</label>
                    <div class="field-value-row">
                        <input
                            type=move || if show_password.get() { "text" } else { "password" }
                            class="field-input"
                            autocomplete="new-password"
                            prop:value=move || form.password.get()
                            on:input=move |event| form.password.set(event_target_value(&event))
                        />
                        <button
                            type="button"
                            class="btn-icon"
                            on:click=move |_| show_password.update(|v| *v = !*v)
                            title=move || if show_password.get() { "Hide password" } else { "Show password" }
                        >
                            {move || if show_password.get() {
                                view! { <EyeOffIcon /> }.into_view()
                            } else {
                                view! { <EyeIcon /> }.into_view()
                            }}
                        </button>
                        <button
                            type="button"
                            class="btn-icon"
                            on:click=move |_| show_generator.set(true)
                            title="Generate password"
                        >
                            <GenerateIcon />
                        </button>
                    </div>
                </div>
                <TextField label="URL" value=form.url />
                <div class="field-group">
                    <label>"Notes"</label>
                    <textarea
                        class="field-textarea"
                        prop:value=move || form.notes.get()
                        on:input=move |event| form.notes.set(event_target_value(&event))
                    ></textarea>
                </div>
                <TextField label="Tags" value=form.tags placeholder="Comma-separated" />

                <div class="field-group">
                    <label class="checkbox-label">
                        <input
                            type="checkbox"
                            prop:checked=move || form.expires.get()
                            on:change=move |event| form.expires.set(event_target_checked(&event))
                        />
                        "Expires"
                    </label>
                    <Show when=move || form.expires.get()>
                        <input
                            type="datetime-local"
                            class="field-input"
                            prop:value=move || form.expiry.get()
                            on:input=move |event| form.expiry.set(event_target_value(&event))
                        />
                    </Show>
                </div>

                <section class="editor-section">
                    <h3 class="section-header">"Custom Fields"</h3>
                    <p class="section-hint">"Store a TOTP setup as a field named “otp”."</p>
                    <For
                        each=move || form.custom.get()
                        key=|row| row.id
                        children=move |row| view! {
                            <div class="editor-row">
                                <input
                                    type="text"
                                    class="field-input editor-key"
                                    placeholder="Name"
                                    prop:value=move || row.key.get()
                                    on:input=move |event| row.key.set(event_target_value(&event))
                                />
                                <input
                                    type=move || if row.shown.get() { "text" } else { "password" }
                                    class="field-input"
                                    placeholder="Value"
                                    autocomplete="off"
                                    prop:value=move || row.value.get()
                                    on:input=move |event| row.value.set(event_target_value(&event))
                                />
                                <button
                                    type="button"
                                    class="btn-icon"
                                    on:click=move |_| row.shown.update(|v| *v = !*v)
                                    title=move || if row.shown.get() { "Hide value" } else { "Show value" }
                                >
                                    {move || if row.shown.get() {
                                        view! { <EyeOffIcon /> }.into_view()
                                    } else {
                                        view! { <EyeIcon /> }.into_view()
                                    }}
                                </button>
                                <label class="checkbox-label" title="Protect the value in memory and hide it by default">
                                    <input
                                        type="checkbox"
                                        prop:checked=move || row.protected.get()
                                        on:change=move |event| row.protected.set(event_target_checked(&event))
                                    />
                                    "Protected"
                                </label>
                                <button
                                    type="button"
                                    class="btn-icon"
                                    title="Remove field"
                                    on:click=move |_| form.custom.update(|rows| rows.retain(|other| other.id != row.id))
                                >
                                    <CloseIcon />
                                </button>
                            </div>
                        }
                    />
                    <button
                        type="button"
                        class="btn btn-secondary btn-small"
                        on:click=move |_| form.add_field(String::new(), String::new(), false)
                    >
                        "+ Add field"
                    </button>
                </section>

                <section class="editor-section">
                    <h3 class="section-header">"Attachments"</h3>
                    <For
                        each=move || form.attachments.get()
                        key=|row| row.id
                        children=move |row| {
                            let id = row.id;
                            let (size, download) = match &row.source {
                                AttachmentSource::Existing { stored_name, size } => {
                                    (*size, Some(stored_name.clone()))
                                }
                                AttachmentSource::New(bytes) => (bytes.len() as u64, None),
                            };
                            view! {
                                <div class="editor-row attachment-item">
                                    <AttachmentIcon />
                                    <input
                                        type="text"
                                        class="field-input"
                                        aria-label="Attachment name"
                                        prop:value=move || row.name.get()
                                        on:input=move |event| row.name.set(event_target_value(&event))
                                    />
                                    <span class="attachment-size">{model::format_size(size)}</span>
                                    {download.map(|stored_name| match mode {
                                        EntryEditor::Edit(uuid) => view! {
                                            <button
                                                type="button"
                                                class="btn-icon"
                                                title="Download"
                                                on:click=move |_| {
                                                    let result = state
                                                        .attachment(uuid, &stored_name)
                                                        .ok_or_else(|| "Attachment not found.".to_string())
                                                        .and_then(|bytes| files::download_bytes(&stored_name, &bytes));
                                                    if let Err(message) = result {
                                                        error.set(Some(message));
                                                    }
                                                }
                                            >
                                                <DownloadIcon />
                                            </button>
                                        }.into_view(),
                                        EntryEditor::Create { .. } => ().into_view(),
                                    })}
                                    <button
                                        type="button"
                                        class="btn-icon"
                                        title="Remove attachment"
                                        on:click=move |_| form.attachments.update(|rows| rows.retain(|other| other.id != id))
                                    >
                                        <CloseIcon />
                                    </button>
                                </div>
                            }
                        }
                    />
                    <button
                        type="button"
                        class="btn btn-secondary btn-small"
                        on:click=move |_| {
                            if let Some(input) = attachment_input.get_untracked() {
                                input.click();
                            }
                        }
                    >
                        "+ Add files"
                    </button>
                    <input
                        type="file"
                        multiple=true
                        class="visually-hidden"
                        node_ref=attachment_input
                        on:change=on_add_files
                    />
                </section>

                <section class="editor-section">
                    <h3 class="section-header">"Appearance"</h3>
                    <ColorField label="Text color" value=form.foreground />
                    <ColorField label="Background color" value=form.background />
                    <TextField label="Override URL" value=form.override_url placeholder="e.g. cmd://…" />
                </section>

                <section class="editor-section">
                    <h3 class="section-header">"Auto-Type"</h3>
                    <label class="checkbox-label">
                        <input
                            type="checkbox"
                            prop:checked=move || form.auto_type_enabled.get()
                            on:change=move |event| form.auto_type_enabled.set(event_target_checked(&event))
                        />
                        "Enabled"
                    </label>
                    <label class="checkbox-label">
                        <input
                            type="checkbox"
                            prop:checked=move || form.auto_type_obfuscation.get()
                            on:change=move |event| form.auto_type_obfuscation.set(event_target_checked(&event))
                        />
                        "Two-channel obfuscation"
                    </label>
                    <TextField
                        label="Default sequence"
                        value=form.default_sequence
                        placeholder="{USERNAME}{TAB}{PASSWORD}{ENTER}"
                    />
                    <label class="field-label">"Window associations"</label>
                    <For
                        each=move || form.associations.get()
                        key=|row| row.id
                        children=move |row| view! {
                            <div class="editor-row">
                                <input
                                    type="text"
                                    class="field-input"
                                    placeholder="Window title"
                                    prop:value=move || row.window.get()
                                    on:input=move |event| row.window.set(event_target_value(&event))
                                />
                                <input
                                    type="text"
                                    class="field-input"
                                    placeholder="Sequence (optional)"
                                    prop:value=move || row.sequence.get()
                                    on:input=move |event| row.sequence.set(event_target_value(&event))
                                />
                                <button
                                    type="button"
                                    class="btn-icon"
                                    title="Remove association"
                                    on:click=move |_| form.associations.update(|rows| rows.retain(|other| other.id != row.id))
                                >
                                    <CloseIcon />
                                </button>
                            </div>
                        }
                    />
                    <button
                        type="button"
                        class="btn btn-secondary btn-small"
                        on:click=move |_| form.add_association(String::new(), String::new())
                    >
                        "+ Add window"
                    </button>
                </section>

                <Show when=move || error.get().is_some()>
                    <div class="error-message" role="alert">{move || error.get().unwrap_or_default()}</div>
                </Show>
            </div>

            <div class="entry-detail-footer">
                <span class="footer-spacer"></span>
                <button type="button" class="btn btn-secondary" on:click=move |_| cancel()>"Cancel"</button>
                <button type="submit" class="btn btn-primary" disabled=move || state.saving.get()>
                    {match mode {
                        EntryEditor::Edit(_) => "Apply",
                        EntryEditor::Create { .. } => "Create",
                    }}
                </button>
            </div>
        </form>

        // Outside the form so its controls cannot submit the entry.
        <Show when=move || show_generator.get()>
            <PasswordGenerator
                on_close=move |_| show_generator.set(false)
                on_use=move |password: String| form.password.set(password)
            />
        </Show>
    }
}

#[component]
fn TextField(
    label: &'static str,
    value: RwSignal<String>,
    #[prop(optional)] placeholder: &'static str,
) -> impl IntoView {
    view! {
        <div class="field-group">
            <label>{label}</label>
            <input
                type="text"
                class="field-input"
                placeholder=placeholder
                prop:value=move || value.get()
                on:input=move |event| value.set(event_target_value(&event))
            />
        </div>
    }
}

/// KeePass color: empty for the default, otherwise "#RRGGBB".
#[component]
fn ColorField(label: &'static str, value: RwSignal<String>) -> impl IntoView {
    view! {
        <div class="field-group">
            <label>{label}</label>
            <div class="field-value-row">
                <input
                    type="color"
                    class="color-input"
                    prop:value=move || {
                        let color = value.get();
                        if color.len() == 7 && color.starts_with('#') {
                            color.to_ascii_lowercase()
                        } else {
                            "#000000".to_string()
                        }
                    }
                    on:input=move |event| value.set(event_target_value(&event).to_ascii_uppercase())
                />
                <span class="color-value">
                    {move || {
                        let color = value.get();
                        if color.is_empty() { "Default".to_string() } else { color }
                    }}
                </span>
                <Show when=move || !value.get().is_empty()>
                    <button type="button" class="btn btn-secondary btn-small" on:click=move |_| value.set(String::new())>
                        "Reset"
                    </button>
                </Show>
            </div>
        </div>
    }
}
