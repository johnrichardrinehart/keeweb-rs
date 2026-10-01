//! Database name, description, recycle bin, history limits, fingerprint unlock, and the
//! inactivity lock of this browser.

use keeweb_wasm::document::{Change, MetaEdit};
use leptos::*;

use crate::components::dialog::Dialog;
use crate::components::unlock_dialog::FingerprintIcon;
use crate::quick_unlock::{self, Support};
use crate::state::{AppState, save_idle_lock};

const MIB: i64 = 1024 * 1024;

#[component]
pub fn DatabaseSettings() -> impl IntoView {
    let state = expect_context::<AppState>();
    view! {
        <Show when=move || state.show_settings.get()>
            {move || state.meta.get_untracked().map(|meta| view! {
                <SettingsForm initial=meta.to_edit() />
            })}
        </Show>
    }
}

/// Text for a limit input: blank means unlimited (negative in KeePass).
fn limit_text(value: i64, unit: i64) -> String {
    if value < 0 {
        String::new()
    } else if value % unit == 0 {
        (value / unit).to_string()
    } else {
        format!("{:.2}", value as f64 / unit as f64)
    }
}

/// Parses a limit input; blank means unlimited.
fn parse_limit(text: &str, unit: i64, what: &str) -> Result<i64, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(-1);
    }
    match text.parse::<f64>() {
        Ok(value) if value >= 0.0 && value.is_finite() => Ok((value * unit as f64).round() as i64),
        _ => Err(format!(
            "{what} must be a non-negative number, or blank for no limit."
        )),
    }
}

#[component]
fn SettingsForm(initial: MetaEdit) -> impl IntoView {
    let state = expect_context::<AppState>();
    let name = create_rw_signal(initial.name.clone());
    let description = create_rw_signal(initial.description.clone());
    let recycle_bin = create_rw_signal(initial.recycle_bin_enabled);
    let max_items = create_rw_signal(limit_text(initial.history_max_items.into(), 1));
    let max_size = create_rw_signal(limit_text(initial.history_max_size, MIB));
    let error = create_rw_signal(Option::<String>::None);
    let initial = store_value(initial);

    let close = move || state.show_settings.set(false);
    let submit = move || {
        let parsed =
            parse_limit(&max_items.get_untracked(), 1, "Maximum versions").and_then(|items| {
                let items = i32::try_from(items)
                    .map_err(|_| "Maximum versions is too large.".to_string())?;
                let size = parse_limit(&max_size.get_untracked(), MIB, "Maximum size")?;
                Ok((items, size))
            });
        let (history_max_items, history_max_size) = match parsed {
            Ok(limits) => limits,
            Err(message) => {
                error.set(Some(message));
                return;
            }
        };
        let original = initial.get_value();
        // Re-entering the displayed value must not round away the stored byte count.
        let history_max_size =
            if max_size.get_untracked() == limit_text(original.history_max_size, MIB) {
                original.history_max_size
            } else {
                history_max_size
            };
        let meta = MetaEdit {
            name: name.get_untracked(),
            description: description.get_untracked(),
            recycle_bin_enabled: recycle_bin.get_untracked(),
            history_max_items,
            history_max_size,
        };
        match state.apply(Change::UpdateMeta { meta }) {
            Ok(_) => close(),
            Err(message) => error.set(Some(message)),
        }
    };

    view! {
        <Dialog title="Database settings" on_close=move |_| close() class="settings-dialog">
            <form on:submit=move |event| {
                event.prevent_default();
                submit();
            }>
                <div class="dialog-body">
                    <div class="form-group">
                        <label for="db-name">"Name"</label>
                        <input
                            id="db-name"
                            type="text"
                            class="form-input"
                            prop:value=move || name.get()
                            on:input=move |event| name.set(event_target_value(&event))
                        />
                    </div>
                    <div class="form-group">
                        <label for="db-description">"Description"</label>
                        <textarea
                            id="db-description"
                            class="form-input form-textarea"
                            prop:value=move || description.get()
                            on:input=move |event| description.set(event_target_value(&event))
                        ></textarea>
                    </div>
                    <div class="form-group">
                        <label class="checkbox-label">
                            <input
                                type="checkbox"
                                prop:checked=move || recycle_bin.get()
                                on:change=move |event| recycle_bin.set(event_target_checked(&event))
                            />
                            "Use a recycle bin for deleted items"
                        </label>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="db-history-items">"Maximum versions per entry"</label>
                            <input
                                id="db-history-items"
                                type="number"
                                min="0"
                                step="1"
                                class="form-input"
                                placeholder="No limit"
                                prop:value=move || max_items.get()
                                on:input=move |event| max_items.set(event_target_value(&event))
                            />
                        </div>
                        <div class="form-group">
                            <label for="db-history-size">"Maximum history size (MiB)"</label>
                            <input
                                id="db-history-size"
                                type="number"
                                min="0"
                                step="any"
                                class="form-input"
                                placeholder="No limit"
                                prop:value=move || max_size.get()
                                on:input=move |event| max_size.set(event_target_value(&event))
                            />
                        </div>
                    </div>
                    <p class="section-hint">"Leave a limit blank for no limit. Lowering a limit removes the oldest versions."</p>
                    <Show when=move || error.get().is_some()>
                        <div class="error-message" role="alert">{move || error.get().unwrap_or_default()}</div>
                    </Show>
                    <FingerprintSettings />
                    <IdleLockSettings />
                </div>
                <div class="dialog-footer">
                    <button type="button" class="btn btn-secondary" on:click=move |_| close()>"Cancel"</button>
                    <button type="submit" class="btn btn-primary" disabled=move || state.saving.get()>"Apply"</button>
                </div>
            </form>
        </Dialog>
    }
}

/// Fingerprint unlock of the vault on screen, on this device.
#[component]
fn FingerprintSettings() -> impl IntoView {
    let state = expect_context::<AppState>();
    let session = state.active.get_untracked();
    let vault = store_value(state.active_vault_key());
    // `None` while the stored record is being looked up.
    let enrolled = create_rw_signal(Option::<bool>::None);
    let support = create_rw_signal(Support::Unavailable);
    let busy = create_rw_signal(false);
    let message = create_rw_signal(Option::<String>::None);

    if let Some(vault) = vault.get_value() {
        spawn_local(async move {
            let found = quick_unlock::load(&vault).await.is_some();
            support.set(quick_unlock::support().await);
            enrolled.set(Some(found));
        });
    }

    let forget = move |_| {
        let Some(vault) = vault.get_value() else {
            return;
        };
        busy.set(true);
        message.set(None);
        spawn_local(async move {
            match quick_unlock::forget(&vault).await {
                Ok(()) => {
                    enrolled.set(Some(false));
                    message.set(Some(
                        "Fingerprint unlock is off for this vault on this device.".to_string(),
                    ));
                }
                Err(error) => message.set(Some(error)),
            }
            busy.set(false);
        });
    };
    let set_up = move |_| {
        let Some(id) = session else {
            return;
        };
        busy.set(true);
        message.set(None);
        spawn_local(async move {
            match state.enroll_fingerprint(id).await {
                Ok(()) => {
                    enrolled.set(Some(true));
                    message.set(None);
                }
                Err(error) => {
                    message.set(Some(format!("Fingerprint unlock was not set up: {error}")))
                }
            }
            busy.set(false);
        });
    };

    view! {
        <section class="settings-section" aria-labelledby="fingerprint-settings-title">
            <h3 id="fingerprint-settings-title" class="settings-section-title">"Fingerprint unlock"</h3>
            {move || match enrolled.get() {
                None => view! { <p class="section-hint">"Checking…"</p> }.into_view(),
                Some(true) => view! {
                    <p class="section-hint">"This vault can be unlocked with your fingerprint on this device."</p>
                    <button
                        type="button"
                        class="btn btn-secondary"
                        on:click=forget
                        disabled=move || busy.get()
                    >
                        "Forget fingerprint unlock"
                    </button>
                }.into_view(),
                Some(false) if support.get() != Support::Unavailable => view! {
                    <p class="section-hint">"Unlock this vault on this device with your fingerprint instead of the password."</p>
                    <button
                        type="button"
                        class="btn btn-secondary"
                        on:click=set_up
                        disabled=move || busy.get()
                    >
                        <FingerprintIcon />
                        "Set up fingerprint unlock"
                    </button>
                }.into_view(),
                Some(false) => view! {
                    <p class="section-hint">"This browser or device does not offer fingerprint unlock (WebAuthn PRF on a built-in authenticator)."</p>
                }.into_view(),
            }}
            <Show when=move || message.get().is_some()>
                <p class="section-hint" role="status">{move || message.get().unwrap_or_default()}</p>
            </Show>
        </section>
    }
}

/// Choices for the inactivity lock, in seconds; `None` turns it off.
const IDLE_LOCK_CHOICES: [(Option<u32>, &str); 9] = [
    (Some(30), "30 seconds"),
    (Some(60), "1 minute"),
    (Some(2 * 60), "2 minutes"),
    (Some(5 * 60), "5 minutes"),
    (Some(10 * 60), "10 minutes"),
    (Some(15 * 60), "15 minutes"),
    (Some(30 * 60), "30 minutes"),
    (Some(60 * 60), "1 hour"),
    (None, "Never"),
];

/// Inactivity time before every vault locks. Stored per browser and applied at once.
#[component]
fn IdleLockSettings() -> impl IntoView {
    let state = expect_context::<AppState>();
    let on_change = move |event| {
        let value = event_target_value(&event);
        let seconds = value.parse::<u32>().ok();
        state.idle_lock.set(seconds);
        save_idle_lock(seconds);
    };
    let encode =
        |seconds: Option<u32>| seconds.map_or_else(|| "never".to_string(), |s| s.to_string());

    view! {
        <section class="settings-section" aria-labelledby="idle-lock-settings-title">
            <h3 id="idle-lock-settings-title" class="settings-section-title">"Lock when idle"</h3>
            <p class="section-hint">"Lock every vault after this much inactivity. Applies to this browser."</p>
            <select
                class="form-input"
                aria-labelledby="idle-lock-settings-title"
                on:change=on_change
            >
                // `selected` on the option, because a value set on the <select> before its
                // options exist falls back to the first option.
                {IDLE_LOCK_CHOICES
                    .iter()
                    .map(|&(seconds, label)| view! {
                        <option
                            value=encode(seconds)
                            prop:selected=move || state.idle_lock.get() == seconds
                        >
                            {label}
                        </option>
                    })
                    .collect_view()}
            </select>
        </section>
    }
}
