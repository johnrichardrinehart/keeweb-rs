//! Password and passphrase generator, modelled on KeePassXC's generator dialog.

use keeweb_wasm::generator::{
    CharClass, GeneratorError, LOOK_ALIKE_CHARACTERS, MAX_PASSWORD_LENGTH, MAX_WORD_COUNT,
    MIN_PASSWORD_LENGTH, MIN_WORD_COUNT, PassphraseOptions, PasswordOptions, Strength, WordCase,
};
use leptos::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;

use crate::state::local_storage;
use crate::utils::clipboard;

const SETTINGS_KEY: &str = "keeweb-rs-password-generator";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    #[default]
    Password,
    Passphrase,
}

/// Generator choices remembered on this browser. The generated value is never stored.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    mode: Mode,
    password: PasswordOptions,
    passphrase: PassphraseOptions,
}

impl Settings {
    fn load() -> Self {
        local_storage()
            .and_then(|storage| storage.get_item(SETTINGS_KEY).ok().flatten())
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default()
    }

    fn save(&self) {
        if let (Some(storage), Ok(json)) = (local_storage(), serde_json::to_string(self)) {
            let _ = storage.set_item(SETTINGS_KEY, &json);
        }
    }

    fn generate(&self) -> Result<String, GeneratorError> {
        match self.mode {
            Mode::Password => self.password.generate(),
            Mode::Passphrase => self.passphrase.generate(),
        }
    }

    fn entropy(&self) -> Result<f64, GeneratorError> {
        match self.mode {
            Mode::Password => self.password.entropy(),
            Mode::Passphrase => self.passphrase.entropy(),
        }
    }
}

/// Parses a count typed or slid into a range or number input, clamped to `min..=max`.
/// Returns `None` while the field is empty or holds no number.
fn count_input(event: &ev::Event, min: usize, max: usize) -> Option<usize> {
    event_target_value(event)
        .parse::<usize>()
        .ok()
        .map(|count| count.clamp(min, max))
}

/// Password generator dialog. With `on_use` the generated value can be written straight
/// into the field that opened the generator.
#[component]
pub fn PasswordGenerator(
    #[prop(into)] on_close: Callback<()>,
    #[prop(optional, into)] on_use: Option<Callback<String>>,
) -> impl IntoView {
    let settings = create_rw_signal(Settings::load());
    let generated = create_rw_signal(Ok::<_, GeneratorError>(String::new()));
    let copied = create_rw_signal(false);
    let entropy = create_memo(move |_| settings.with(|s| s.entropy().ok()));
    let has_value = move || generated.with(Result::is_ok);

    let regenerate = move || {
        generated.set(settings.with_untracked(Settings::generate));
        copied.set(false);
    };

    create_effect(move |_| {
        settings.with(Settings::save);
        regenerate();
    });

    let copy = move |_| {
        let Ok(value) = generated.get_untracked() else {
            return;
        };
        spawn_local(async move {
            if clipboard::copy_to_clipboard(&value).await.is_ok() {
                copied.set(true);
                set_timeout(move || copied.set(false), std::time::Duration::from_secs(2));
            }
        });
    };

    let mode_button = move |mode: Mode, label: &'static str| {
        let active = move || settings.with(|s| s.mode == mode);
        view! {
            <button
                type="button"
                class="generator-toggle"
                class:active=active
                aria-pressed=move || active().to_string()
                on:click=move |_| {
                    if !active() {
                        settings.update(|s| s.mode = mode);
                    }
                }
            >
                {label}
            </button>
        }
    };

    view! {
        <div class="dialog-overlay">
            <div
                class="dialog password-generator-dialog"
                role="dialog"
                aria-modal="true"
                aria-labelledby="generator-title"
            >
                <div class="dialog-header">
                    <h2 id="generator-title">"Generate Password"</h2>
                    <button type="button" class="dialog-close" aria-label="Close" on:click=move |_| on_close.call(())>
                        <svg viewBox="0 0 24 24" width="20" height="20">
                            <path fill="currentColor" d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
                        </svg>
                    </button>
                </div>

                <div class="dialog-body">
                    <div class="generator-segments generator-modes" role="group" aria-label="Generator type">
                        {mode_button(Mode::Password, "Password")}
                        {mode_button(Mode::Passphrase, "Passphrase")}
                    </div>

                    <div class="generated-password-display">
                        {move || generated.with(|result| match result {
                            Ok(value) => view! {
                                <code class="generated-password" aria-label="Generated password">{value.clone()}</code>
                            }.into_view(),
                            Err(error) => view! {
                                <p class="generated-password form-error" role="alert">{error.to_string()}</p>
                            }.into_view(),
                        })}
                        <div class="password-actions">
                            <button type="button" class="btn-icon" on:click=move |_| regenerate() title="Generate new" aria-label="Generate new">
                                <svg viewBox="0 0 24 24" width="20" height="20">
                                    <path fill="currentColor" d="M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/>
                                </svg>
                            </button>
                            <button type="button"
                                class="btn-icon"
                                class:copied=move || copied.get()
                                disabled=move || !has_value()
                                on:click=copy
                                title="Copy to clipboard"
                                aria-label="Copy to clipboard"
                            >
                                <svg viewBox="0 0 24 24" width="20" height="20">
                                    <path fill="currentColor" d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/>
                                </svg>
                            </button>
                        </div>
                    </div>

                    <Quality entropy=entropy />

                    <Show
                        when=move || settings.with(|s| s.mode == Mode::Password)
                        fallback=move || view! { <PassphraseControls settings=settings /> }
                    >
                        <PasswordControls settings=settings />
                    </Show>
                </div>

                <div class="dialog-footer">
                    <button type="button" class="btn btn-secondary" on:click=move |_| on_close.call(())>
                        "Close"
                    </button>
                    {match on_use {
                        Some(on_use) => view! {
                            <button type="button" class="btn btn-secondary" disabled=move || !has_value() on:click=copy>
                                <Show when=move || copied.get() fallback=|| "Copy">
                                    "Copied!"
                                </Show>
                            </button>
                            <button type="button"
                                class="btn btn-primary"
                                disabled=move || !has_value()
                                on:click=move |_| {
                                    if let Ok(value) = generated.get_untracked() {
                                        on_use.call(value);
                                        on_close.call(());
                                    }
                                }
                            >
                                "Use password"
                            </button>
                        }.into_view(),
                        None => view! {
                            <button type="button" class="btn btn-primary" disabled=move || !has_value() on:click=copy>
                                <Show when=move || copied.get() fallback=|| "Copy Password">
                                    "Copied!"
                                </Show>
                            </button>
                        }.into_view(),
                    }}
                </div>
            </div>
        </div>
    }
}

/// Entropy in bits and the quality rating derived from it.
#[component]
fn Quality(entropy: Memo<Option<f64>>) -> impl IntoView {
    let strength = move || entropy.get().map(Strength::from_entropy);
    let bar_class = move || match strength() {
        Some(Strength::Poor) => "strength-bar strength-poor",
        Some(Strength::Weak) => "strength-bar strength-weak",
        Some(Strength::Good) => "strength-bar strength-good",
        Some(Strength::Excellent) => "strength-bar strength-excellent",
        None => "strength-bar",
    };
    // Full at 100 bits, where the rating becomes Excellent.
    let bar_width = move || format!("width: {:.0}%", entropy.get().unwrap_or(0.0).min(100.0));

    view! {
        <div class="password-strength">
            <div class="strength-bar-container">
                <div class=bar_class style=bar_width></div>
            </div>
            <div class="strength-text">
                <span>{move || strength().map(|s| format!("Quality: {}", s.label()))}</span>
                <span>{move || entropy.get().map(|bits| format!("Entropy: {bits:.2} bits"))}</span>
            </div>
        </div>
    }
}

#[component]
fn PasswordControls(settings: RwSignal<Settings>) -> impl IntoView {
    let length = move || settings.with(|s| s.password.length);
    let set_length = move |event: ev::Event| {
        if let Some(length) = count_input(&event, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH) {
            settings.update(|s| s.password.length = length);
        }
    };
    let look_alike_hint = format!(
        "Leaves out {}",
        LOOK_ALIKE_CHARACTERS
            .chars()
            .map(String::from)
            .collect::<Vec<_>>()
            .join(" ")
    );

    view! {
        <div class="generator-options">
            <div class="generator-field">
                <label for="generator-length">"Length"</label>
                <div class="generator-count">
                    <input
                        type="range"
                        id="generator-length"
                        min=MIN_PASSWORD_LENGTH
                        max=MAX_PASSWORD_LENGTH
                        prop:value=length
                        on:input=set_length
                    />
                    <input
                        type="number"
                        class="form-input"
                        aria-label="Length"
                        inputmode="numeric"
                        min=MIN_PASSWORD_LENGTH
                        max=MAX_PASSWORD_LENGTH
                        prop:value=length
                        on:input=set_length
                    />
                </div>
            </div>

            <div class="generator-field">
                <span class="generator-label" id="generator-classes">"Character types"</span>
                <div class="generator-toggles" role="group" aria-labelledby="generator-classes">
                    {CharClass::ALL
                        .into_iter()
                        .map(|class| {
                            let active = move || settings.with(|s| s.password.classes.contains(&class));
                            view! {
                                <button
                                    type="button"
                                    class="generator-toggle"
                                    class:active=active
                                    aria-pressed=move || active().to_string()
                                    aria-label=class.description()
                                    title=class.description()
                                    on:click=move |_| settings.update(|s| {
                                        if !s.password.classes.remove(&class) {
                                            s.password.classes.insert(class);
                                        }
                                    })
                                >
                                    {class.label()}
                                </button>
                            }
                        })
                        .collect_view()}
                </div>
            </div>

            <div class="generator-checks">
                <label class="checkbox-label" title=look_alike_hint>
                    <input
                        type="checkbox"
                        prop:checked=move || settings.with(|s| s.password.exclude_look_alike)
                        on:change=move |event| {
                            let checked = event_target_checked(&event);
                            settings.update(|s| s.password.exclude_look_alike = checked);
                        }
                    />
                    "Exclude look-alike characters"
                </label>
                <label class="checkbox-label">
                    <input
                        type="checkbox"
                        prop:checked=move || settings.with(|s| s.password.every_group)
                        on:change=move |event| {
                            let checked = event_target_checked(&event);
                            settings.update(|s| s.password.every_group = checked);
                        }
                    />
                    "Pick characters from every group"
                </label>
            </div>

            <div class="form-row">
                <div class="form-group">
                    <label for="generator-also-choose">"Also choose from"</label>
                    <input
                        id="generator-also-choose"
                        type="text"
                        class="form-input"
                        autocomplete="off"
                        autocapitalize="off"
                        spellcheck="false"
                        prop:value=move || settings.with(|s| s.password.also_choose.clone())
                        on:input=move |event| {
                            let value = event_target_value(&event);
                            settings.update(|s| s.password.also_choose = value);
                        }
                    />
                </div>
                <div class="form-group">
                    <label for="generator-exclude">"Do not include"</label>
                    <input
                        id="generator-exclude"
                        type="text"
                        class="form-input"
                        autocomplete="off"
                        autocapitalize="off"
                        spellcheck="false"
                        prop:value=move || settings.with(|s| s.password.exclude.clone())
                        on:input=move |event| {
                            let value = event_target_value(&event);
                            settings.update(|s| s.password.exclude = value);
                        }
                    />
                </div>
            </div>
        </div>
    }
}

#[component]
fn PassphraseControls(settings: RwSignal<Settings>) -> impl IntoView {
    let word_count = move || settings.with(|s| s.passphrase.word_count);
    let set_word_count = move |event: ev::Event| {
        if let Some(count) = count_input(&event, MIN_WORD_COUNT, MAX_WORD_COUNT) {
            settings.update(|s| s.passphrase.word_count = count);
        }
    };

    view! {
        <div class="generator-options">
            <div class="generator-field">
                <label for="generator-word-count">"Word count"</label>
                <div class="generator-count">
                    <input
                        type="range"
                        id="generator-word-count"
                        min=MIN_WORD_COUNT
                        max=MAX_WORD_COUNT
                        prop:value=word_count
                        on:input=set_word_count
                    />
                    <input
                        type="number"
                        class="form-input"
                        aria-label="Word count"
                        inputmode="numeric"
                        min=MIN_WORD_COUNT
                        max=MAX_WORD_COUNT
                        prop:value=word_count
                        on:input=set_word_count
                    />
                </div>
            </div>

            <div class="generator-field">
                <span class="generator-label" id="generator-word-case">"Word case"</span>
                <div class="generator-segments" role="group" aria-labelledby="generator-word-case">
                    {WordCase::ALL
                        .into_iter()
                        .map(|case| {
                            let active = move || settings.with(|s| s.passphrase.word_case == case);
                            view! {
                                <button
                                    type="button"
                                    class="generator-toggle"
                                    class:active=active
                                    aria-pressed=move || active().to_string()
                                    on:click=move |_| {
                                        if !active() {
                                            settings.update(|s| s.passphrase.word_case = case);
                                        }
                                    }
                                >
                                    {case.label()}
                                </button>
                            }
                        })
                        .collect_view()}
                </div>
            </div>

            <div class="form-group">
                <label for="generator-separator">"Word separator"</label>
                <input
                    id="generator-separator"
                    type="text"
                    class="form-input"
                    autocomplete="off"
                    autocapitalize="off"
                    spellcheck="false"
                    placeholder="None"
                    prop:value=move || settings.with(|s| s.passphrase.separator.clone())
                    on:input=move |event| {
                        let value = event_target_value(&event);
                        settings.update(|s| s.passphrase.separator = value);
                    }
                />
            </div>

            <p class="section-hint">
                "Words from the EFF large wordlist (7776 words), licensed CC BY 3.0 US."
            </p>
        </div>
    }
}
