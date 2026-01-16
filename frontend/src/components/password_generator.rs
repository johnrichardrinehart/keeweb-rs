//! Password generator component

use leptos::*;
use rand::Rng;
use wasm_bindgen_futures::spawn_local;

use crate::utils::clipboard;

/// Password generator options
#[derive(Clone)]
struct GeneratorOptions {
    length: usize,
    uppercase: bool,
    lowercase: bool,
    numbers: bool,
    symbols: bool,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
        }
    }
}

/// Password generator component
#[component]
pub fn PasswordGenerator<F>(on_close: F) -> impl IntoView
where
    F: Fn() + 'static + Clone,
{
    let options = create_rw_signal(GeneratorOptions::default());
    let generated_password = create_rw_signal(String::new());
    let copied = create_rw_signal(false);

    // Generate initial password
    create_effect(move |_| {
        let opts = options.get();
        let password = generate_password(&opts);
        generated_password.set(password);
    });

    // Regenerate password
    let regenerate = move |_| {
        let opts = options.get();
        let password = generate_password(&opts);
        generated_password.set(password);
        copied.set(false);
    };

    // Copy to clipboard
    let copy = move |_| {
        let password = generated_password.get();
        spawn_local(async move {
            if clipboard::copy_to_clipboard(&password).await.is_ok() {
                copied.set(true);
                set_timeout(move || copied.set(false), std::time::Duration::from_secs(2));
            }
        });
    };

    // Update options
    let set_length = move |ev| {
        let value: usize = event_target_value(&ev).parse().unwrap_or(20);
        options.update(|o| o.length = value.clamp(4, 128));
    };

    let toggle_uppercase = move |_| {
        options.update(|o| o.uppercase = !o.uppercase);
    };

    let toggle_lowercase = move |_| {
        options.update(|o| o.lowercase = !o.lowercase);
    };

    let toggle_numbers = move |_| {
        options.update(|o| o.numbers = !o.numbers);
    };

    let toggle_symbols = move |_| {
        options.update(|o| o.symbols = !o.symbols);
    };

    let on_close_click = {
        let on_close = on_close.clone();
        move |_| on_close()
    };

    view! {
        <div class="dialog-overlay">
            <div class="dialog password-generator-dialog">
                <div class="dialog-header">
                    <h2>"Password Generator"</h2>
                    <button class="dialog-close" on:click=on_close_click>
                        <svg viewBox="0 0 24 24" width="20" height="20">
                            <path fill="currentColor" d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
                        </svg>
                    </button>
                </div>

                <div class="dialog-body">
                    // Generated password display
                    <div class="generated-password-display">
                        <code class="generated-password">{move || generated_password.get()}</code>
                        <div class="password-actions">
                            <button class="btn-icon" on:click=regenerate title="Generate new">
                                <svg viewBox="0 0 24 24" width="20" height="20">
                                    <path fill="currentColor" d="M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/>
                                </svg>
                            </button>
                            <button
                                class="btn-icon"
                                class:copied=move || copied.get()
                                on:click=copy
                                title="Copy to clipboard"
                            >
                                <svg viewBox="0 0 24 24" width="20" height="20">
                                    <path fill="currentColor" d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/>
                                </svg>
                            </button>
                        </div>
                    </div>

                    // Password strength indicator
                    <div class="password-strength">
                        <PasswordStrengthBar password=generated_password />
                    </div>

                    // Options
                    <div class="generator-options">
                        <div class="option-row">
                            <label for="length">"Length: " {move || options.get().length}</label>
                            <input
                                type="range"
                                id="length"
                                min="4"
                                max="128"
                                prop:value=move || options.get().length
                                on:input=set_length
                            />
                        </div>

                        <div class="option-row">
                            <label>
                                <input
                                    type="checkbox"
                                    prop:checked=move || options.get().uppercase
                                    on:change=toggle_uppercase
                                />
                                " Uppercase (A-Z)"
                            </label>
                        </div>

                        <div class="option-row">
                            <label>
                                <input
                                    type="checkbox"
                                    prop:checked=move || options.get().lowercase
                                    on:change=toggle_lowercase
                                />
                                " Lowercase (a-z)"
                            </label>
                        </div>

                        <div class="option-row">
                            <label>
                                <input
                                    type="checkbox"
                                    prop:checked=move || options.get().numbers
                                    on:change=toggle_numbers
                                />
                                " Numbers (0-9)"
                            </label>
                        </div>

                        <div class="option-row">
                            <label>
                                <input
                                    type="checkbox"
                                    prop:checked=move || options.get().symbols
                                    on:change=toggle_symbols
                                />
                                " Symbols (!@#$%...)"
                            </label>
                        </div>
                    </div>
                </div>

                <div class="dialog-footer">
                    <button class="btn btn-secondary" on:click={
                        let on_close = on_close.clone();
                        move |_| on_close()
                    }>
                        "Close"
                    </button>
                    <button class="btn btn-primary" on:click=copy>
                        <Show when=move || copied.get() fallback=|| "Copy Password">
                            "Copied!"
                        </Show>
                    </button>
                </div>
            </div>
        </div>
    }
}

/// Password strength indicator bar
#[component]
fn PasswordStrengthBar(password: RwSignal<String>) -> impl IntoView {
    let strength = move || calculate_strength(&password.get());

    let strength_class = move || match strength() {
        0..=20 => "strength-weak",
        21..=40 => "strength-fair",
        41..=60 => "strength-good",
        61..=80 => "strength-strong",
        _ => "strength-excellent",
    };

    let strength_text = move || match strength() {
        0..=20 => "Weak",
        21..=40 => "Fair",
        41..=60 => "Good",
        61..=80 => "Strong",
        _ => "Excellent",
    };

    view! {
        <div class="strength-bar-container">
            <div
                class="strength-bar"
                class=strength_class
                style=move || format!("width: {}%", strength())
            ></div>
        </div>
        <span class="strength-text">{strength_text}</span>
    }
}

/// Generate a password with the given options
fn generate_password(options: &GeneratorOptions) -> String {
    const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const NUMBERS: &[u8] = b"0123456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";

    let mut charset = Vec::new();

    if options.uppercase {
        charset.extend_from_slice(UPPERCASE);
    }
    if options.lowercase {
        charset.extend_from_slice(LOWERCASE);
    }
    if options.numbers {
        charset.extend_from_slice(NUMBERS);
    }
    if options.symbols {
        charset.extend_from_slice(SYMBOLS);
    }

    // If no options selected, use lowercase as default
    if charset.is_empty() {
        charset.extend_from_slice(LOWERCASE);
    }

    let mut rng = rand::thread_rng();
    let password: String = (0..options.length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect();

    password
}

/// Calculate password strength (0-100)
fn calculate_strength(password: &str) -> u32 {
    if password.is_empty() {
        return 0;
    }

    let mut score: u32 = 0;

    // Length score (up to 40 points)
    score += (password.len() as u32).min(40);

    // Character variety (up to 60 points)
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_alphanumeric());

    if has_lower {
        score += 15;
    }
    if has_upper {
        score += 15;
    }
    if has_digit {
        score += 15;
    }
    if has_symbol {
        score += 15;
    }

    score.min(100)
}
