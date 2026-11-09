//! Keyboard shortcuts of an open vault.
//!
//! Ctrl/⌘+F moves focus to the entry search; pressed again there, it opens the
//! browser's own find bar.
//!
//! The copy shortcuts act on the entry row that has keyboard focus in the list, the
//! search cursor while the search box has focus, otherwise the entry open in the
//! detail panel. The bindings follow KeeWeb: Ctrl/⌘+C copies the password unless
//! text is selected, Ctrl/⌘+B the username, Ctrl/⌘+U the URL and Alt/⌥+2 the
//! one-time code. They stay off while an entry is being edited, a dialog is open, or
//! focus is in a writable text field other than the entry search.

use keeweb_wasm::document::EntryView;
use leptos::*;
use uuid::Uuid;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::Closure;
use wasm_bindgen_futures::spawn_local;
use web_sys::{Document, HtmlElement, HtmlInputElement, HtmlTextAreaElement, KeyboardEvent};

use crate::components::entry_detail::totp::TotpConfig;
use crate::model::{self, PASSWORD, URL, USER_NAME};
use crate::state::AppState;
use crate::utils::clipboard;

/// Attribute holding the entry UUID on each entry list row.
pub const ENTRY_ATTRIBUTE: &str = "data-entry";

/// Selector of the entry search box.
const SEARCH_INPUT: &str = ".search-input";

/// The key that moves focus to the entry search.
pub struct SearchShortcut;

pub const SEARCH_SHORTCUT: SearchShortcut = SearchShortcut;

impl SearchShortcut {
    fn matches(&self, event: &KeyboardEvent) -> bool {
        (event.ctrl_key() || event.meta_key())
            && !event.alt_key()
            && !event.shift_key()
            && pressed_letter(event) == Some('f')
    }

    /// Binding as shown to the user: "Ctrl+F" or "⌘F".
    pub fn label(&self) -> &'static str {
        if is_mac() { "⌘F" } else { "Ctrl+F" }
    }

    /// Value for `aria-keyshortcuts`.
    pub fn aria(&self) -> &'static str {
        "Control+F Meta+F"
    }
}

/// A key that copies a value of the focused entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CopyShortcut {
    Password,
    Username,
    Url,
    Otp,
}

impl CopyShortcut {
    const ALL: [Self; 4] = [Self::Password, Self::Username, Self::Url, Self::Otp];

    /// Key of the matching copy button in the detail panel.
    fn field_key(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Username => "username",
            Self::Url => "url",
            Self::Otp => "totp",
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Username => "username",
            Self::Url => "URL",
            Self::Otp => "one-time code",
        }
    }

    /// Letter pressed with Ctrl/⌘, or `None` for the Alt+2 binding.
    fn letter(self) -> Option<char> {
        match self {
            Self::Password => Some('c'),
            Self::Username => Some('b'),
            Self::Url => Some('u'),
            Self::Otp => None,
        }
    }

    fn matches(self, event: &KeyboardEvent) -> bool {
        if event.shift_key() {
            return false;
        }
        match self.letter() {
            Some(letter) => {
                (event.ctrl_key() || event.meta_key())
                    && !event.alt_key()
                    && pressed_letter(event) == Some(letter)
            }
            // The physical key, since Alt/⌥ changes the character on some layouts.
            None => {
                event.alt_key()
                    && !event.ctrl_key()
                    && !event.meta_key()
                    && event.code() == "Digit2"
            }
        }
    }

    /// Binding as shown to the user, e.g. "Ctrl+B" or "⌘B".
    pub fn label(self) -> String {
        let mac = is_mac();
        match self.letter() {
            Some(letter) => {
                let letter = letter.to_ascii_uppercase();
                if mac {
                    format!("⌘{letter}")
                } else {
                    format!("Ctrl+{letter}")
                }
            }
            None if mac => "⌥2".to_string(),
            None => "Alt+2".to_string(),
        }
    }

    /// Value for `aria-keyshortcuts`.
    pub fn aria(self) -> &'static str {
        match self {
            Self::Password => "Control+C Meta+C",
            Self::Username => "Control+B Meta+B",
            Self::Url => "Control+U Meta+U",
            Self::Otp => "Alt+2",
        }
    }

    /// Tooltip of a button doing `action`, with this binding appended.
    pub fn hint(self, action: &str) -> String {
        format!("{action} ({})", self.label())
    }
}

/// Lower-case letter of a key press. Falls back to the physical key when the
/// layout produces a non-Latin character, so the bindings work there too.
fn pressed_letter(event: &KeyboardEvent) -> Option<char> {
    let single = |text: &str| {
        let mut chars = text.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None) => Some(c),
            _ => None,
        }
    };
    match single(&event.key()) {
        Some(c) if c.is_ascii_alphabetic() => Some(c.to_ascii_lowercase()),
        Some(_) => event
            .code()
            .strip_prefix("Key")
            .and_then(single)
            .map(|c| c.to_ascii_lowercase()),
        None => None,
    }
}

fn is_mac() -> bool {
    web_sys::window()
        .and_then(|window| window.navigator().platform().ok())
        .is_some_and(|platform| platform.starts_with("Mac") || platform.starts_with("iP"))
}

/// Installs the shortcuts for the lifetime of the page.
pub fn install_entry_shortcuts(state: AppState) {
    let handler: Closure<dyn Fn(KeyboardEvent)> = Closure::new(move |event: KeyboardEvent| {
        if event.default_prevented() || event.repeat() || event.is_composing() {
            return;
        }
        let search = SEARCH_SHORTCUT.matches(&event);
        let copy = CopyShortcut::ALL.into_iter().find(|s| s.matches(&event));
        if !search && copy.is_none() {
            return;
        }
        if state.active.get_untracked().is_none() {
            return;
        }
        let Some(document) = web_sys::window().and_then(|window| window.document()) else {
            return;
        };
        // Open dialogs keep the keyboard to themselves.
        if document
            .query_selector("[aria-modal='true']")
            .ok()
            .flatten()
            .is_some()
        {
            return;
        }
        if search {
            if focus_search(state, &document) {
                event.prevent_default();
            }
            return;
        }
        let Some(shortcut) = copy else {
            return;
        };
        if state.editor.with_untracked(Option::is_some) {
            return;
        }
        // Leave keys alone while the user types, except in the entry search.
        if typing_outside_search(&document) {
            return;
        }
        // Ctrl+C still copies text the user selected.
        if shortcut == CopyShortcut::Password && has_text_selection(&document) {
            return;
        }
        let Some(entry) = target_entry(state, &document) else {
            return;
        };
        event.prevent_default();
        run(state, shortcut, &entry);
    });
    if let Some(window) = web_sys::window() {
        let _ =
            window.add_event_listener_with_callback("keydown", handler.as_ref().unchecked_ref());
    }
    handler.forget();
}

/// Moves focus to the entry search and selects its text. Returns false, leaving the
/// key to the browser, when the search already has focus or cannot take it.
fn focus_search(state: AppState, document: &Document) -> bool {
    let Some(input) = document
        .query_selector(SEARCH_INPUT)
        .ok()
        .flatten()
        .and_then(|element| element.dyn_into::<HtmlInputElement>().ok())
    else {
        return false;
    };
    if document.active_element().as_deref() == Some(input.as_ref()) {
        return false;
    }
    let hidden = input.offset_parent().is_none();
    let focus = move || {
        let _ = input.focus();
        input.select();
    };
    // Narrow screens hide the list behind the open entry; close the entry first,
    // but never an editor with unsaved input.
    if hidden {
        if state.editor.with_untracked(Option::is_some) {
            return false;
        }
        state.selected_entry.set(None);
        request_animation_frame(focus);
    } else {
        focus();
    }
    true
}

/// Whether keyboard focus is in a writable text field other than the entry search.
fn typing_outside_search(document: &Document) -> bool {
    let Some(element) = document.active_element() else {
        return false;
    };
    if element.matches(".search-input").unwrap_or(false) {
        return false;
    }
    if let Some(input) = element.dyn_ref::<HtmlInputElement>() {
        let typed = !matches!(
            input.type_().as_str(),
            "button"
                | "checkbox"
                | "color"
                | "file"
                | "image"
                | "radio"
                | "range"
                | "reset"
                | "submit"
        );
        return typed && !input.read_only();
    }
    if let Some(area) = element.dyn_ref::<HtmlTextAreaElement>() {
        return !area.read_only();
    }
    element
        .dyn_ref::<HtmlElement>()
        .is_some_and(HtmlElement::is_content_editable)
}

/// Whether the page or the focused text field has a non-empty selection.
fn has_text_selection(document: &Document) -> bool {
    let range = document.active_element().and_then(|element| {
        if let Some(input) = element.dyn_ref::<HtmlInputElement>() {
            // Throws for input types without a text selection.
            Some((input.selection_start().ok()??, input.selection_end().ok()??))
        } else if let Some(area) = element.dyn_ref::<HtmlTextAreaElement>() {
            Some((area.selection_start().ok()??, area.selection_end().ok()??))
        } else {
            None
        }
    });
    if range.is_some_and(|(start, end)| start != end) {
        return true;
    }
    document
        .get_selection()
        .ok()
        .flatten()
        .is_some_and(|selection| !selection.is_collapsed())
}

/// The entry row with keyboard focus, the search cursor while the search box has
/// focus, else the entry open in the detail panel.
fn target_entry(state: AppState, document: &Document) -> Option<EntryView> {
    let active = document.active_element();
    let focused = active
        .as_ref()
        .and_then(|element| {
            element
                .closest(&format!("[{ENTRY_ATTRIBUTE}]"))
                .ok()
                .flatten()
        })
        .and_then(|row| row.get_attribute(ENTRY_ATTRIBUTE))
        .and_then(|uuid| Uuid::parse_str(&uuid).ok());
    let in_search = active.is_some_and(|element| element.matches(SEARCH_INPUT).unwrap_or(false));
    let cursor = in_search
        .then(|| state.search_cursor.get_untracked())
        .flatten();
    let uuid = focused
        .or(cursor)
        .or_else(|| state.selected_entry.get_untracked())?;
    state
        .entries
        .with_untracked(|entries| entries.iter().find(|entry| entry.uuid == uuid).cloned())
}

fn run(state: AppState, shortcut: CopyShortcut, entry: &EntryView) {
    let title = model::display_title(entry);
    let value = match shortcut {
        CopyShortcut::Password => model::field(entry, PASSWORD).to_string(),
        CopyShortcut::Username => model::field(entry, USER_NAME).to_string(),
        CopyShortcut::Url => model::field(entry, URL).to_string(),
        CopyShortcut::Otp => match model::otp_value(entry) {
            None => String::new(),
            Some(otp) => match TotpConfig::parse(otp).and_then(|config| config.generate()) {
                Ok(result) => result.code,
                Err(error) => {
                    state
                        .error_message
                        .set(Some(format!("No one-time code for “{title}”: {error}")));
                    return;
                }
            },
        },
    };
    let noun = shortcut.noun();
    if value.is_empty() {
        state.show_notice(format!("“{title}” has no {noun}"));
        return;
    }
    let shown = state.selected_entry.get_untracked() == Some(entry.uuid);
    spawn_local(async move {
        match clipboard::copy_to_clipboard(&value).await {
            Ok(()) => {
                if shown {
                    state.mark_copied(shortcut.field_key().to_string());
                }
                state.show_notice(format!("Copied the {noun} of “{title}”"));
            }
            Err(_) => state
                .error_message
                .set(Some("Could not copy to the clipboard.".to_string())),
        }
    });
}
