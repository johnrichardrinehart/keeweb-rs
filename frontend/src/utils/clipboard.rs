//! Clipboard utilities

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::window;

/// Copy text to the clipboard
pub async fn copy_to_clipboard(text: &str) -> Result<(), JsValue> {
    let window = window().ok_or_else(|| JsValue::from_str("No window object"))?;
    let navigator = window.navigator();
    let clipboard = navigator.clipboard();

    let promise = clipboard.write_text(text);
    JsFuture::from(promise).await?;

    Ok(())
}

/// Read text from clipboard (requires user permission)
#[allow(dead_code)]
pub async fn read_from_clipboard() -> Result<String, JsValue> {
    let window = window().ok_or_else(|| JsValue::from_str("No window object"))?;
    let navigator = window.navigator();
    let clipboard = navigator.clipboard();

    let promise = clipboard.read_text();
    let result = JsFuture::from(promise).await?;

    result
        .as_string()
        .ok_or_else(|| JsValue::from_str("Clipboard content is not a string"))
}
