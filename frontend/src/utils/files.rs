//! Browser file input and download helpers.

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Blob, BlobPropertyBag, File, HtmlAnchorElement, HtmlInputElement, Url};

/// Contents of a picked file.
pub async fn read_file(file: &File) -> Result<Vec<u8>, String> {
    let buffer = JsFuture::from(file.array_buffer())
        .await
        .map_err(|_| format!("Failed to read {}", file.name()))?;
    Ok(js_sys::Uint8Array::new(&buffer).to_vec())
}

/// Files selected in the `<input type="file">` that fired `event`. Clears the input so
/// picking the same file again fires another change event.
pub fn take_input_files(event: &web_sys::Event) -> Vec<File> {
    let Some(input) = event
        .target()
        .and_then(|target| target.dyn_into::<HtmlInputElement>().ok())
    else {
        return Vec::new();
    };
    let files = input
        .files()
        .map(|list| (0..list.length()).filter_map(|i| list.get(i)).collect())
        .unwrap_or_default();
    input.set_value("");
    files
}

/// Offers `bytes` to the user as a download named `name`.
pub fn download_bytes(name: &str, bytes: &[u8]) -> Result<(), String> {
    let failed = |_| "Failed to prepare the download".to_string();
    let parts = js_sys::Array::new();
    parts.push(&js_sys::Uint8Array::from(bytes));
    let options = BlobPropertyBag::new();
    options.set_type("application/octet-stream");
    let blob = Blob::new_with_u8_array_sequence_and_options(&parts, &options).map_err(failed)?;
    let url = Url::create_object_url_with_blob(&blob).map_err(failed)?;

    let document = web_sys::window()
        .and_then(|window| window.document())
        .ok_or("No document")?;
    let anchor: HtmlAnchorElement = document
        .create_element("a")
        .map_err(failed)?
        .dyn_into()
        .map_err(|_| "Failed to prepare the download".to_string())?;
    anchor.set_href(&url);
    anchor.set_download(name);
    anchor.click();

    // Revoking synchronously can cancel the download in some browsers.
    let revoke = wasm_bindgen::closure::Closure::once_into_js(move || {
        let _ = Url::revoke_object_url(&url);
    });
    if let Some(window) = web_sys::window() {
        let _ = window
            .set_timeout_with_callback_and_timeout_and_arguments_0(revoke.unchecked_ref(), 60_000);
    }
    Ok(())
}
