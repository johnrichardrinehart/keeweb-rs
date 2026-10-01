//! Client for the keeweb-server database storage API.

use serde::Deserialize;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{File, Request, RequestInit, Response};

/// Whether this build stores databases on the serving keeweb-server.
pub fn storage_enabled() -> bool {
    option_env!("KEEWEB_SERVER_STORAGE") == Some("1")
}

#[derive(Clone, Deserialize)]
pub struct StoredFile {
    pub id: String,
    pub name: String,
    pub size: u64,
}

/// Identity and revision of a database after a successful write.
#[derive(Clone, Deserialize)]
pub struct WrittenFile {
    pub id: String,
    pub name: String,
    pub revision: String,
}

/// Why a conditional replace did not happen.
pub enum ReplaceError {
    /// The server copy is no longer the revision this session is based on.
    Stale,
    Failed(String),
}

fn encode(component: &str) -> String {
    js_sys::encode_uri_component(component).into()
}

async fn fetch(request: &Request) -> Result<Response, String> {
    let window = web_sys::window().ok_or("No window object")?;
    let value = JsFuture::from(window.fetch_with_request(request))
        .await
        .map_err(|_| "The KeePass server is unavailable".to_string())?;
    value
        .dyn_into()
        .map_err(|_| "The server returned an invalid response".to_string())
}

async fn get(url: &str) -> Result<Response, String> {
    let request =
        Request::new_with_str(url).map_err(|_| "Failed to create the request".to_string())?;
    fetch(&request).await
}

async fn json<T: for<'de> Deserialize<'de>>(response: &Response) -> Result<T, String> {
    let value = JsFuture::from(
        response
            .json()
            .map_err(|_| "Failed to read the server response".to_string())?,
    )
    .await
    .map_err(|_| "Failed to read the server response".to_string())?;
    serde_wasm_bindgen::from_value(value)
        .map_err(|_| "The server returned an unexpected response".to_string())
}

async fn bytes(response: &Response) -> Result<Vec<u8>, String> {
    let buffer = JsFuture::from(
        response
            .array_buffer()
            .map_err(|_| "Failed to read the server response".to_string())?,
    )
    .await
    .map_err(|_| "Failed to read the server response".to_string())?;
    Ok(js_sys::Uint8Array::new(&buffer).to_vec())
}

/// `ETag: "<revision>"` → `<revision>`
fn revision_from_etag(response: &Response) -> Option<String> {
    let tag = response.headers().get("ETag").ok().flatten()?;
    let tag = tag.trim();
    let revision = tag
        .strip_prefix('"')
        .and_then(|tag| tag.strip_suffix('"'))
        .unwrap_or(tag);
    (!revision.is_empty() && !tag.starts_with("W/")).then(|| revision.to_ascii_lowercase())
}

pub async fn list_files() -> Result<Vec<StoredFile>, String> {
    let response = get("/api/files").await?;
    if !response.ok() {
        return Err(format!(
            "Failed to list stored databases: HTTP {}.",
            response.status()
        ));
    }
    json(&response).await
}

/// The database bytes and the revision of exactly those bytes.
pub async fn download(id: &str, name: &str) -> Result<(Vec<u8>, String), String> {
    let response = get(&format!("/api/files/{}", encode(id))).await?;
    match response.status() {
        200 => {}
        404 => return Err(format!("{name} no longer exists on the server.")),
        status => return Err(format!("Failed to download {name}: HTTP {status}.")),
    }
    let revision = revision_from_etag(&response)
        .ok_or_else(|| format!("The server sent {name} without a revision."))?;
    Ok((bytes(&response).await?, revision))
}

/// Store a new database; never overwrites an existing one.
pub async fn create(file: &File, name: &str) -> Result<WrittenFile, String> {
    let options = RequestInit::new();
    options.set_method("PUT");
    options.set_body(file.as_ref());
    let request = Request::new_with_str_and_init(&format!("/api/files/{}", encode(name)), &options)
        .map_err(|_| "Failed to create the upload request".to_string())?;
    let response = fetch(&request).await?;
    match response.status() {
        201 => json(&response).await,
        409 => Err(format!("A database named {name} already exists.")),
        status => Err(format!(
            "The server rejected the upload with HTTP {status}."
        )),
    }
}

/// Atomically replace database `id` if the server still holds `revision`.
pub async fn replace(
    id: &str,
    revision: &str,
    content: &[u8],
) -> Result<WrittenFile, ReplaceError> {
    let failed = |message: &str| ReplaceError::Failed(message.to_string());
    let options = RequestInit::new();
    options.set_method("PUT");
    let body = js_sys::Uint8Array::from(content);
    options.set_body(&body);
    let request =
        Request::new_with_str_and_init(&format!("/api/files/{}/content", encode(id)), &options)
            .map_err(|_| failed("Failed to create the save request"))?;
    let headers = request.headers();
    headers
        .set("If-Match", &format!("\"{revision}\""))
        .and_then(|_| headers.set("Content-Type", "application/octet-stream"))
        .map_err(|_| failed("Failed to create the save request"))?;

    let response = fetch(&request).await.map_err(ReplaceError::Failed)?;
    match response.status() {
        200 => json(&response).await.map_err(ReplaceError::Failed),
        412 => Err(ReplaceError::Stale),
        404 => Err(failed("The database no longer exists on the server.")),
        status => Err(ReplaceError::Failed(format!(
            "The server rejected the save with HTTP {status}."
        ))),
    }
}
