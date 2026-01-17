//! WASM bindings for keeweb-rs
//!
//! This crate provides JavaScript bindings for the kdbx-core and kdbx-diff crates,
//! allowing them to be used in web browsers via WebAssembly.

use kdbx_core::{compute_composite_key, parse_kdbx4_header, Database, Entry, EntryBuilder, Group, KdfType};
use kdbx_core::{TotpAlgorithm, TotpConfig};
use kdbx_diff::{DatabaseDiff, Merger, Resolution};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

/// Initialize panic hook for better error messages.
/// Call this function once at startup from your application.
#[allow(unexpected_cfgs)]
pub fn init_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// A WASM-compatible wrapper around a KeePass database
#[wasm_bindgen]
pub struct WasmDatabase {
    inner: Database,
}

#[wasm_bindgen]
impl WasmDatabase {
    /// Open a database from bytes with a password
    #[wasm_bindgen(constructor)]
    pub fn open(data: &[u8], password: &str) -> Result<WasmDatabase, JsValue> {
        Database::open(data, password)
            .map(|db| WasmDatabase { inner: db })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Create a new empty database
    #[wasm_bindgen(js_name = create)]
    pub fn create(name: &str, password: &str) -> WasmDatabase {
        WasmDatabase {
            inner: Database::new(name, password),
        }
    }

    /// Save the database to bytes
    pub fn save(&self) -> Result<Vec<u8>, JsValue> {
        self.inner
            .save()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Get database metadata as JSON
    #[wasm_bindgen(js_name = getMetadata)]
    pub fn get_metadata(&self) -> String {
        serde_json::to_string(&self.inner.metadata()).unwrap_or_default()
    }

    /// Get all entries as JSON
    #[wasm_bindgen(js_name = getEntries)]
    pub fn get_entries(&self) -> String {
        let entries: Vec<&Entry> = self.inner.entries().collect();
        serde_json::to_string(&entries).unwrap_or_default()
    }

    /// Get a single entry by UUID as JSON
    #[wasm_bindgen(js_name = getEntry)]
    pub fn get_entry(&self, uuid: &str) -> Option<String> {
        let uuid = uuid::Uuid::parse_str(uuid).ok()?;
        self.inner
            .get_entry(&uuid)
            .map(|e| serde_json::to_string(e).unwrap_or_default())
    }

    /// Add a new entry from JSON
    #[wasm_bindgen(js_name = addEntry)]
    pub fn add_entry(&mut self, entry_json: &str) -> Result<String, JsValue> {
        let entry_data: EntryData =
            serde_json::from_str(entry_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let mut builder = EntryBuilder::new(&entry_data.title);

        if let Some(username) = entry_data.username {
            builder = builder.username(username);
        }
        if let Some(password) = entry_data.password {
            builder = builder.password(password);
        }
        if let Some(url) = entry_data.url {
            builder = builder.url(url);
        }
        if let Some(notes) = entry_data.notes {
            builder = builder.notes(notes);
        }

        let entry = builder.build();
        let uuid = self.inner.add_entry(entry);
        Ok(uuid.to_string())
    }

    /// Update an existing entry from JSON
    #[wasm_bindgen(js_name = updateEntry)]
    pub fn update_entry(&mut self, uuid: &str, entry_json: &str) -> Result<(), JsValue> {
        let uuid = uuid::Uuid::parse_str(uuid)
            .map_err(|e: uuid::Error| JsValue::from_str(&e.to_string()))?;

        let entry_data: EntryData =
            serde_json::from_str(entry_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let entry = self
            .inner
            .get_entry_mut(&uuid)
            .ok_or_else(|| JsValue::from_str("Entry not found"))?;

        entry.title = entry_data.title;
        if let Some(username) = entry_data.username {
            entry.username = username;
        }
        if let Some(password) = entry_data.password {
            entry.set_password(password);
        }
        if let Some(url) = entry_data.url {
            entry.url = url;
        }
        if let Some(notes) = entry_data.notes {
            entry.notes = notes;
        }
        entry.mark_modified();

        Ok(())
    }

    /// Delete an entry by UUID
    #[wasm_bindgen(js_name = deleteEntry)]
    pub fn delete_entry(&mut self, uuid: &str) -> Result<(), JsValue> {
        let uuid = uuid::Uuid::parse_str(uuid)
            .map_err(|e: uuid::Error| JsValue::from_str(&e.to_string()))?;
        self.inner
            .delete_entry(&uuid)
            .map(|_| ())
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Search entries by query
    pub fn search(&self, query: &str) -> String {
        let results: Vec<&Entry> = self.inner.search(query);
        serde_json::to_string(&results).unwrap_or_default()
    }

    /// Get the group tree as JSON
    #[wasm_bindgen(js_name = getGroupTree)]
    pub fn get_group_tree(&self) -> String {
        serde_json::to_string(&self.inner.group_tree()).unwrap_or_default()
    }

    /// Get all groups as JSON
    #[wasm_bindgen(js_name = getGroups)]
    pub fn get_groups(&self) -> String {
        let groups: Vec<&Group> = self.inner.groups().collect();
        serde_json::to_string(&groups).unwrap_or_default()
    }

    /// Add a new group
    #[wasm_bindgen(js_name = addGroup)]
    pub fn add_group(
        &mut self,
        name: &str,
        parent_uuid: Option<String>,
    ) -> Result<String, JsValue> {
        let mut group = Group::new(name);

        if let Some(parent_str) = parent_uuid {
            let parent = uuid::Uuid::parse_str(&parent_str)
                .map_err(|e: uuid::Error| JsValue::from_str(&e.to_string()))?;
            group.parent = Some(parent);
        }

        let uuid = self.inner.add_group(group);
        Ok(uuid.to_string())
    }
}

/// Internal helper struct for entry JSON serialization
#[derive(Debug, Serialize, Deserialize)]
struct EntryData {
    title: String,
    username: Option<String>,
    password: Option<String>,
    url: Option<String>,
    notes: Option<String>,
}

/// Compute a two-way diff between two databases
#[wasm_bindgen(js_name = diffDatabases)]
pub fn diff_databases(left: &WasmDatabase, right: &WasmDatabase) -> String {
    let diff = DatabaseDiff::two_way(&left.inner, &right.inner);
    serde_json::to_string(&diff).unwrap_or_default()
}

/// Compute a three-way diff between databases
#[wasm_bindgen(js_name = diffDatabasesThreeWay)]
pub fn diff_databases_three_way(
    base: &WasmDatabase,
    left: &WasmDatabase,
    right: &WasmDatabase,
) -> String {
    let diff = DatabaseDiff::three_way(&base.inner, &left.inner, &right.inner);
    serde_json::to_string(&diff).unwrap_or_default()
}

/// Merge two databases with provided resolutions
#[wasm_bindgen(js_name = mergeDatabases)]
pub fn merge_databases(
    base: &WasmDatabase,
    left: &WasmDatabase,
    right: &WasmDatabase,
    resolutions_json: &str,
) -> Result<WasmMergeResult, JsValue> {
    // Parse resolutions
    let resolutions_map: HashMap<String, String> =
        serde_json::from_str(resolutions_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Convert to proper resolution types
    let mut resolutions = HashMap::new();
    for (uuid_str, resolution_str) in resolutions_map {
        let uuid = uuid::Uuid::parse_str(&uuid_str)
            .map_err(|e: uuid::Error| JsValue::from_str(&e.to_string()))?;
        let resolution = parse_resolution(&resolution_str)?;
        resolutions.insert(uuid, resolution);
    }

    let merger = Merger::new();
    let (merged_db, result) =
        merger.merge_three_way(&base.inner, &left.inner, &right.inner, &resolutions);

    Ok(WasmMergeResult {
        database: WasmDatabase { inner: merged_db },
        result_json: serde_json::to_string(&result).unwrap_or_default(),
    })
}

/// Result of a merge operation
#[wasm_bindgen]
pub struct WasmMergeResult {
    database: WasmDatabase,
    result_json: String,
}

#[wasm_bindgen]
impl WasmMergeResult {
    /// Get the merged database
    #[wasm_bindgen(getter)]
    pub fn database(self) -> WasmDatabase {
        self.database
    }

    /// Get the merge result as JSON
    #[wasm_bindgen(js_name = getResult)]
    pub fn get_result(&self) -> String {
        self.result_json.clone()
    }
}

/// Parse a resolution string into a Resolution enum
fn parse_resolution(s: &str) -> Result<Resolution, JsValue> {
    match s.to_lowercase().as_str() {
        "left" | "takeleft" | "take_left" => Ok(Resolution::TakeLeft),
        "right" | "takeright" | "take_right" => Ok(Resolution::TakeRight),
        "base" | "takebase" | "take_base" => Ok(Resolution::TakeBase),
        "newest" | "takenewest" | "take_newest" => Ok(Resolution::TakeNewest),
        _ => {
            // Assume it's a manual value
            if s.starts_with("manual:") {
                Ok(Resolution::Manual(s[7..].to_string()))
            } else {
                Err(JsValue::from_str(&format!("Unknown resolution: {}", s)))
            }
        }
    }
}

// ============================================================================
// Fast unlock with external KDF (for argon2-browser SIMD)
// ============================================================================

/// KDF parameters extracted from KDBX4 header
#[wasm_bindgen]
pub struct WasmKdfParams {
    kdf_type: String,
    salt: Vec<u8>,
    memory_kb: u64,
    iterations: u64,
    parallelism: u32,
    version: u32,
    composite_key: Vec<u8>,
}

#[wasm_bindgen]
impl WasmKdfParams {
    #[wasm_bindgen(getter, js_name = kdfType)]
    pub fn kdf_type(&self) -> String {
        self.kdf_type.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn salt(&self) -> Vec<u8> {
        self.salt.clone()
    }

    #[wasm_bindgen(getter, js_name = memoryKb)]
    pub fn memory_kb(&self) -> u64 {
        self.memory_kb
    }

    #[wasm_bindgen(getter)]
    pub fn iterations(&self) -> u64 {
        self.iterations
    }

    #[wasm_bindgen(getter)]
    pub fn parallelism(&self) -> u32 {
        self.parallelism
    }

    #[wasm_bindgen(getter)]
    pub fn version(&self) -> u32 {
        self.version
    }

    #[wasm_bindgen(getter, js_name = compositeKey)]
    pub fn composite_key(&self) -> Vec<u8> {
        self.composite_key.clone()
    }
}

/// Parse KDBX4 header and extract KDF parameters for external processing
///
/// This allows using a faster external Argon2 implementation (like argon2-browser SIMD)
/// instead of the internal rust-argon2.
#[wasm_bindgen(js_name = getKdfParams)]
pub fn get_kdf_params(data: &[u8], password: &str) -> Result<WasmKdfParams, JsValue> {
    let header = parse_kdbx4_header(data)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let kdf_type = match header.kdf_params.kdf_type {
        KdfType::Argon2d => "argon2d",
        KdfType::Argon2id => "argon2id",
    };

    let composite_key = compute_composite_key(password);

    Ok(WasmKdfParams {
        kdf_type: kdf_type.to_string(),
        salt: header.kdf_params.salt,
        memory_kb: header.kdf_params.memory_kb,
        iterations: header.kdf_params.iterations,
        parallelism: header.kdf_params.parallelism,
        version: header.kdf_params.version,
        composite_key: composite_key.to_vec(),
    })
}

/// Decrypt and parse a database using a pre-computed transformed key (from external Argon2)
///
/// The `transformed_key` should be the 32-byte output of running Argon2 on the
/// composite key with the parameters from `getKdfParams`.
///
/// Returns JSON with entries and groups directly, bypassing Database construction.
#[wasm_bindgen(js_name = decryptWithDerivedKey)]
pub fn decrypt_with_derived_key(
    data: &[u8],
    password: &str,
    transformed_key: &[u8],
) -> Result<WasmDecryptResult, JsValue> {
    if transformed_key.len() != 32 {
        return Err(JsValue::from_str("Transformed key must be 32 bytes"));
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(transformed_key);

    // Use our custom decryption that accepts a pre-computed key and decrypts protected values
    let decrypted_xml = kdbx_core::decrypt_kdbx4_full(data, password, &key_arr)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Parse the XML to extract entries and groups
    let (entries_json, groups_json, metadata_json) = parse_kdbx_xml(decrypted_xml.as_bytes())
        .map_err(|e| JsValue::from_str(&e))?;

    Ok(WasmDecryptResult {
        entries_json,
        groups_json,
        metadata_json,
    })
}

/// Result of decryption with derived key
#[wasm_bindgen]
pub struct WasmDecryptResult {
    entries_json: String,
    groups_json: String,
    metadata_json: String,
}

#[wasm_bindgen]
impl WasmDecryptResult {
    #[wasm_bindgen(getter, js_name = entriesJson)]
    pub fn entries_json(&self) -> String {
        self.entries_json.clone()
    }

    #[wasm_bindgen(getter, js_name = groupsJson)]
    pub fn groups_json(&self) -> String {
        self.groups_json.clone()
    }

    #[wasm_bindgen(getter, js_name = metadataJson)]
    pub fn metadata_json(&self) -> String {
        self.metadata_json.clone()
    }
}

// ============================================================================
// TOTP (Time-based One-Time Password) support
// ============================================================================

/// TOTP code result with metadata
#[wasm_bindgen]
pub struct TotpResult {
    code: String,
    period: u32,
    remaining: u32,
    digits: u32,
}

#[wasm_bindgen]
impl TotpResult {
    /// The generated TOTP code
    #[wasm_bindgen(getter)]
    pub fn code(&self) -> String {
        self.code.clone()
    }

    /// The time period in seconds
    #[wasm_bindgen(getter)]
    pub fn period(&self) -> u32 {
        self.period
    }

    /// Seconds remaining until the code changes
    #[wasm_bindgen(getter)]
    pub fn remaining(&self) -> u32 {
        self.remaining
    }

    /// Number of digits in the code
    #[wasm_bindgen(getter)]
    pub fn digits(&self) -> u32 {
        self.digits
    }
}

/// Generate a TOTP code from an OTP configuration string
///
/// Accepts:
/// - otpauth://totp/... URI format (KeePassXC standard)
/// - Bare base32 secret (uses defaults: SHA1, 6 digits, 30s period)
///
/// Returns a TotpResult with the code and metadata, or an error message.
#[wasm_bindgen(js_name = generateTotp)]
pub fn generate_totp(otp_value: &str) -> Result<TotpResult, JsValue> {
    let config = TotpConfig::parse(otp_value)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let code = config.generate()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(TotpResult {
        code,
        period: config.period,
        remaining: config.time_remaining(),
        digits: config.digits,
    })
}

/// Parse a TOTP configuration and return its details as JSON
///
/// Returns JSON with: secret, digits, period, algorithm, issuer, label
#[wasm_bindgen(js_name = parseTotpConfig)]
pub fn parse_totp_config(otp_value: &str) -> Result<String, JsValue> {
    let config = TotpConfig::parse(otp_value)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    #[derive(Serialize)]
    struct TotpConfigJson {
        digits: u32,
        period: u32,
        algorithm: String,
        issuer: Option<String>,
        label: Option<String>,
    }

    let json = TotpConfigJson {
        digits: config.digits,
        period: config.period,
        algorithm: match config.algorithm {
            TotpAlgorithm::Sha1 => "SHA1".to_string(),
            TotpAlgorithm::Sha256 => "SHA256".to_string(),
            TotpAlgorithm::Sha512 => "SHA512".to_string(),
        },
        issuer: config.issuer,
        label: config.label,
    };

    serde_json::to_string(&json)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Check if a string looks like a valid TOTP configuration
#[wasm_bindgen(js_name = isValidTotp)]
pub fn is_valid_totp(otp_value: &str) -> bool {
    TotpConfig::parse(otp_value).is_ok()
}

/// Simple XML parser for KDBX format - extracts entries and groups
fn parse_kdbx_xml(xml_data: &[u8]) -> Result<(String, String, String), String> {

    // Skip inner header (binary format before XML)
    let xml_start = find_xml_start(xml_data)?;
    let xml_str = std::str::from_utf8(&xml_data[xml_start..])
        .map_err(|_| "Invalid UTF-8 in XML")?;

    // Simple XML parsing - look for Entry and Group elements
    let mut entries: Vec<SimpleEntry> = Vec::new();
    let mut groups: Vec<SimpleGroup> = Vec::new();

    // Parse groups
    for group_match in find_elements(xml_str, "Group") {
        if let Some(group) = parse_group_element(&group_match) {
            groups.push(group);
        }
    }

    // Parse entries - find top-level entries only (not those inside <History>)
    // We need to parse entries from the original XML to get their history,
    // but only parse top-level Entry elements (not nested ones in History)
    let entry_elements = find_top_level_entries(xml_str);

    for entry_match in entry_elements.iter() {
        if let Some(entry) = parse_entry_element(&entry_match) {
            entries.push(entry);
        }
    }

    let entries_json = serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string());
    let groups_json = serde_json::to_string(&groups).unwrap_or_else(|_| "[]".to_string());
    let metadata_json = "{}".to_string(); // TODO: parse metadata

    Ok((entries_json, groups_json, metadata_json))
}

fn find_xml_start(data: &[u8]) -> Result<usize, String> {
    // Inner header format: type (1 byte) + length (4 bytes) + data
    // Type 0 = end
    let mut pos = 0;
    while pos < data.len() {
        let entry_type = data[pos];
        if pos + 5 > data.len() {
            break;
        }
        let entry_len = u32::from_le_bytes([data[pos+1], data[pos+2], data[pos+3], data[pos+4]]) as usize;
        pos += 5 + entry_len;

        if entry_type == 0 {
            // End of inner header
            return Ok(pos);
        }
    }

    // Try to find <?xml directly
    if let Some(idx) = data.windows(5).position(|w| w == b"<?xml") {
        return Ok(idx);
    }

    Err("Could not find XML start".to_string())
}

/// A historical version of an entry
#[derive(Serialize, Clone)]
struct HistoryEntry {
    title: String,
    username: String,
    password: Option<String>,
    url: String,
    notes: String,
    /// Last modification time of this history version
    last_modification_time: Option<String>,
}

#[derive(Serialize)]
struct SimpleEntry {
    uuid: String,
    title: String,
    username: String,
    password: Option<String>,
    url: String,
    notes: String,
    parent_group: Option<String>,
    /// TOTP/OTP configuration (otpauth:// URI or bare secret)
    otp: Option<String>,
    /// Historical versions of this entry (oldest first)
    #[serde(default)]
    history: Vec<HistoryEntry>,
}

#[derive(Serialize)]
struct SimpleGroup {
    uuid: String,
    name: String,
    parent: Option<String>,
    icon_id: Option<u32>,
}

/// Find top-level Entry elements (not those nested inside <History>)
fn find_top_level_entries(xml: &str) -> Vec<String> {
    let mut results = Vec::new();
    let open_tag_exact = "<Entry>";
    let open_tag_attr = "<Entry ";

    let mut search_pos = 0;
    while search_pos < xml.len() {
        // Find either <Entry> or <Entry with attributes
        let start_exact = xml[search_pos..].find(open_tag_exact);
        let start_attr = xml[search_pos..].find(open_tag_attr);

        let start = match (start_exact, start_attr) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        match start {
            Some(rel_start) => {
                let abs_start = search_pos + rel_start;

                // Check if this Entry is inside a <History> section
                // Look backwards for <History> and </History>
                let before = &xml[..abs_start];
                let last_history_open = before.rfind("<History>");
                let last_history_close = before.rfind("</History>");

                let is_inside_history = match (last_history_open, last_history_close) {
                    (Some(open), Some(close)) => open > close, // Inside if <History> is after </History>
                    (Some(_), None) => true,                   // Inside if <History> but no </History>
                    _ => false,
                };

                // Find the matching </Entry> (accounting for nesting)
                if let Some(end_pos) = find_matching_close_tag(&xml[abs_start..], "Entry") {
                    let abs_end = abs_start + end_pos;

                    if !is_inside_history {
                        let entry_xml = &xml[abs_start..abs_end];
                        results.push(entry_xml.to_string());
                    }

                    search_pos = abs_end;
                } else {
                    break;
                }
            }
            None => break,
        }
    }

    results
}

/// Find the position of the matching closing tag, accounting for nested tags
/// xml should start AT the opening tag (e.g., "<Entry>...")
fn find_matching_close_tag(xml: &str, tag: &str) -> Option<usize> {
    let open_tag_exact = format!("<{}>", tag);
    let open_tag_attr = format!("<{} ", tag);
    let close_tag = format!("</{}>", tag);

    // We start AT an opening tag, so depth starts at 1
    let mut depth = 1;

    // Skip past the initial opening tag
    let initial_tag_end = xml.find('>')? + 1;
    let mut pos = initial_tag_end;

    while pos < xml.len() {
        // Look for next open or close tag
        let next_open_exact = xml[pos..].find(&open_tag_exact);
        let next_open_attr = xml[pos..].find(&open_tag_attr);
        let next_close = xml[pos..].find(&close_tag);

        let next_open = match (next_open_exact, next_open_attr) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        match (next_open, next_close) {
            (Some(open), Some(close)) if open < close => {
                // Found open tag first - nested element
                depth += 1;
                pos += open + 1; // Move past the '<'
            }
            (_, Some(close)) => {
                // Found close tag (or close tag is before open tag)
                depth -= 1;
                if depth == 0 {
                    // This is the matching close tag
                    return Some(pos + close + close_tag.len());
                }
                pos += close + close_tag.len();
            }
            (Some(open), None) => {
                // Only found open tag, no close tag
                depth += 1;
                pos += open + 1;
            }
            (None, None) => {
                // No more tags found
                return None;
            }
        }
    }

    None
}

/// Remove all <History>...</History> sections from XML to avoid parsing old entry versions
#[allow(dead_code)]
fn remove_history_sections(xml: &str) -> String {
    let mut result = String::with_capacity(xml.len());
    let mut pos = 0;

    while pos < xml.len() {
        if let Some(history_start) = xml[pos..].find("<History>") {
            // Copy everything before <History>
            result.push_str(&xml[pos..pos + history_start]);

            // Find the matching </History>
            let search_start = pos + history_start;
            if let Some(history_end) = xml[search_start..].find("</History>") {
                // Skip past </History>
                pos = search_start + history_end + "</History>".len();
            } else {
                // No closing tag found, copy the rest
                result.push_str(&xml[pos + history_start..]);
                break;
            }
        } else {
            // No more History sections, copy the rest
            result.push_str(&xml[pos..]);
            break;
        }
    }

    result
}

fn find_elements(xml: &str, tag: &str) -> Vec<String> {
    let mut results = Vec::new();
    // Match <tag> or <tag followed by space/attributes
    let open_tag_exact = format!("<{}>", tag);
    let open_tag_attr = format!("<{} ", tag);
    let close_tag = format!("</{}>", tag);

    let mut search_pos = 0;
    while search_pos < xml.len() {
        // Find either <tag> or <tag with attributes
        let start_exact = xml[search_pos..].find(&open_tag_exact);
        let start_attr = xml[search_pos..].find(&open_tag_attr);

        let start = match (start_exact, start_attr) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        match start {
            Some(rel_start) => {
                let abs_start = search_pos + rel_start;
                if let Some(end) = xml[abs_start..].find(&close_tag) {
                    let abs_end = abs_start + end + close_tag.len();
                    results.push(xml[abs_start..abs_end].to_string());
                    search_pos = abs_end;
                } else {
                    break;
                }
            }
            None => break,
        }
    }

    results
}

fn parse_entry_element(xml: &str) -> Option<SimpleEntry> {
    // Extract the part before <History> to parse the main entry data
    // Also extract the History section separately to parse historical versions
    let (xml_to_parse, history_xml) = if let Some(history_pos) = xml.find("<History>") {
        let history_end = xml.find("</History>").unwrap_or(xml.len());
        let hist_section = &xml[history_pos..history_end + "</History>".len()];
        (&xml[..history_pos], Some(hist_section))
    } else {
        (xml, None)
    };

    let uuid = extract_tag_value(xml_to_parse, "UUID")?;
    let title = extract_string_value(xml_to_parse, "Title").unwrap_or_default();

    // Debug: dump all Key names found in this entry
    #[cfg(target_arch = "wasm32")]
    {
        let mut keys = Vec::new();
        let key_pattern = "<Key>";
        let mut pos = 0;
        while let Some(start) = xml_to_parse[pos..].find(key_pattern) {
            let abs_start = pos + start + key_pattern.len();
            if let Some(end) = xml_to_parse[abs_start..].find("</Key>") {
                let key_name = &xml_to_parse[abs_start..abs_start + end];
                keys.push(key_name.to_string());
            }
            pos = abs_start;
        }
        web_sys::console::log_1(&format!(
            "[parse_entry] title='{}', keys={:?}",
            title, keys
        ).into());
    }

    let username = extract_string_value(xml_to_parse, "UserName").unwrap_or_default();
    let password = extract_string_value(xml_to_parse, "Password");
    let url = extract_string_value(xml_to_parse, "URL").unwrap_or_default();
    let notes = extract_string_value(xml_to_parse, "Notes").unwrap_or_default();
    // KeePassXC stores TOTP config in "otp" field (can also be "TOTP Seed" or "TOTP" in some implementations)
    // Try multiple case variations since different implementations may use different cases
    let otp = extract_string_value(xml_to_parse, "otp")
        .or_else(|| extract_string_value(xml_to_parse, "OTP"))
        .or_else(|| extract_string_value(xml_to_parse, "TOTP Seed"))
        .or_else(|| extract_string_value(xml_to_parse, "TOTP"))
        .or_else(|| extract_string_value(xml_to_parse, "totp"));

    // Debug: log if we found an OTP value
    #[cfg(target_arch = "wasm32")]
    if otp.is_some() {
        web_sys::console::log_1(&format!("Found OTP for entry '{}': {:?}", title, otp.as_ref().map(|s| if s.len() > 20 { format!("{}...", &s[..20]) } else { s.clone() })).into());
    }

    // Parse history entries
    let history = if let Some(hist_xml) = history_xml {
        parse_history_entries(hist_xml)
    } else {
        Vec::new()
    };

    Some(SimpleEntry {
        uuid,
        title,
        username,
        password,
        url,
        notes,
        parent_group: None, // TODO: track parent
        otp,
        history,
    })
}

/// Parse historical entry versions from a <History>...</History> block
fn parse_history_entries(history_xml: &str) -> Vec<HistoryEntry> {
    let mut history = Vec::new();

    // Find all Entry elements within the History block
    for entry_xml in find_elements(history_xml, "Entry") {
        if let Some(hist_entry) = parse_history_entry(&entry_xml) {
            history.push(hist_entry);
        }
    }

    history
}

/// Parse a single history entry
fn parse_history_entry(xml: &str) -> Option<HistoryEntry> {
    let title = extract_string_value(xml, "Title").unwrap_or_default();
    let username = extract_string_value(xml, "UserName").unwrap_or_default();
    let password = extract_string_value(xml, "Password");
    let url = extract_string_value(xml, "URL").unwrap_or_default();
    let notes = extract_string_value(xml, "Notes").unwrap_or_default();
    let last_modification_time = extract_tag_value(xml, "LastModificationTime");

    Some(HistoryEntry {
        title,
        username,
        password,
        url,
        notes,
        last_modification_time,
    })
}

fn parse_group_element(xml: &str) -> Option<SimpleGroup> {
    let uuid = extract_tag_value(xml, "UUID")?;
    let name = extract_tag_value(xml, "Name").unwrap_or_default();
    let icon_id = extract_tag_value(xml, "IconID")
        .and_then(|s| s.parse().ok());

    Some(SimpleGroup {
        uuid,
        name,
        parent: None, // TODO: track parent
        icon_id,
    })
}

fn extract_tag_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);

    let start = xml.find(&open)? + open.len();
    let end_offset = xml[start..].find(&close)?;
    let value = &xml[start..start + end_offset];

    Some(value.trim().to_string())
}

fn extract_string_value(xml: &str, key: &str) -> Option<String> {
    // KeePass stores strings as <String><Key>name</Key><Value>value</Value></String>
    // or <String><Key>name</Key><Value Protected="True">base64</Value></String>
    let pattern = format!("<Key>{}</Key>", key);
    let key_pos = xml.find(&pattern)?;

    // Look for </String> after the key to bound our search
    let after_key = &xml[key_pos + pattern.len()..];
    let string_end = after_key.find("</String>").unwrap_or(after_key.len());
    let search_area = &after_key[..string_end];

    // Find <Value or <Value Protected="True"> in the bounded area
    let value_tag_start = search_area.find("<Value")?;
    let value_tag_area = &search_area[value_tag_start..];

    // Find the closing > of the Value tag (handles both <Value> and <Value Protected="True">)
    let value_tag_end = value_tag_area.find('>')?;
    let content_start = value_tag_end + 1;

    // Find </Value>
    let content_end = value_tag_area.find("</Value>")?;

    // Extract the content between > and </Value>
    let value = &value_tag_area[content_start..content_end];

    // Debug: log when we're looking for otp-related keys
    #[cfg(target_arch = "wasm32")]
    if key.to_lowercase().contains("otp") || key.to_lowercase().contains("totp") {
        let tag_preview = if value_tag_area.len() > 100 {
            format!("{}...", &value_tag_area[..100])
        } else {
            value_tag_area.to_string()
        };
        web_sys::console::log_1(&format!(
            "[extract_string_value] key='{}', value_empty={}, tag_area='{}'",
            key, value.is_empty(), tag_preview
        ).into());
    }

    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_create_database() {
        let db = WasmDatabase::create("Test", "password");
        let metadata = db.get_metadata();
        assert!(metadata.contains("Test"));
    }

    #[wasm_bindgen_test]
    fn test_add_entry() {
        let mut db = WasmDatabase::create("Test", "password");
        let entry_json =
            r#"{"title": "GitHub", "username": "user@example.com", "password": "secret"}"#;
        let result = db.add_entry(entry_json);
        assert!(result.is_ok());
    }
}
