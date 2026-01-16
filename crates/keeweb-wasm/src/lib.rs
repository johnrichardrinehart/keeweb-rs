//! WASM bindings for keeweb-rs
//!
//! This crate provides JavaScript bindings for the kdbx-core and kdbx-diff crates,
//! allowing them to be used in web browsers via WebAssembly.

use kdbx_core::{Database, Entry, EntryBuilder, Group};
use kdbx_diff::{DatabaseDiff, Merger, Resolution};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

/// Initialize panic hook for better error messages.
/// Call this function once at startup from your application.
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
