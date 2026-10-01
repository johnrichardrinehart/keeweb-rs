//! The slow-path key derivation must reproduce the transformed key of files written by
//! other KeePass implementations, for every Argon2 parameter the header can carry.

use keepass::config::{DatabaseConfig, KdfConfig};
use keepass::db::{Entry, Value};
use keepass::{Database, DatabaseKey};
use keeweb_wasm::{WasmDocument, composite_key, derive_transformed_key};

const PASSWORD: &str = "correct horse battery staple";

fn written_by_keepass(argon2id: bool) -> Vec<u8> {
    let mut config = DatabaseConfig::default();
    config.kdf_config = match config.kdf_config {
        KdfConfig::Argon2 { version, .. } | KdfConfig::Argon2id { version, .. } => {
            let (iterations, memory, parallelism) = (3, 64 * 1024, 2);
            if argon2id {
                KdfConfig::Argon2id {
                    iterations,
                    memory,
                    parallelism,
                    version,
                }
            } else {
                KdfConfig::Argon2 {
                    iterations,
                    memory,
                    parallelism,
                    version,
                }
            }
        }
        other => other,
    };
    let mut db = Database::new(config);
    let mut entry = Entry::new();
    entry
        .fields
        .insert("Title".to_string(), Value::Unprotected("Mail".to_string()));
    db.root.add_child(entry);
    let mut written = Vec::new();
    db.save(&mut written, DatabaseKey::new().with_password(PASSWORD))
        .unwrap();
    written
}

fn unlock(data: &[u8], password: &str) -> Result<WasmDocument, String> {
    let params = WasmDocument::kdf_params(data)?;
    let composite = composite_key(password);
    let transformed = derive_transformed_key(params.params(), &composite)?;
    WasmDocument::open(data, &composite, &transformed)
}

#[test]
fn derived_key_opens_argon2d_and_argon2id_files() {
    for argon2id in [false, true] {
        let data = written_by_keepass(argon2id);
        let expected = if argon2id { "argon2id" } else { "argon2d" };
        assert_eq!(
            WasmDocument::kdf_params(&data).unwrap().kdf_type(),
            expected
        );

        let document = unlock(&data, PASSWORD).unwrap();
        let titles: Vec<String> = document
            .document()
            .entries()
            .iter()
            .map(|entry| entry.title().to_string())
            .collect();
        assert_eq!(titles, ["Mail"]);
        assert!(unlock(&data, "wrong password").is_err());
    }
}
