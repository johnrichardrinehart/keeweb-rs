use super::container::{CIPHER_AES256, CIPHER_CHACHA20, OuterCipher};
use super::edit::set_times;
use super::values::{format_time, format_uuid};
use super::*;
use crate::kdbx4_decrypt::{KdfType, compute_composite_key};
use chrono::{DateTime, TimeZone, Utc};

const PASSWORD: &str = "correct horse battery staple";
const SALT: [u8; 32] = [7; 32];
const ARGON2D: [u8; 16] = [
    0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
];

const ROOT: Uuid = Uuid::from_u128(0x1000);
const WORK: Uuid = Uuid::from_u128(0x2000);
const GITHUB: Uuid = Uuid::from_u128(0x3000);
const JIRA: Uuid = Uuid::from_u128(0x4000);
const ICON: Uuid = Uuid::from_u128(0x5000);
const DELETED: Uuid = Uuid::from_u128(0x6000);
const PNG: &[u8] = b"\x89PNG\r\n\x1a\nfixture";

const FIXTURE: &str = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
	<Meta>
		<Generator>KeePassXC</Generator>
		<DatabaseName>Fixture</DatabaseName>
		<DatabaseNameChanged>@OLD@</DatabaseNameChanged>
		<DatabaseDescription>Tom &amp; Jerry</DatabaseDescription>
		<DatabaseDescriptionChanged>@OLD@</DatabaseDescriptionChanged>
		<XFutureMeta mode="keep">opaque</XFutureMeta>
		<CustomIcons>
			<Icon>
				<UUID>@ICON@</UUID>
				<Data>@PNG@</Data>
			</Icon>
		</CustomIcons>
		<RecycleBinEnabled>True</RecycleBinEnabled>
		<RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID>
		<RecycleBinChanged>@OLD@</RecycleBinChanged>
		<HistoryMaxItems>10</HistoryMaxItems>
		<HistoryMaxSize>6291456</HistoryMaxSize>
		<CustomData>
			<Item><Key>plugin</Key><Value>data</Value></Item>
		</CustomData>
	</Meta>
	<Root>
		<Group>
			<UUID>@ROOT@</UUID>
			<Name>Root</Name>
			<Notes/>
			<IconID>48</IconID>
			@TIMES@
			<IsExpanded>True</IsExpanded>
			<DefaultAutoTypeSequence/>
			<EnableAutoType>null</EnableAutoType>
			<EnableSearching>null</EnableSearching>
			<LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>
			<Entry>
				<UUID>@GITHUB@</UUID>
				<IconID>1</IconID>
				<CustomIconUUID>@ICON@</CustomIconUUID>
				<ForegroundColor/>
				<BackgroundColor>#FF0000</BackgroundColor>
				<OverrideURL/>
				<Tags>dev;work</Tags>
				@TIMES@
				<String><Key>Title</Key><Value>GitHub</Value></String>
				<String><Key>UserName</Key><Value>octocat</Value></String>
				<String><Key>Password</Key><Value Protected="True" XExtra="1">s3cr&lt;et</Value></String>
				<String><Key>URL</Key><Value>https://github.com</Value></String>
				<String><Key>Notes</Key><Value>line1&#13;
line2  </Value></String>
				<String><Key>otp</Key><Value Protected="True">otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP</Value></String>
				<Binary><Key>id_rsa</Key><Value Ref="1"/></Binary>
				<AutoType>
					<Enabled>True</Enabled>
					<DataTransferObfuscation>0</DataTransferObfuscation>
					<Association><Window>Firefox*</Window><KeystrokeSequence>{USERNAME}{TAB}{PASSWORD}{ENTER}</KeystrokeSequence></Association>
				</AutoType>
				<XFutureEntry flavor="new"><Nested>1</Nested></XFutureEntry>
				<History>
					<Entry>
						<UUID>@GITHUB@</UUID>
						<IconID>1</IconID>
						<ForegroundColor/>
						<BackgroundColor/>
						<OverrideURL/>
						<Tags/>
						@OLD_TIMES@
						<String><Key>Title</Key><Value>GitHub</Value></String>
						<String><Key>Password</Key><Value Protected="True">old-pass</Value></String>
						<Binary><Key>id_rsa</Key><Value Ref="0"/></Binary>
						<AutoType><Enabled>True</Enabled><DataTransferObfuscation>0</DataTransferObfuscation></AutoType>
					</Entry>
				</History>
			</Entry>
			<Group>
				<UUID>@WORK@</UUID>
				<Name>Work</Name>
				<Notes>office</Notes>
				<IconID>48</IconID>
				@TIMES@
				<IsExpanded>True</IsExpanded>
				<Entry>
					<UUID>@JIRA@</UUID>
					<IconID>0</IconID>
					<ForegroundColor/>
					<BackgroundColor/>
					<OverrideURL/>
					<Tags/>
					@TIMES@
					<String><Key>Title</Key><Value>Jira</Value></String>
					<String><Key>UserName</Key><Value>me</Value></String>
					<String><Key>Password</Key><Value Protected="True"/></String>
					<AutoType><Enabled>False</Enabled><DataTransferObfuscation>0</DataTransferObfuscation></AutoType>
					<History/>
				</Entry>
			</Group>
		</Group>
		<DeletedObjects>
			<DeletedObject><UUID>@DELETED@</UUID><DeletionTime>@OLD@</DeletionTime></DeletedObject>
		</DeletedObjects>
		<XFutureRoot/>
	</Root>
</KeePassFile>
"#;

fn at(year: i32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, 1, 1, 0, 0, 0).unwrap()
}

fn times_xml(modified: DateTime<Utc>) -> String {
    let old = format_time(at(2020));
    let modified = format_time(modified);
    format!(
        "<Times><CreationTime>{old}</CreationTime><LastModificationTime>{modified}</LastModificationTime>\
         <LastAccessTime>{modified}</LastAccessTime><ExpiryTime>{old}</ExpiryTime><Expires>False</Expires>\
         <UsageCount>3</UsageCount><LocationChanged>{old}</LocationChanged></Times>"
    )
}

fn variant_dictionary(items: &[(u8, &str, &[u8])]) -> Vec<u8> {
    let mut out = vec![0x00, 0x01];
    for (kind, key, value) in items {
        out.push(*kind);
        out.extend_from_slice(&(key.len() as u32).to_le_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
    }
    out.push(0);
    out
}

fn fixture_header(minor: u16, cipher: OuterCipher, compressed: bool) -> OuterHeader {
    let (cipher_id, iv_len) = match cipher {
        OuterCipher::Aes256Cbc => (CIPHER_AES256, 16),
        OuterCipher::ChaCha20 => (CIPHER_CHACHA20, 12),
    };
    let kdf = variant_dictionary(&[
        (0x42, "$UUID", &ARGON2D),
        (0x42, "S", &SALT),
        (0x05, "I", &2u64.to_le_bytes()),
        (0x05, "M", &(64u64 * 1024).to_le_bytes()),
        (0x04, "P", &1u32.to_le_bytes()),
        (0x04, "V", &0x13u32.to_le_bytes()),
    ]);
    let custom = variant_dictionary(&[(0x18, "KPXC_TEST", b"kept")]);
    OuterHeader {
        minor,
        fields: vec![
            (2, cipher_id.to_vec()),
            (3, u32::from(compressed).to_le_bytes().to_vec()),
            (4, vec![0; 32]),
            (7, vec![0; iv_len]),
            (11, kdf),
            (12, custom),
        ],
        end: b"\r\n\r\n".to_vec(),
        cipher,
        compressed,
    }
}

/// Builds the fixture document directly; protected values in the XML are plaintext.
fn fixture(minor: u16, cipher: OuterCipher, compressed: bool) -> KdbxDocument {
    let text = FIXTURE
        .replace("@OLD_TIMES@", &times_xml(at(2020)))
        .replace("@TIMES@", &times_xml(at(2021)))
        .replace("@OLD@", &format_time(at(2020)))
        .replace("@ROOT@", &format_uuid(ROOT))
        .replace("@WORK@", &format_uuid(WORK))
        .replace("@GITHUB@", &format_uuid(GITHUB))
        .replace("@JIRA@", &format_uuid(JIRA))
        .replace("@ICON@", &format_uuid(ICON))
        .replace("@DELETED@", &format_uuid(DELETED))
        .replace("@PNG@", &STANDARD.encode(PNG));
    KdbxDocument {
        header: fixture_header(minor, cipher, compressed),
        binaries: vec![
            Binary {
                flags: 1,
                data: b"old-key".to_vec(),
            },
            Binary {
                flags: 0,
                data: b"new-key".to_vec(),
            },
            Binary {
                flags: 0,
                data: b"orphan".to_vec(),
            },
        ],
        xml: xml::parse(text.as_bytes(), |plain| Ok(plain.to_string())).unwrap(),
    }
}

/// Composite and transformed key for `data`, derived like an unlocking client would.
fn keys_for(data: &[u8]) -> ([u8; 32], [u8; 32]) {
    let params = KdbxDocument::kdf_request(data).unwrap();
    let composite = compute_composite_key(PASSWORD);
    let algorithm = match params.kdf_type {
        KdfType::Argon2d => argon2::Algorithm::Argon2d,
        KdfType::Argon2id => argon2::Algorithm::Argon2id,
    };
    let argon_params = argon2::Params::new(
        params.memory_kb as u32,
        params.iterations as u32,
        params.parallelism,
        Some(32),
    )
    .unwrap();
    let mut transformed = [0u8; 32];
    argon2::Argon2::new(algorithm, argon2::Version::V0x13, argon_params)
        .hash_password_into(&composite, &params.salt, &mut transformed)
        .unwrap();
    (composite, transformed)
}

fn fixture_keys() -> ([u8; 32], [u8; 32]) {
    let composite = compute_composite_key(PASSWORD);
    let params = argon2::Params::new(64, 2, 1, Some(32)).unwrap();
    let mut transformed = [0u8; 32];
    argon2::Argon2::new(argon2::Algorithm::Argon2d, argon2::Version::V0x13, params)
        .hash_password_into(&composite, &SALT, &mut transformed)
        .unwrap();
    (composite, transformed)
}

fn save(document: &KdbxDocument) -> Vec<u8> {
    let (composite, transformed) = fixture_keys();
    document.save(&composite, &transformed).unwrap()
}

fn reopen(document: &KdbxDocument) -> KdbxDocument {
    let (composite, transformed) = fixture_keys();
    KdbxDocument::open(&save(document), &composite, &transformed).unwrap()
}

fn opened_fixture() -> KdbxDocument {
    reopen(&fixture(1, OuterCipher::Aes256Cbc, true))
}

fn entry(document: &KdbxDocument, uuid: Uuid) -> EntryView {
    document
        .entries()
        .into_iter()
        .find(|e| e.uuid == uuid)
        .unwrap()
}

fn find_entry(document: &KdbxDocument, uuid: Uuid) -> Option<EntryView> {
    document.entries().into_iter().find(|e| e.uuid == uuid)
}

fn group(document: &KdbxDocument, uuid: Uuid) -> GroupView {
    document
        .groups()
        .into_iter()
        .find(|g| g.uuid == uuid)
        .unwrap()
}

fn set_field(edit: &mut EntryEdit, key: &str, value: &str) {
    match edit.strings.iter_mut().find(|f| f.key == key) {
        Some(field) => field.value = value.to_string(),
        None => edit.strings.push(StringField {
            key: key.to_string(),
            value: value.to_string(),
            protected: false,
        }),
    }
}

fn update(
    document: &mut KdbxDocument,
    uuid: Uuid,
    change: impl FnOnce(&mut EntryEdit),
) -> ChangeOutcome {
    let mut edit = entry(document, uuid).to_edit();
    change(&mut edit);
    document
        .apply(Change::UpdateEntry { uuid, entry: edit })
        .unwrap()
}

fn deleted_uuids(document: &KdbxDocument) -> Vec<Uuid> {
    document
        .xml
        .child("Root")
        .and_then(|r| r.child("DeletedObjects"))
        .map(|d| {
            d.children_named("DeletedObject")
                .filter_map(uuid_of)
                .collect()
        })
        .unwrap_or_default()
}

fn set_time(document: &mut KdbxDocument, uuid: Uuid, name: &str, time: DateTime<Utc>) {
    let path = document
        .find(uuid, Kind::Entry)
        .or_else(|| document.find(uuid, Kind::Group))
        .unwrap();
    set_times(element_at_mut(&mut document.xml, &path), &[name], time);
}

fn find_element<'a>(element: &'a Element, name: &str) -> Option<&'a Element> {
    if element.name == name {
        return Some(element);
    }
    element.children.iter().find_map(|c| find_element(c, name))
}

#[test]
fn round_trip_preserves_document() {
    for (minor, cipher, compressed) in [
        (1, OuterCipher::Aes256Cbc, true),
        (0, OuterCipher::ChaCha20, false),
    ] {
        let original = fixture(minor, cipher, compressed);
        let bytes = save(&original);
        assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), minor);
        assert_ne!(bytes, save(&original), "master seed and IV must be fresh");

        let (composite, transformed) = fixture_keys();
        let opened = KdbxDocument::open(&bytes, &composite, &transformed).unwrap();
        assert_eq!(opened.entries(), original.entries());
        assert_eq!(opened.groups(), original.groups());
        assert_eq!(opened.meta(), original.meta());
        assert_eq!(opened.custom_icons(), original.custom_icons());

        // The whole tree, unknown elements and attributes included, is unchanged apart
        // from attachment references, which are renumbered in document order.
        let mut expected = original.xml.clone();
        import_binaries(
            &mut expected,
            &original.binaries,
            &mut BinaryPool::default(),
        )
        .unwrap();
        assert_eq!(opened.xml, expected);
        assert_eq!(
            opened.binaries,
            vec![
                Binary {
                    flags: 0,
                    data: b"new-key".to_vec()
                },
                Binary {
                    flags: 1,
                    data: b"old-key".to_vec()
                },
            ]
        );

        let github = entry(&opened, GITHUB);
        assert_eq!(github.field("Password"), Some("s3cr<et"));
        assert_eq!(github.field("Notes"), Some("line1\r\nline2  "));
        assert!(
            github
                .strings
                .iter()
                .find(|s| s.key == "otp")
                .unwrap()
                .protected
        );
        assert_eq!(github.history.len(), 1);
        assert_eq!(github.history[0].field("Password"), Some("old-pass"));
        assert_eq!(opened.attachment(GITHUB, "id_rsa").unwrap(), b"new-key");
        assert_eq!(
            opened.history_attachment(GITHUB, 0, "id_rsa").unwrap(),
            b"old-key"
        );
        assert_eq!(entry(&opened, JIRA).field("Password"), Some(""));
        assert_eq!(opened.custom_icons()[0].png, PNG);
        assert_eq!(deleted_uuids(&opened), vec![DELETED]);

        for (id, value) in &original.header.fields {
            let reopened = opened.header.fields.iter().find(|(i, _)| i == id).unwrap();
            if *id == 4 || *id == 7 {
                assert_ne!(&reopened.1, value);
            } else {
                assert_eq!(&reopened.1, value);
            }
        }
        assert_eq!(opened.header.fields.len(), original.header.fields.len());

        let again = reopen(&opened);
        assert_eq!(again.xml, opened.xml);
        assert_eq!(again.binaries, opened.binaries);
    }
}

#[test]
fn open_rejects_wrong_key_and_kdbx3() {
    let bytes = save(&fixture(1, OuterCipher::Aes256Cbc, true));
    let (composite, _) = fixture_keys();
    assert!(matches!(
        KdbxDocument::open(&bytes, &composite, &[0u8; 32]),
        Err(Error::InvalidCredentials)
    ));

    let mut kdbx3 = bytes.clone();
    kdbx3[8..12].copy_from_slice(&[1, 0, 3, 0]);
    assert!(matches!(
        KdbxDocument::open(&kdbx3, &composite, &[0u8; 32]),
        Err(Error::UnsupportedFormat(_))
    ));
}

fn keepass_entry<'a>(db: &'a keepass::Database, title: &str) -> &'a keepass::db::Entry {
    db.root
        .iter()
        .find_map(|node| match node {
            keepass::db::NodeRef::Entry(e) if e.get_title() == Some(title) => Some(e),
            _ => None,
        })
        .unwrap()
}

#[test]
fn interoperates_with_keepass_crate() {
    use keepass::config::{DatabaseConfig, KdfConfig};
    use keepass::db::{Entry, Group, History, Icon, Value};
    use keepass::{Database, DatabaseKey};
    use secstr::SecStr;

    // A file written by an independent KDBX 4 implementation opens and saves.
    let mut config = DatabaseConfig::default();
    if let KdfConfig::Argon2 {
        iterations,
        memory,
        parallelism,
        ..
    } = &mut config.kdf_config
    {
        *iterations = 2;
        *memory = 64 * 1024;
        *parallelism = 1;
    }
    let mut db = Database::new(config);
    db.meta.database_name = Some("From keepass".to_string());
    db.meta.custom_icons.icons.push(Icon {
        uuid: ICON,
        data: PNG.to_vec(),
    });
    let mut mail = Entry::new();
    mail.fields
        .insert("Title".to_string(), Value::Unprotected("Mail".to_string()));
    mail.fields.insert(
        "Password".to_string(),
        Value::Protected(SecStr::new(b"pw0".to_vec())),
    );
    let old = mail.clone();
    mail.fields.insert(
        "Password".to_string(),
        Value::Protected(SecStr::new(b"pw1".to_vec())),
    );
    let mut history = History::default();
    history.add_entry(old);
    mail.history = Some(history);
    let mut email = Group::new("Email");
    email.add_child(mail);
    db.root.add_child(email);
    let mut written = Vec::new();
    db.save(&mut written, DatabaseKey::new().with_password(PASSWORD))
        .unwrap();

    let (composite, transformed) = keys_for(&written);
    let document = KdbxDocument::open(&written, &composite, &transformed).unwrap();
    let view = document
        .entries()
        .into_iter()
        .find(|e| e.title() == "Mail")
        .unwrap();
    assert_eq!(view.field("Password"), Some("pw1"));
    assert_eq!(view.history.len(), 1);
    assert_eq!(view.history[0].field("Password"), Some("pw0"));
    assert_eq!(document.meta().name, "From keepass");
    assert_eq!(document.custom_icons()[0].png, PNG);

    let resaved = document.save(&composite, &transformed).unwrap();
    let reread = Database::parse(&resaved, DatabaseKey::new().with_password(PASSWORD)).unwrap();
    let mail = keepass_entry(&reread, "Mail");
    assert_eq!(mail.get_password(), Some("pw1"));
    assert_eq!(mail.history.as_ref().unwrap().get_entries().len(), 1);

    // Our own fixture, saved by us, reads back in the independent implementation. The
    // keepass crate rejects unknown children of Root, so that one is dropped here.
    let mut ours = fixture(1, OuterCipher::ChaCha20, true);
    ours.xml
        .child_mut("Root")
        .unwrap()
        .remove_children("XFutureRoot");
    let fixture_bytes = save(&ours);
    let reread =
        Database::parse(&fixture_bytes, DatabaseKey::new().with_password(PASSWORD)).unwrap();
    let github = keepass_entry(&reread, "GitHub");
    assert_eq!(github.get_password(), Some("s3cr<et"));
    assert_eq!(
        github.get("otp"),
        Some("otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP")
    );
    let history = github.history.as_ref().unwrap().get_entries();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].get_password(), Some("old-pass"));
    // The keepass crate reports empty values as missing.
    assert_eq!(
        keepass_entry(&reread, "Jira")
            .get_password()
            .unwrap_or_default(),
        ""
    );
    assert_eq!(reread.meta.custom_icons.icons.len(), 1);
    assert_eq!(reread.header_attachments.len(), 2);
}

#[test]
fn update_entry_records_history() {
    let mut document = opened_fixture();
    let before = entry(&document, GITHUB);
    let outcome = update(&mut document, GITHUB, |edit| {
        set_field(edit, "Password", "n3w-secret");
        set_field(edit, "UserName", "hubot");
    });
    assert_eq!(outcome.summary, "Edited entry “GitHub”: Password, UserName");
    assert!(outcome.changed);

    let after = entry(&document, GITHUB);
    assert_eq!(after.field("Password"), Some("n3w-secret"));
    assert!(
        after
            .strings
            .iter()
            .find(|s| s.key == "Password")
            .unwrap()
            .protected
    );
    assert_eq!(after.history.len(), 2);
    assert_eq!(after.history[1].field("Password"), Some("s3cr<et"));
    assert!(after.times.last_modification > before.times.last_modification);
    let password_value = find_element(&document.xml, "Entry")
        .unwrap()
        .children_named("String")
        .find(|s| s.child_text("Key") == Some("Password"))
        .unwrap()
        .child("Value")
        .unwrap();
    assert_eq!(password_value.attr("XExtra"), Some("1"));

    let outcome = update(&mut document, GITHUB, |_| {});
    assert!(!outcome.changed);
    assert_eq!(entry(&document, GITHUB).history.len(), 2);

    let outcome = update(&mut document, GITHUB, |edit| {
        edit.tags = vec!["personal".to_string()];
        edit.expires = true;
        edit.expiry_time = Some(at(2030));
        edit.auto_type.associations.clear();
        edit.strings.retain(|s| s.key != "otp");
    });
    assert_eq!(
        outcome.summary,
        "Edited entry “GitHub”: otp, Tags, Expiry, Auto-Type"
    );
    let reopened = reopen(&document);
    assert_eq!(reopened.entries(), document.entries());
    let github = entry(&reopened, GITHUB);
    assert_eq!(github.tags, vec!["personal"]);
    assert!(github.expires);
    assert_eq!(github.expiry_time, Some(at(2030)));
    assert!(github.field("otp").is_none());
}

#[test]
fn update_entry_ignores_empty_fields_it_never_stored() {
    let mut document = opened_fixture();
    let outcome = update(&mut document, GITHUB, |edit| {
        set_field(edit, "Password", "changed");
        set_field(edit, "NeverStored", "");
    });
    assert_eq!(outcome.summary, "Edited entry “GitHub”: Password");
    assert!(entry(&document, GITHUB).field("NeverStored").is_none());

    let outcome = update(&mut document, GITHUB, |edit| {
        set_field(edit, "NeverStored", "")
    });
    assert!(!outcome.changed);
}

#[test]
fn history_limits_trim_oldest_versions() {
    let mut document = opened_fixture();
    let mut meta = document.meta().to_edit();
    meta.history_max_items = 2;
    document.apply(Change::UpdateMeta { meta }).unwrap();
    for password in ["pw0", "pw1", "pw2"] {
        update(&mut document, GITHUB, |edit| {
            set_field(edit, "Password", password)
        });
    }
    let history: Vec<_> = entry(&document, GITHUB)
        .history
        .iter()
        .map(|h| h.field("Password").unwrap().to_string())
        .collect();
    assert_eq!(history, ["pw0", "pw1"]);

    let mut meta = document.meta().to_edit();
    meta.history_max_size = 0;
    let outcome = document.apply(Change::UpdateMeta { meta }).unwrap();
    assert_eq!(outcome.summary, "Changed database settings: History limits");
    assert!(entry(&document, GITHUB).history.is_empty());
    assert_eq!(document.meta().history_max_size, 0);
}

#[test]
fn attachments_can_be_added_renamed_and_removed() {
    let mut document = opened_fixture();
    let outcome = update(&mut document, GITHUB, |edit| {
        edit.attachments = vec![
            AttachmentEdit {
                name: "id_ed25519".to_string(),
                data: AttachmentData::Existing("id_rsa".to_string()),
            },
            AttachmentEdit {
                name: "notes.txt".to_string(),
                data: AttachmentData::New(b"hello".to_vec()),
            },
        ];
    });
    assert_eq!(outcome.summary, "Edited entry “GitHub”: Attachments");
    let reopened = reopen(&document);
    assert_eq!(
        reopened.attachment(GITHUB, "id_ed25519").unwrap(),
        b"new-key"
    );
    assert_eq!(reopened.attachment(GITHUB, "notes.txt").unwrap(), b"hello");
    assert!(reopened.attachment(GITHUB, "id_rsa").is_none());
    assert_eq!(
        reopened.history_attachment(GITHUB, 0, "id_rsa").unwrap(),
        b"old-key"
    );
    assert_eq!(
        reopened.history_attachment(GITHUB, 1, "id_rsa").unwrap(),
        b"new-key"
    );

    let mut document = reopened;
    update(&mut document, GITHUB, |edit| edit.attachments.clear());
    let reopened = reopen(&document);
    assert!(entry(&reopened, GITHUB).attachments.is_empty());
    // "hello" is only referenced by history now; everything else still is.
    assert_eq!(reopened.binaries.len(), 3);

    let mut edit = entry(&document, GITHUB).to_edit();
    edit.attachments.push(AttachmentEdit {
        name: "ghost".to_string(),
        data: AttachmentData::Existing("missing".to_string()),
    });
    let snapshot = document.xml.clone();
    assert!(
        document
            .apply(Change::UpdateEntry {
                uuid: GITHUB,
                entry: edit
            })
            .is_err()
    );
    assert_eq!(document.xml, snapshot);
}

#[test]
fn create_duplicate_and_move_entries() {
    let mut document = opened_fixture();
    let mut edit = EntryEdit::default();
    set_field(&mut edit, "Title", "Mail");
    edit.strings.push(StringField {
        key: "Password".to_string(),
        value: "hunter2".to_string(),
        protected: true,
    });
    let outcome = document
        .apply(Change::CreateEntry {
            group: WORK,
            entry: edit,
        })
        .unwrap();
    assert_eq!(outcome.summary, "Created entry “Mail” in “Work”");
    let mail = entry(&document, outcome.created.unwrap());
    assert_eq!(mail.group, WORK);
    assert_eq!(mail.field("Password"), Some("hunter2"));
    assert!(mail.times.creation.is_some());

    let outcome = document
        .apply(Change::DuplicateEntry { uuid: GITHUB })
        .unwrap();
    assert_eq!(outcome.summary, "Duplicated entry “GitHub”");
    let copy_uuid = outcome.created.unwrap();
    let order: Vec<Uuid> = document.entries().iter().map(|e| e.uuid).collect();
    assert_eq!(&order[..2], &[GITHUB, copy_uuid]);
    let copy = entry(&document, copy_uuid);
    assert_eq!(copy.title(), "GitHub - Copy");
    assert!(copy.history.is_empty());
    assert_eq!(
        document.attachment(copy_uuid, "id_rsa").unwrap(),
        b"new-key"
    );

    let outcome = document
        .apply(Change::MoveEntry {
            uuid: copy_uuid,
            group: WORK,
        })
        .unwrap();
    assert_eq!(outcome.summary, "Moved entry “GitHub - Copy” to “Work”");
    let moved = entry(&document, copy_uuid);
    assert_eq!(moved.group, WORK);
    let path = document.entry_path(copy_uuid).unwrap();
    assert_eq!(
        element_at(&document.xml, &path).child_text("PreviousParentGroup"),
        Some(format_uuid(ROOT).as_str())
    );
    let again = document
        .apply(Change::MoveEntry {
            uuid: copy_uuid,
            group: WORK,
        })
        .unwrap();
    assert!(!again.changed);

    let reopened = reopen(&document);
    assert_eq!(reopened.entries(), document.entries());
}

#[test]
fn delete_entry_uses_recycle_bin_then_deletes_permanently() {
    let mut document = opened_fixture();
    let outcome = document.apply(Change::DeleteEntry { uuid: JIRA }).unwrap();
    assert_eq!(outcome.summary, "Moved entry “Jira” to the recycle bin");
    let bin = document.meta().recycle_bin_uuid.unwrap();
    let bin_group = group(&document, bin);
    assert!(bin_group.is_recycle_bin);
    assert_eq!(bin_group.name, "Recycle Bin");
    assert_eq!(bin_group.parent, Some(ROOT));
    let jira = entry(&document, JIRA);
    assert_eq!(jira.group, bin);
    assert!(jira.in_recycle_bin);

    let outcome = document.apply(Change::DeleteEntry { uuid: JIRA }).unwrap();
    assert_eq!(outcome.summary, "Permanently deleted entry “Jira”");
    assert!(find_entry(&document, JIRA).is_none());
    assert!(deleted_uuids(&document).contains(&JIRA));

    let mut meta = document.meta().to_edit();
    meta.recycle_bin_enabled = false;
    document.apply(Change::UpdateMeta { meta }).unwrap();
    let outcome = document
        .apply(Change::DeleteEntry { uuid: GITHUB })
        .unwrap();
    assert_eq!(outcome.summary, "Permanently deleted entry “GitHub”");
    assert!(deleted_uuids(&document).contains(&GITHUB));
}

#[test]
fn restore_and_delete_history_versions() {
    let mut document = opened_fixture();
    let outcome = document
        .apply(Change::RestoreHistory {
            uuid: GITHUB,
            index: 0,
        })
        .unwrap();
    assert_eq!(outcome.summary, "Restored entry “GitHub” from history");
    let github = entry(&document, GITHUB);
    assert_eq!(github.field("Password"), Some("old-pass"));
    assert_eq!(github.group, ROOT);
    assert_eq!(github.history.len(), 2);
    assert_eq!(github.history[1].field("Password"), Some("s3cr<et"));
    assert_eq!(document.attachment(GITHUB, "id_rsa").unwrap(), b"old-key");

    document
        .apply(Change::DeleteHistory {
            uuid: GITHUB,
            index: 0,
        })
        .unwrap();
    assert_eq!(entry(&document, GITHUB).history.len(), 1);
    assert!(
        document
            .apply(Change::DeleteHistory {
                uuid: GITHUB,
                index: 5
            })
            .is_err()
    );
}

#[test]
fn group_operations_and_empty_recycle_bin() {
    let mut document = opened_fixture();
    let outcome = document
        .apply(Change::CreateGroup {
            parent: ROOT,
            group: GroupEdit {
                name: "Personal".to_string(),
                ..GroupEdit::default()
            },
        })
        .unwrap();
    assert_eq!(outcome.summary, "Created group “Personal” in “Root”");
    let personal = outcome.created.unwrap();

    let mut edit = group(&document, personal).to_edit();
    edit.name = "Private".to_string();
    edit.notes = "family".to_string();
    let outcome = document
        .apply(Change::UpdateGroup {
            uuid: personal,
            group: edit,
        })
        .unwrap();
    assert_eq!(outcome.summary, "Edited group “Private”: Name, Notes");

    document
        .apply(Change::MoveGroup {
            uuid: WORK,
            parent: personal,
        })
        .unwrap();
    assert_eq!(group(&document, WORK).parent, Some(personal));
    assert!(
        document
            .apply(Change::MoveGroup {
                uuid: personal,
                parent: WORK
            })
            .is_err()
    );
    assert!(document.apply(Change::DeleteGroup { uuid: ROOT }).is_err());

    let outcome = document
        .apply(Change::DeleteGroup { uuid: personal })
        .unwrap();
    assert_eq!(outcome.summary, "Moved group “Private” to the recycle bin");
    assert!(entry(&document, JIRA).in_recycle_bin);
    assert!(group(&document, WORK).in_recycle_bin);

    let outcome = document.apply(Change::EmptyRecycleBin).unwrap();
    assert_eq!(
        outcome.summary,
        "Emptied the recycle bin (1 entries, 2 groups)"
    );
    assert!(find_entry(&document, JIRA).is_none());
    let deleted = deleted_uuids(&document);
    for uuid in [personal, WORK, JIRA] {
        assert!(deleted.contains(&uuid));
    }
    let bin = document.meta().recycle_bin_uuid.unwrap();
    assert!(document.groups().iter().any(|g| g.uuid == bin));
    assert!(!document.apply(Change::EmptyRecycleBin).unwrap().changed);
}

#[test]
fn custom_icons_and_meta() {
    let mut document = opened_fixture();
    let outcome = document
        .apply(Change::AddCustomIcon {
            png: b"another".to_vec(),
        })
        .unwrap();
    let icon = outcome.created.unwrap();
    assert_eq!(document.custom_icons().len(), 2);
    let again = document
        .apply(Change::AddCustomIcon {
            png: b"another".to_vec(),
        })
        .unwrap();
    assert_eq!(again.created, Some(icon));
    assert!(!again.changed);

    update(&mut document, JIRA, |edit| edit.custom_icon = Some(icon));
    assert_eq!(entry(&document, JIRA).custom_icon, Some(icon));
    let mut edit = entry(&document, JIRA).to_edit();
    edit.custom_icon = Some(Uuid::from_u128(42));
    assert!(
        document
            .apply(Change::UpdateEntry {
                uuid: JIRA,
                entry: edit
            })
            .is_err()
    );

    let mut meta = document.meta().to_edit();
    meta.name = "Renamed".to_string();
    meta.description = "Updated".to_string();
    let outcome = document.apply(Change::UpdateMeta { meta }).unwrap();
    assert_eq!(
        outcome.summary,
        "Changed database settings: Name, Description"
    );
    let reopened = reopen(&document);
    assert_eq!(reopened.meta().name, "Renamed");
    assert_eq!(reopened.custom_icons().len(), 2);
}

#[test]
fn summaries_contain_no_field_values() {
    let mut document = opened_fixture();
    let secret = "do-not-leak";
    let mut summaries = vec![
        update(&mut document, GITHUB, |edit| {
            set_field(edit, "Password", secret);
            set_field(edit, "Notes", secret);
            set_field(edit, "Recovery", secret);
        })
        .summary,
    ];
    let mut edit = EntryEdit::default();
    set_field(&mut edit, "Title", "New");
    set_field(&mut edit, "Password", secret);
    summaries.push(
        document
            .apply(Change::CreateEntry {
                group: ROOT,
                entry: edit,
            })
            .unwrap()
            .summary,
    );
    summaries.push(
        document
            .apply(Change::RestoreHistory {
                uuid: GITHUB,
                index: 1,
            })
            .unwrap()
            .summary,
    );
    for summary in summaries {
        assert!(!summary.contains(secret), "{summary}");
    }
}

/// Base, local and remote copies of the fixture.
fn merge_setup() -> (KdbxDocument, KdbxDocument, KdbxDocument) {
    let base = opened_fixture();
    (base.clone(), base.clone(), base)
}

fn merged(base: &KdbxDocument, local: &KdbxDocument, remote: &KdbxDocument) -> MergeOutcome {
    let outcome = merge(base, local, remote).unwrap();
    // The merged document must save and reopen with the local key.
    let reopened = reopen(&outcome.document);
    assert_eq!(reopened.entries(), outcome.document.entries());
    outcome
}

#[test]
fn merge_takes_one_sided_changes() {
    let (base, mut local, mut remote) = merge_setup();
    update(&mut local, GITHUB, |edit| {
        set_field(edit, "UserName", "local-user")
    });
    update(&mut remote, JIRA, |edit| {
        set_field(edit, "UserName", "remote-user")
    });
    let mut meta = remote.meta().to_edit();
    meta.name = "Remote name".to_string();
    remote.apply(Change::UpdateMeta { meta }).unwrap();
    // Only reading an entry is not a change.
    set_time(&mut remote, GITHUB, "LastAccessTime", at(2035));

    let outcome = merged(&base, &local, &remote);
    assert!(outcome.conflicts.is_empty());
    let document = outcome.document;
    assert_eq!(
        entry(&document, GITHUB).field("UserName"),
        Some("local-user")
    );
    assert_eq!(
        entry(&document, JIRA).field("UserName"),
        Some("remote-user")
    );
    assert_eq!(document.meta().name, "Remote name");
}

#[test]
fn merge_conflict_newer_wins_and_keeps_loser_in_history() {
    let (base, mut local, mut remote) = merge_setup();
    update(&mut local, GITHUB, |edit| {
        set_field(edit, "Password", "local-pw")
    });
    set_time(&mut local, GITHUB, "LastModificationTime", at(2030));
    update(&mut remote, GITHUB, |edit| {
        set_field(edit, "Password", "remote-pw")
    });
    set_time(&mut remote, GITHUB, "LastModificationTime", at(2031));

    let outcome = merged(&base, &local, &remote);
    assert_eq!(outcome.conflicts, vec!["GitHub"]);
    let github = entry(&outcome.document, GITHUB);
    assert_eq!(github.field("Password"), Some("remote-pw"));
    let versions: Vec<_> = github
        .history
        .iter()
        .map(|h| h.field("Password").unwrap())
        .collect();
    assert_eq!(versions, ["old-pass", "s3cr<et", "local-pw"]);
}

#[test]
fn merge_keeps_edit_over_delete() {
    let (base, mut local, mut remote) = merge_setup();
    local.apply(Change::DeleteEntry { uuid: JIRA }).unwrap();
    local.apply(Change::DeleteEntry { uuid: JIRA }).unwrap();
    update(&mut remote, JIRA, |edit| {
        set_field(edit, "UserName", "still-here")
    });

    let outcome = merged(&base, &local, &remote);
    let jira = entry(&outcome.document, JIRA);
    assert_eq!(jira.field("UserName"), Some("still-here"));
    assert_eq!(jira.group, WORK);
    assert!(!deleted_uuids(&outcome.document).contains(&JIRA));
}

#[test]
fn merge_deletes_unchanged() {
    let (base, mut local, mut remote) = merge_setup();
    local.apply(Change::DeleteEntry { uuid: JIRA }).unwrap();
    local.apply(Change::DeleteEntry { uuid: JIRA }).unwrap();
    set_time(&mut remote, JIRA, "LastAccessTime", at(2035));

    let outcome = merged(&base, &local, &remote);
    assert!(find_entry(&outcome.document, JIRA).is_none());
    assert!(deleted_uuids(&outcome.document).contains(&JIRA));

    // Symmetric: deleted remotely, untouched locally.
    let (base, local, mut remote) = merge_setup();
    remote.apply(Change::DeleteEntry { uuid: JIRA }).unwrap();
    remote.apply(Change::DeleteEntry { uuid: JIRA }).unwrap();
    let outcome = merged(&base, &local, &remote);
    assert!(find_entry(&outcome.document, JIRA).is_none());
    assert!(deleted_uuids(&outcome.document).contains(&JIRA));
}

#[test]
fn merge_resolves_moves_by_location_changed() {
    let mut base = opened_fixture();
    let mut create = |name: &str| {
        base.apply(Change::CreateGroup {
            parent: ROOT,
            group: GroupEdit {
                name: name.to_string(),
                ..GroupEdit::default()
            },
        })
        .unwrap()
        .created
        .unwrap()
    };
    let a = create("A");
    let b = create("B");
    let mut local = base.clone();
    let mut remote = base.clone();

    local
        .apply(Change::MoveEntry {
            uuid: GITHUB,
            group: a,
        })
        .unwrap();
    set_time(&mut local, GITHUB, "LocationChanged", at(2030));
    remote
        .apply(Change::MoveEntry {
            uuid: GITHUB,
            group: b,
        })
        .unwrap();
    set_time(&mut remote, GITHUB, "LocationChanged", at(2031));

    // A move on one side combines with a content edit on the other.
    local
        .apply(Change::MoveEntry {
            uuid: JIRA,
            group: a,
        })
        .unwrap();
    update(&mut remote, JIRA, |edit| {
        set_field(edit, "UserName", "moved-and-edited")
    });

    let outcome = merged(&base, &local, &remote);
    assert!(outcome.conflicts.is_empty());
    let document = outcome.document;
    assert_eq!(entry(&document, GITHUB).group, b);
    assert_eq!(
        entry(&document, GITHUB).times.location_changed,
        Some(at(2031))
    );
    let jira = entry(&document, JIRA);
    assert_eq!(jira.group, a);
    assert_eq!(jira.field("UserName"), Some("moved-and-edited"));
}

#[test]
fn merge_restores_deleted_group_with_kept_entries_and_unions_attachments() {
    let (base, mut local, mut remote) = merge_setup();
    remote.apply(Change::DeleteGroup { uuid: WORK }).unwrap();
    remote.apply(Change::DeleteGroup { uuid: WORK }).unwrap();
    let mut edit = EntryEdit::default();
    set_field(&mut edit, "Title", "Remote new");
    edit.attachments.push(AttachmentEdit {
        name: "remote.bin".to_string(),
        data: AttachmentData::New(b"remote-bytes".to_vec()),
    });
    let remote_new = remote
        .apply(Change::CreateEntry {
            group: ROOT,
            entry: edit,
        })
        .unwrap()
        .created
        .unwrap();

    update(&mut local, JIRA, |edit| {
        set_field(edit, "UserName", "edited")
    });
    update(&mut local, GITHUB, |edit| {
        edit.attachments.push(AttachmentEdit {
            name: "local.bin".to_string(),
            data: AttachmentData::New(b"local-bytes".to_vec()),
        });
    });

    let outcome = merged(&base, &local, &remote);
    let document = reopen(&outcome.document);
    assert_eq!(group(&document, WORK).parent, Some(ROOT));
    let jira = entry(&document, JIRA);
    assert_eq!(jira.group, WORK);
    assert_eq!(jira.field("UserName"), Some("edited"));
    assert_eq!(
        document.attachment(remote_new, "remote.bin").unwrap(),
        b"remote-bytes"
    );
    assert_eq!(
        document.attachment(GITHUB, "local.bin").unwrap(),
        b"local-bytes"
    );
    assert_eq!(document.attachment(GITHUB, "id_rsa").unwrap(), b"new-key");
    let deleted = deleted_uuids(&document);
    assert!(!deleted.contains(&WORK));
    assert!(!deleted.contains(&JIRA));
}

#[test]
fn merge_ignores_reserialization_by_other_clients() {
    use keepass::config::{DatabaseConfig, KdfConfig};
    use keepass::db::{Entry, Value};
    use keepass::{Database, DatabaseKey};
    use secstr::SecStr;

    let mut config = DatabaseConfig::default();
    if let KdfConfig::Argon2 {
        iterations,
        memory,
        parallelism,
        ..
    } = &mut config.kdf_config
    {
        *iterations = 2;
        *memory = 64 * 1024;
        *parallelism = 1;
    }
    let mut db = Database::new(config);
    for title in ["Mail", "Bank"] {
        let mut entry = Entry::new();
        entry
            .fields
            .insert("Title".to_string(), Value::Unprotected(title.to_string()));
        entry
            .fields
            .insert("UserName".to_string(), Value::Unprotected("me".to_string()));
        entry.fields.insert(
            "Password".to_string(),
            Value::Protected(SecStr::new(b"initial".to_vec())),
        );
        db.root.add_child(entry);
    }
    let mut written = Vec::new();
    db.save(&mut written, DatabaseKey::new().with_password(PASSWORD))
        .unwrap();
    let (composite, transformed) = keys_for(&written);
    let base = KdbxDocument::open(&written, &composite, &transformed).unwrap();
    let uuid_of_title = |document: &KdbxDocument, title: &str| {
        document
            .entries()
            .into_iter()
            .find(|e| e.title() == title)
            .unwrap()
            .uuid
    };
    let mail = uuid_of_title(&base, "Mail");
    let bank = uuid_of_title(&base, "Bank");

    let mut local = base.clone();
    update(&mut local, mail, |edit| {
        set_field(edit, "Password", "local")
    });

    // Remote edits another entry, then a different implementation re-saves the file:
    // child order, default and empty elements differ from what we wrote.
    let mut remote = base.clone();
    update(&mut remote, bank, |edit| {
        set_field(edit, "Password", "remote")
    });
    let ours = remote.save(&composite, &transformed).unwrap();
    let theirs = Database::parse(&ours, DatabaseKey::new().with_password(PASSWORD)).unwrap();
    let mut resaved = Vec::new();
    theirs
        .save(&mut resaved, DatabaseKey::new().with_password(PASSWORD))
        .unwrap();
    let (remote_composite, remote_transformed) = keys_for(&resaved);
    let remote = KdbxDocument::open(&resaved, &remote_composite, &remote_transformed).unwrap();

    let outcome = merge(&base, &local, &remote).unwrap();
    assert!(outcome.conflicts.is_empty(), "{:?}", outcome.conflicts);
    let mail = entry(&outcome.document, mail);
    assert_eq!(mail.field("Password"), Some("local"));
    assert_eq!(mail.history.len(), 1);
    let bank = entry(&outcome.document, bank);
    assert_eq!(bank.field("Password"), Some("remote"));
    assert_eq!(bank.history.len(), 1);
}
