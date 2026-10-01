//! Password and passphrase generation following KeePassXC's generator.
//!
//! Every random choice is an index drawn uniformly from the operating system CSPRNG
//! (`crypto.getRandomValues` in browsers) by rejection sampling, so no character or
//! word is favoured over another.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const MIN_PASSWORD_LENGTH: usize = 1;
pub const MAX_PASSWORD_LENGTH: usize = 128;
pub const MIN_WORD_COUNT: usize = 1;
pub const MAX_WORD_COUNT: usize = 40;

/// Characters dropped from the built-in classes by "Exclude look-alike characters".
/// KeePassXC lists "﹒" here; U+00B7 is the Latin-1 character that looks like it.
pub const LOOK_ALIKE_CHARACTERS: &str = "0O1lI|B8G6\u{b7}";

const SOFT_HYPHEN: char = '\u{ad}';

/// EFF large wordlist. See `wordlists/NOTICE` for attribution.
static WORDLIST: LazyLock<Wordlist> = LazyLock::new(|| {
    let words: Vec<&'static str> = include_str!("../wordlists/eff_large_wordlist.txt")
        .lines()
        .collect();
    let longest = words.iter().map(|word| word.len()).max().unwrap_or(0);
    Wordlist { words, longest }
});

struct Wordlist {
    words: Vec<&'static str>,
    longest: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GeneratorError {
    #[error(
        "Length must be between {} and {}",
        MIN_PASSWORD_LENGTH,
        MAX_PASSWORD_LENGTH
    )]
    InvalidLength,
    #[error("Word count must be between {} and {}", MIN_WORD_COUNT, MAX_WORD_COUNT)]
    InvalidWordCount,
    #[error("No characters to choose from")]
    EmptyPool,
    #[error("Length must be at least {0} to pick characters from every group")]
    TooShort(usize),
    #[error("Random number generator failed: {0}")]
    Random(String),
}

/// A character group of KeePassXC's password generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CharClass {
    Upper,
    Lower,
    Digits,
    Braces,
    Punctuation,
    Quotes,
    Dashes,
    Math,
    Logograms,
    ExtendedAscii,
}

impl CharClass {
    pub const ALL: [CharClass; 10] = [
        CharClass::Upper,
        CharClass::Lower,
        CharClass::Digits,
        CharClass::Braces,
        CharClass::Punctuation,
        CharClass::Quotes,
        CharClass::Dashes,
        CharClass::Math,
        CharClass::Logograms,
        CharClass::ExtendedAscii,
    ];

    /// Short label showing the characters of the class.
    pub fn label(self) -> &'static str {
        match self {
            CharClass::Upper => "A-Z",
            CharClass::Lower => "a-z",
            CharClass::Digits => "0-9",
            CharClass::Braces => "{ [ ( ) ] }",
            CharClass::Punctuation => ". , : ;",
            CharClass::Quotes => "\" '",
            CharClass::Dashes => "\\ / | _ -",
            CharClass::Math => "< > * + ! ? =",
            CharClass::Logograms => "# $ % & @ ^ ` ~",
            CharClass::ExtendedAscii => "Extended ASCII",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            CharClass::Upper => "Upper-case letters",
            CharClass::Lower => "Lower-case letters",
            CharClass::Digits => "Numbers",
            CharClass::Braces => "Braces",
            CharClass::Punctuation => "Punctuation",
            CharClass::Quotes => "Quotes",
            CharClass::Dashes => "Dashes and slashes",
            CharClass::Math => "Math symbols",
            CharClass::Logograms => "Logograms",
            CharClass::ExtendedAscii => "Extended ASCII (Latin-1)",
        }
    }

    fn characters(self) -> impl Iterator<Item = char> {
        let ascii = match self {
            CharClass::Upper => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            CharClass::Lower => "abcdefghijklmnopqrstuvwxyz",
            CharClass::Digits => "0123456789",
            CharClass::Braces => "()[]{}",
            CharClass::Punctuation => ".,:;",
            CharClass::Quotes => "\"'",
            CharClass::Dashes => "\\/|_-",
            CharClass::Math => "<>*+!?=",
            CharClass::Logograms => "#$%&@^`~",
            CharClass::ExtendedAscii => "",
        };
        // Printable Latin-1 starts after the C1 controls and the no-break space; the
        // soft hyphen is invisible.
        let latin1 = (self == CharClass::ExtendedAscii).then_some('\u{a1}'..='\u{ff}');
        ascii
            .chars()
            .chain(latin1.into_iter().flatten().filter(|&c| c != SOFT_HYPHEN))
    }
}

/// Options of the character-based generator. Defaults follow KeePassXC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordOptions {
    pub length: usize,
    pub classes: BTreeSet<CharClass>,
    /// Drop [`LOOK_ALIKE_CHARACTERS`] from the built-in classes. Characters listed in
    /// `also_choose` are kept, as in KeePassXC.
    pub exclude_look_alike: bool,
    /// Pick at least one character from every non-empty group.
    pub every_group: bool,
    /// Extra characters, forming a group of their own.
    pub also_choose: String,
    /// Characters removed from every group, including `also_choose`.
    pub exclude: String,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            classes: CharClass::ALL
                .into_iter()
                .filter(|&class| class != CharClass::ExtendedAscii)
                .collect(),
            exclude_look_alike: true,
            every_group: true,
            also_choose: String::new(),
            exclude: String::new(),
        }
    }
}

/// Non-empty character groups and the deduplicated union drawn from for the fill.
struct Groups {
    groups: Vec<Vec<char>>,
    pool: Vec<char>,
}

impl PasswordOptions {
    fn groups(&self) -> Result<Groups, GeneratorError> {
        if !(MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH).contains(&self.length) {
            return Err(GeneratorError::InvalidLength);
        }

        let excluded: BTreeSet<char> = self.exclude.chars().collect();
        let mut groups: Vec<Vec<char>> = self
            .classes
            .iter()
            .map(|class| {
                class
                    .characters()
                    .filter(|&c| {
                        let look_alike =
                            self.exclude_look_alike && LOOK_ALIKE_CHARACTERS.contains(c);
                        !look_alike && !excluded.contains(&c)
                    })
                    .collect()
            })
            .collect();
        let extra: BTreeSet<char> = self
            .also_choose
            .chars()
            .filter(|c| !excluded.contains(c))
            .collect();
        groups.push(extra.into_iter().collect());
        groups.retain(|group| !group.is_empty());

        let pool: BTreeSet<char> = groups.iter().flatten().copied().collect();
        if pool.is_empty() {
            return Err(GeneratorError::EmptyPool);
        }
        if self.every_group && self.length < groups.len() {
            return Err(GeneratorError::TooShort(groups.len()));
        }
        Ok(Groups {
            groups,
            pool: pool.into_iter().collect(),
        })
    }

    /// Entropy in bits of a password drawn uniformly from the pool. Like KeePassXC this
    /// ignores the small reduction caused by picking from every group.
    pub fn entropy(&self) -> Result<f64, GeneratorError> {
        let Groups { pool, .. } = self.groups()?;
        Ok(self.length as f64 * (pool.len() as f64).log2())
    }

    pub fn generate(&self) -> Result<String, GeneratorError> {
        let Groups { groups, pool } = self.groups()?;
        let mut chars = Zeroizing::new(Vec::with_capacity(self.length));
        if self.every_group {
            for group in &groups {
                chars.push(group[random_below(group.len())?]);
            }
        }
        while chars.len() < self.length {
            chars.push(pool[random_below(pool.len())?]);
        }
        if self.every_group {
            // Fisher-Yates, so the guaranteed characters do not sit at fixed positions.
            for i in (1..chars.len()).rev() {
                chars.swap(i, random_below(i + 1)?);
            }
        }
        let mut password = String::with_capacity(chars.iter().map(|c| c.len_utf8()).sum());
        password.extend(chars.iter());
        Ok(password)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WordCase {
    #[default]
    Lower,
    Upper,
    Title,
}

impl WordCase {
    pub const ALL: [WordCase; 3] = [WordCase::Lower, WordCase::Upper, WordCase::Title];

    pub fn label(self) -> &'static str {
        match self {
            WordCase::Lower => "lower",
            WordCase::Upper => "UPPER",
            WordCase::Title => "Title",
        }
    }
}

/// Options of the passphrase generator. Defaults follow KeePassXC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PassphraseOptions {
    pub word_count: usize,
    pub separator: String,
    pub word_case: WordCase,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            word_count: 7,
            separator: " ".to_owned(),
            word_case: WordCase::Lower,
        }
    }
}

impl PassphraseOptions {
    fn check_word_count(&self) -> Result<(), GeneratorError> {
        if (MIN_WORD_COUNT..=MAX_WORD_COUNT).contains(&self.word_count) {
            Ok(())
        } else {
            Err(GeneratorError::InvalidWordCount)
        }
    }

    /// Entropy in bits: every word is an independent uniform pick from the wordlist.
    pub fn entropy(&self) -> Result<f64, GeneratorError> {
        self.check_word_count()?;
        Ok(self.word_count as f64 * (WORDLIST.words.len() as f64).log2())
    }

    pub fn generate(&self) -> Result<String, GeneratorError> {
        self.check_word_count()?;
        let Wordlist { words, longest } = &*WORDLIST;
        // Sized up front so growing the string leaves no partial copies behind.
        let mut passphrase = String::with_capacity(
            self.word_count * longest + (self.word_count - 1) * self.separator.len(),
        );
        for index in 0..self.word_count {
            if index > 0 {
                passphrase.push_str(&self.separator);
            }
            // The wordlist is lower-case ASCII, so ASCII case mapping suffices.
            let word = words[random_below(words.len())?];
            match self.word_case {
                WordCase::Lower => passphrase.push_str(word),
                WordCase::Upper => passphrase.extend(word.chars().map(|c| c.to_ascii_uppercase())),
                WordCase::Title => {
                    let mut chars = word.chars();
                    if let Some(first) = chars.next() {
                        passphrase.push(first.to_ascii_uppercase());
                        passphrase.push_str(chars.as_str());
                    }
                }
            }
        }
        Ok(passphrase)
    }
}

/// Quality rating derived from entropy bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    Poor,
    Weak,
    Good,
    Excellent,
}

impl Strength {
    pub fn from_entropy(bits: f64) -> Self {
        if bits < 40.0 {
            Strength::Poor
        } else if bits < 65.0 {
            Strength::Weak
        } else if bits < 100.0 {
            Strength::Good
        } else {
            Strength::Excellent
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Strength::Poor => "Poor",
            Strength::Weak => "Weak",
            Strength::Good => "Good",
            Strength::Excellent => "Excellent",
        }
    }
}

/// Uniform index in `0..bound` from the CSPRNG.
fn random_below(bound: usize) -> Result<usize, GeneratorError> {
    // Bounds are at most the number of Unicode scalar values, the wordlist size or the
    // password length.
    let bound = u32::try_from(bound).expect("random bound fits in u32");
    assert!(bound > 0, "random bound must be positive");
    // Rejecting the lowest 2^32 mod `bound` values leaves a range that is a whole multiple
    // of `bound`, so the remainder is unbiased.
    let threshold = bound.wrapping_neg() % bound;
    loop {
        let mut bytes = [0u8; 4];
        getrandom::getrandom(&mut bytes)
            .map_err(|error| GeneratorError::Random(error.to_string()))?;
        let value = u32::from_le_bytes(bytes);
        if value >= threshold {
            return Ok((value % bound) as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLES: usize = 2000;

    fn options(classes: &[CharClass]) -> PasswordOptions {
        PasswordOptions {
            length: 16,
            classes: classes.iter().copied().collect(),
            exclude_look_alike: false,
            every_group: false,
            also_choose: String::new(),
            exclude: String::new(),
        }
    }

    fn class_chars(class: CharClass) -> BTreeSet<char> {
        class.characters().collect()
    }

    #[test]
    fn every_group_is_represented_even_at_minimum_length() {
        let mut opts = options(&CharClass::ALL);
        opts.every_group = true;
        opts.also_choose = "€".to_owned();
        // Ten classes plus the extra group.
        opts.length = 11;
        for _ in 0..SAMPLES {
            let password = opts.generate().unwrap();
            assert_eq!(password.chars().count(), 11);
            for class in CharClass::ALL {
                let chars = class_chars(class);
                assert!(password.chars().any(|c| chars.contains(&c)), "{class:?}");
            }
            assert!(password.contains('€'));
        }
    }

    #[test]
    fn every_group_positions_are_shuffled() {
        let mut opts = options(&[CharClass::Upper, CharClass::Digits]);
        opts.every_group = true;
        opts.length = 2;
        let samples = 20_000;
        let digit_first = (0..samples)
            .filter(|_| {
                let password = opts.generate().unwrap();
                password.chars().next().unwrap().is_ascii_digit()
            })
            .count();
        let ratio = digit_first as f64 / samples as f64;
        assert!((0.45..0.55).contains(&ratio), "{ratio}");
    }

    #[test]
    fn characters_are_drawn_uniformly() {
        let mut opts = options(&[CharClass::Digits]);
        opts.length = 100;
        let mut counts = [0usize; 10];
        for _ in 0..1000 {
            for c in opts.generate().unwrap().chars() {
                counts[c.to_digit(10).unwrap() as usize] += 1;
            }
        }
        // 10_000 expected per digit; 5% is about five standard deviations.
        for count in counts {
            assert!((9_500..10_500).contains(&count), "{counts:?}");
        }
    }

    #[test]
    fn excluded_characters_never_appear() {
        let mut opts = options(&CharClass::ALL);
        opts.every_group = true;
        opts.also_choose = "€xz".to_owned();
        opts.exclude = "aeiouAEIOU02468€z{}".to_owned();
        opts.length = 64;
        for _ in 0..SAMPLES {
            let password = opts.generate().unwrap();
            assert!(
                !password.chars().any(|c| opts.exclude.contains(c)),
                "{password}"
            );
        }
    }

    #[test]
    fn class_emptied_by_exclusions_is_not_a_group() {
        let mut opts = options(&[CharClass::Lower, CharClass::Digits]);
        opts.every_group = true;
        opts.exclude = "0123456789".to_owned();
        opts.length = 1;
        let password = opts.generate().unwrap();
        assert!(password.chars().all(|c| c.is_ascii_lowercase()));
        assert_eq!(opts.entropy().unwrap(), 26f64.log2());
    }

    #[test]
    fn look_alike_characters_are_excluded_from_classes_only() {
        let mut opts = options(&CharClass::ALL);
        opts.exclude_look_alike = true;
        opts.length = 128;
        for _ in 0..SAMPLES {
            let password = opts.generate().unwrap();
            assert!(
                !password.chars().any(|c| LOOK_ALIKE_CHARACTERS.contains(c)),
                "{password}"
            );
        }

        let mut opts = options(&[CharClass::Upper, CharClass::Lower, CharClass::Digits]);
        opts.exclude_look_alike = true;
        opts.length = 10;
        // 26 - "BGIO", 26 - "l", 10 - "0168".
        assert_eq!(opts.entropy().unwrap(), 10.0 * 53f64.log2());

        let mut opts = options(&[]);
        opts.exclude_look_alike = true;
        opts.also_choose = "0".to_owned();
        assert_eq!(opts.generate().unwrap(), "0".repeat(16));
    }

    #[test]
    fn extra_characters_are_included() {
        let mut opts = options(&[]);
        opts.also_choose = "€x€".to_owned();
        for _ in 0..SAMPLES {
            assert!(
                opts.generate()
                    .unwrap()
                    .chars()
                    .all(|c| c == '€' || c == 'x')
            );
        }
        assert_eq!(opts.entropy().unwrap(), 16.0);

        let mut opts = options(&[CharClass::Lower]);
        opts.also_choose = "€".to_owned();
        opts.every_group = true;
        for _ in 0..SAMPLES {
            assert!(opts.generate().unwrap().contains('€'));
        }
    }

    #[test]
    fn invalid_options_are_rejected() {
        let mut opts = options(&[CharClass::Upper, CharClass::Lower, CharClass::Digits]);
        opts.every_group = true;
        opts.also_choose = "€".to_owned();
        opts.length = 3;
        assert_eq!(opts.generate(), Err(GeneratorError::TooShort(4)));
        assert_eq!(opts.entropy(), Err(GeneratorError::TooShort(4)));
        opts.every_group = false;
        assert_eq!(opts.generate().unwrap().chars().count(), 3);

        assert_eq!(options(&[]).generate(), Err(GeneratorError::EmptyPool));
        let mut opts = options(&[CharClass::Digits]);
        opts.also_choose = "x".to_owned();
        opts.exclude = "0123456789x".to_owned();
        assert_eq!(opts.generate(), Err(GeneratorError::EmptyPool));

        for length in [0, MAX_PASSWORD_LENGTH + 1] {
            let opts = PasswordOptions {
                length,
                ..PasswordOptions::default()
            };
            assert_eq!(opts.generate(), Err(GeneratorError::InvalidLength));
        }
        let opts = PasswordOptions {
            length: MAX_PASSWORD_LENGTH,
            ..PasswordOptions::default()
        };
        assert_eq!(
            opts.generate().unwrap().chars().count(),
            MAX_PASSWORD_LENGTH
        );
    }

    #[test]
    fn default_password_entropy() {
        // Letters and digits without look-alikes (22 + 25 + 6) plus every special class
        // without "|" (6 + 4 + 2 + 4 + 7 + 8).
        let entropy = PasswordOptions::default().entropy().unwrap();
        assert_eq!(entropy, 20.0 * 84f64.log2());
        assert_eq!(Strength::from_entropy(entropy), Strength::Excellent);
    }

    #[test]
    fn extended_ascii_is_printable_latin1() {
        let chars = class_chars(CharClass::ExtendedAscii);
        assert_eq!(chars.len(), 94);
        assert!(!chars.contains(&'\u{a0}'));
        assert!(!chars.contains(&SOFT_HYPHEN));
        assert!(chars.contains(&'\u{a1}') && chars.contains(&'\u{ff}'));
    }

    #[test]
    fn wordlist_has_7776_unique_lowercase_words() {
        let words = &WORDLIST.words;
        assert_eq!(words.len(), 7776);
        assert_eq!(words.iter().collect::<BTreeSet<_>>().len(), 7776);
        assert!(
            words.iter().all(|word| !word.is_empty()
                && word.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'))
        );
    }

    fn split_words(passphrase: &str, separator: &str) -> Vec<String> {
        passphrase.split(separator).map(str::to_owned).collect()
    }

    #[test]
    fn passphrase_word_count_separator_and_case() {
        let words: BTreeSet<&str> = WORDLIST.words.iter().copied().collect();
        for word_case in WordCase::ALL {
            for word_count in [MIN_WORD_COUNT, 7, MAX_WORD_COUNT] {
                let opts = PassphraseOptions {
                    word_count,
                    separator: " + ".to_owned(),
                    word_case,
                };
                let passphrase = opts.generate().unwrap();
                let parts = split_words(&passphrase, " + ");
                assert_eq!(parts.len(), word_count);
                for part in parts {
                    assert!(words.contains(part.to_ascii_lowercase().as_str()), "{part}");
                    let expected = match word_case {
                        WordCase::Lower => part.to_ascii_lowercase(),
                        WordCase::Upper => part.to_ascii_uppercase(),
                        WordCase::Title => {
                            let lower = part.to_ascii_lowercase();
                            format!("{}{}", lower[..1].to_ascii_uppercase(), &lower[1..])
                        }
                    };
                    assert_eq!(part, expected);
                }
            }
        }

        let opts = PassphraseOptions {
            word_count: 3,
            separator: String::new(),
            word_case: WordCase::Title,
        };
        assert_eq!(
            opts.generate()
                .unwrap()
                .chars()
                .filter(char::is_ascii_uppercase)
                .count(),
            3
        );
    }

    #[test]
    fn passphrase_rejects_invalid_word_counts() {
        for word_count in [0, MAX_WORD_COUNT + 1] {
            let opts = PassphraseOptions {
                word_count,
                ..PassphraseOptions::default()
            };
            assert_eq!(opts.generate(), Err(GeneratorError::InvalidWordCount));
            assert_eq!(opts.entropy(), Err(GeneratorError::InvalidWordCount));
        }
    }

    #[test]
    fn passphrase_entropy() {
        let opts = PassphraseOptions::default();
        let entropy = opts.entropy().unwrap();
        assert_eq!(entropy, 7.0 * 7776f64.log2());
        assert!((entropy - 90.47).abs() < 0.01);
        assert_eq!(Strength::from_entropy(entropy), Strength::Good);
    }

    #[test]
    fn strength_thresholds() {
        let cases = [
            (0.0, Strength::Poor),
            (39.99, Strength::Poor),
            (40.0, Strength::Weak),
            (64.99, Strength::Weak),
            (65.0, Strength::Good),
            (99.99, Strength::Good),
            (100.0, Strength::Excellent),
        ];
        for (bits, strength) in cases {
            assert_eq!(Strength::from_entropy(bits), strength, "{bits}");
        }
    }
}
