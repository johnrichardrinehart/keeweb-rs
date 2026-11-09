//! Ranked, typo-tolerant entry search.
//!
//! The query and every field split into lower-case words at anything that is not a
//! letter or digit, so "google personal" finds "Google (Personal)". Each query word
//! must match a word of some field, as the whole word, its start, a part of it, or
//! its start with a few typos. Better matches in more important fields rank higher.

/// Weight of a field in the ranking.
pub const TITLE: f32 = 1.0;
pub const USER_NAME: f32 = 0.8;
pub const URL: f32 = 0.7;
pub const TAG: f32 = 0.7;
pub const GROUP: f32 = 0.5;

/// A parsed search query.
pub struct Query {
    tokens: Vec<Vec<char>>,
    /// Query words joined by single spaces, for the title bonus.
    phrase: String,
}

impl Query {
    /// `None` when the text holds no letters or digits.
    pub fn parse(text: &str) -> Option<Self> {
        let words = words(text);
        if words.is_empty() {
            return None;
        }
        Some(Self {
            phrase: words.join(" "),
            tokens: words.iter().map(|word| word.chars().collect()).collect(),
        })
    }

    /// Rank of an entry with `fields` as (weight, text) pairs, `None` when some
    /// query word matches no field. `fields[0]` should be the title.
    pub fn score(&self, fields: &[(f32, &str)]) -> Option<f32> {
        let fields: Vec<(f32, Vec<Vec<char>>)> = fields
            .iter()
            .map(|(weight, text)| {
                let words = words(text).iter().map(|w| w.chars().collect()).collect();
                (*weight, words)
            })
            .collect();
        let mut total = 0.0;
        for token in &self.tokens {
            let best = fields
                .iter()
                .flat_map(|(weight, words)| {
                    words
                        .iter()
                        .map(move |word| weight * word_score(token, word))
                })
                .fold(0.0_f32, f32::max);
            if best <= 0.0 {
                return None;
            }
            total += best;
        }
        // The title reads like the query: exact, or starting with it.
        if let Some((_, title)) = fields.first() {
            let title = title
                .iter()
                .map(|word| word.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join(" ");
            if title == self.phrase {
                total += 1.0;
            } else if title.starts_with(&self.phrase) {
                total += 0.5;
            }
        }
        Some(total)
    }
}

/// Lower-case words of `text`, split at anything that is not a letter or digit.
fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// How many typos a query word of `len` characters may contain.
fn allowed_typos(len: usize) -> usize {
    match len {
        0..=3 => 0,
        4..=7 => 1,
        _ => 2,
    }
}

/// How well query word `token` matches field word `word`, from 0 (not at all) to 1.
fn word_score(token: &[char], word: &[char]) -> f32 {
    if token == word {
        return 1.0;
    }
    if word.starts_with(token) {
        // Longer prefixes of the word rank higher.
        return 0.75 + 0.15 * token.len() as f32 / word.len() as f32;
    }
    if token.len() >= 2 && word.windows(token.len()).any(|part| part == token) {
        return 0.6;
    }
    let allowed = allowed_typos(token.len());
    if allowed > 0 {
        let typos = prefix_distance(token, word, allowed);
        if typos <= allowed {
            return 0.5 - 0.15 * typos as f32;
        }
    }
    0.0
}

/// Fewest single-character insertions, deletions, substitutions and swaps of
/// neighbours that turn `token` into some start of `word`. Values above `limit`
/// come back as `limit + 1`.
fn prefix_distance(token: &[char], word: &[char], limit: usize) -> usize {
    let (m, n) = (token.len(), word.len());
    if m > n + limit {
        return limit + 1;
    }
    // Rows of the edit-distance table for the previous two and the current token
    // character; column j is the distance to word[..j].
    let mut before: Vec<usize> = vec![0; n + 1];
    let mut previous: Vec<usize> = (0..=n).collect();
    let mut current: Vec<usize> = vec![0; n + 1];
    for i in 1..=m {
        current[0] = i;
        for j in 1..=n {
            let substitution = usize::from(token[i - 1] != word[j - 1]);
            let mut cost = (previous[j] + 1)
                .min(current[j - 1] + 1)
                .min(previous[j - 1] + substitution);
            if i > 1 && j > 1 && token[i - 1] == word[j - 2] && token[i - 2] == word[j - 1] {
                cost = cost.min(before[j - 2] + 1);
            }
            current[j] = cost;
        }
        if current.iter().min().is_some_and(|&best| best > limit) {
            return limit + 1;
        }
        std::mem::swap(&mut before, &mut previous);
        std::mem::swap(&mut previous, &mut current);
    }
    previous.into_iter().min().unwrap_or(m).min(limit + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(query: &str, title: &str) -> Option<f32> {
        Query::parse(query).unwrap().score(&[(TITLE, title)])
    }

    #[test]
    fn extra_words_narrow_the_match() {
        assert!(score("google personal", "Google (Personal)").is_some());
        assert!(score("google personal", "Google Account").is_none());
        assert!(score("personal google", "Google (Personal)").is_some());
    }

    #[test]
    fn typos_still_match() {
        assert!(score("gogle", "Google Account").is_some());
        assert!(score("goolge", "Google Account").is_some());
        assert!(score("google personl", "Google (Personal)").is_some());
        assert!(score("amazn", "Amazon").is_some());
        // Short words must be exact.
        assert!(score("gpo", "GitHub").is_none());
    }

    #[test]
    fn partial_words_match() {
        assert!(score("goo", "Google").is_some());
        assert!(score("hub", "GitHub").is_some());
        assert!(score("g", "Google").is_some());
        assert!(score("o", "Google").is_none());
    }

    #[test]
    fn unrelated_words_do_not_match() {
        assert!(score("bank", "Google Account").is_none());
        assert!(score("netflix", "Google").is_none());
    }

    #[test]
    fn closer_titles_rank_higher() {
        let exact = score("google personal", "Google (Personal)").unwrap();
        let typo = score("google personl", "Google (Personal)").unwrap();
        assert!(exact > typo);

        let whole = score("google", "Google").unwrap();
        let prefix = score("google", "Google Account").unwrap();
        let fuzzy = score("google", "Googel Account").unwrap();
        assert!(whole > prefix && prefix > fuzzy);
    }

    #[test]
    fn title_outranks_other_fields() {
        let query = Query::parse("personal").unwrap();
        let in_title = query.score(&[(TITLE, "Personal mail"), (GROUP, "Work")]);
        let in_group = query.score(&[(TITLE, "Mail"), (GROUP, "Personal Accounts")]);
        assert!(in_title.unwrap() > in_group.unwrap());
    }

    #[test]
    fn punctuation_only_query_is_empty() {
        assert!(Query::parse(" .-( ").is_none());
    }

    #[test]
    fn prefix_distance_counts_typos() {
        let chars = |s: &str| s.chars().collect::<Vec<_>>();
        assert_eq!(prefix_distance(&chars("gogle"), &chars("google"), 2), 1);
        assert_eq!(prefix_distance(&chars("goolge"), &chars("google"), 2), 1);
        assert_eq!(prefix_distance(&chars("persn"), &chars("personal"), 2), 1);
        assert_eq!(prefix_distance(&chars("xyzzy"), &chars("google"), 1), 2);
    }
}
