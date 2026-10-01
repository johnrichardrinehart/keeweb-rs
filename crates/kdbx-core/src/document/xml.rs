//! Generic element tree for the KDBX inner XML document.
//!
//! KeePass XML never uses mixed content, so each element holds either text or child
//! elements. Whitespace between child elements is dropped and regenerated as
//! indentation on write; text of leaf elements is kept verbatim.

use crate::error::{Error, Result};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Element {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub text: String,
    pub children: Vec<Element>,
}

impl Element {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Self::default()
        }
    }

    pub fn with_text(name: &str, text: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            text: text.into(),
            ..Self::default()
        }
    }

    pub fn with_children(name: &str, children: Vec<Element>) -> Self {
        Self {
            name: name.to_string(),
            children,
            ..Self::default()
        }
    }

    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }

    pub fn child_mut(&mut self, name: &str) -> Option<&mut Element> {
        self.children.iter_mut().find(|c| c.name == name)
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }

    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).map(|c| c.text.as_str())
    }

    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn set_attr(&mut self, name: &str, value: &str) {
        match self.attrs.iter_mut().find(|(k, _)| k == name) {
            Some((_, v)) => *v = value.to_string(),
            None => self.attrs.push((name.to_string(), value.to_string())),
        }
    }

    pub fn remove_attr(&mut self, name: &str) {
        self.attrs.retain(|(k, _)| k != name);
    }

    /// Whether the text is encrypted with the inner random stream in the file.
    pub fn is_protected(&self) -> bool {
        self.attr("Protected")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"))
    }

    pub fn remove_children(&mut self, name: &str) {
        self.children.retain(|c| c.name != name);
    }

    /// Inserts `child` before the first existing child that comes later in `order`.
    /// Children not listed in `order` are skipped over, which keeps unknown elements
    /// where they were and appends repeated elements after their last sibling.
    pub fn insert_ordered(&mut self, child: Element, order: &[&str]) -> usize {
        let index = match order.iter().position(|n| *n == child.name) {
            Some(rank) => self
                .children
                .iter()
                .position(|c| {
                    order
                        .iter()
                        .position(|n| *n == c.name)
                        .is_some_and(|r| r > rank)
                })
                .unwrap_or(self.children.len()),
            None => self.children.len(),
        };
        self.children.insert(index, child);
        index
    }

    /// Returns the named child, inserting an empty one at its canonical position when missing.
    pub fn ensure_child(&mut self, name: &str, order: &[&str]) -> &mut Element {
        let index = match self.children.iter().position(|c| c.name == name) {
            Some(index) => index,
            None => self.insert_ordered(Element::new(name), order),
        };
        &mut self.children[index]
    }

    pub fn set_child_text(&mut self, name: &str, text: &str, order: &[&str]) {
        let child = self.ensure_child(name, order);
        if child.text != text {
            child.text = text.to_string();
        }
    }

    /// Replaces the first child with the same name, or inserts it at its canonical position.
    pub fn replace_child(&mut self, child: Element, order: &[&str]) {
        match self.children.iter_mut().find(|c| c.name == child.name) {
            Some(existing) => *existing = child,
            None => {
                self.insert_ordered(child, order);
            }
        }
    }
}

fn xml_error(e: impl std::fmt::Display) -> Error {
    Error::ParseError(format!("XML error: {e}"))
}

fn start_element(reader: &Reader<&[u8]>, start: &BytesStart) -> Result<Element> {
    let name = std::str::from_utf8(start.name().as_ref())
        .map_err(xml_error)?
        .to_string();
    let mut element = Element::new(&name);
    for attr in start.attributes() {
        let attr = attr.map_err(xml_error)?;
        let key = std::str::from_utf8(attr.key.as_ref())
            .map_err(xml_error)?
            .to_string();
        let value = attr
            .decode_and_unescape_value(reader.decoder())
            .map_err(xml_error)?
            .into_owned();
        element.attrs.push((key, value));
    }
    Ok(element)
}

/// Parses a KeePass XML document. `unprotect` receives the trimmed base64 text of each
/// non-empty protected element in document order and returns its plaintext.
pub(crate) fn parse(
    data: &[u8],
    mut unprotect: impl FnMut(&str) -> Result<String>,
) -> Result<Element> {
    let mut reader = Reader::from_reader(data);
    reader.config_mut().trim_text(false);
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;

    let mut finish = |mut element: Element,
                      stack: &mut Vec<Element>,
                      root: &mut Option<Element>|
     -> Result<()> {
        if !element.children.is_empty() {
            element.text.clear();
        } else if element.is_protected() {
            let encoded = element.text.trim();
            element.text = if encoded.is_empty() {
                String::new()
            } else {
                unprotect(encoded)?
            };
        }
        match stack.last_mut() {
            Some(parent) => parent.children.push(element),
            None if root.is_none() => *root = Some(element),
            None => return Err(xml_error("multiple root elements")),
        }
        Ok(())
    };

    loop {
        match reader.read_event().map_err(xml_error)? {
            Event::Start(start) => stack.push(start_element(&reader, &start)?),
            Event::Empty(start) => {
                let element = start_element(&reader, &start)?;
                finish(element, &mut stack, &mut root)?;
            }
            Event::End(_) => {
                let element = stack.pop().ok_or_else(|| xml_error("unbalanced end tag"))?;
                finish(element, &mut stack, &mut root)?;
            }
            Event::Text(text) => {
                if let Some(current) = stack.last_mut() {
                    current
                        .text
                        .push_str(&text.xml10_content().map_err(xml_error)?);
                }
            }
            Event::CData(data) => {
                if let Some(current) = stack.last_mut() {
                    current
                        .text
                        .push_str(&data.xml10_content().map_err(xml_error)?);
                }
            }
            Event::GeneralRef(reference) => {
                let ch = match reference.resolve_char_ref().map_err(xml_error)? {
                    Some(ch) => ch,
                    None => match reference.decode().map_err(xml_error)?.as_ref() {
                        "amp" => '&',
                        "lt" => '<',
                        "gt" => '>',
                        "quot" => '"',
                        "apos" => '\'',
                        other => return Err(xml_error(format!("unknown entity &{other};"))),
                    },
                };
                if let Some(current) = stack.last_mut() {
                    current.text.push(ch);
                }
            }
            Event::Eof => break,
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) | Event::DocType(_) => {}
        }
    }

    if !stack.is_empty() {
        return Err(xml_error("unexpected end of document"));
    }
    root.ok_or_else(|| xml_error("empty document"))
}

/// Characters XML 1.0 cannot represent at all, even escaped.
fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r') || (c >= ' ' && c != '\u{FFFE}' && c != '\u{FFFF}')
}

fn escape_into(out: &mut String, text: &str, attribute: bool) {
    for c in text.chars().filter(|c| is_xml_char(*c)) {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            // Literal CR would be normalized away by the next parser.
            '\r' => out.push_str("&#13;"),
            '"' if attribute => out.push_str("&quot;"),
            '\n' if attribute => out.push_str("&#10;"),
            '\t' if attribute => out.push_str("&#9;"),
            c => out.push(c),
        }
    }
}

/// Serializes the document. `protect` receives the plaintext of each protected element
/// in document order and returns the text to store (base64 ciphertext).
pub(crate) fn write(root: &Element, mut protect: impl FnMut(&str) -> String) -> Vec<u8> {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n");
    write_element(root, 0, &mut out, &mut protect);
    out.into_bytes()
}

fn write_element(
    element: &Element,
    depth: usize,
    out: &mut String,
    protect: &mut dyn FnMut(&str) -> String,
) {
    for _ in 0..depth {
        out.push('\t');
    }
    out.push('<');
    out.push_str(&element.name);
    for (key, value) in &element.attrs {
        out.push(' ');
        out.push_str(key);
        out.push_str("=\"");
        escape_into(out, value, true);
        out.push('"');
    }
    if element.children.is_empty() {
        let protected;
        let text = if element.is_protected() {
            protected = protect(&element.text);
            protected.as_str()
        } else {
            element.text.as_str()
        };
        if text.is_empty() {
            out.push_str("/>\n");
        } else {
            out.push('>');
            escape_into(out, text, false);
            out.push_str("</");
            out.push_str(&element.name);
            out.push_str(">\n");
        }
    } else {
        out.push_str(">\n");
        for child in &element.children {
            write_element(child, depth + 1, out, protect);
        }
        for _ in 0..depth {
            out.push('\t');
        }
        out.push_str("</");
        out.push_str(&element.name);
        out.push_str(">\n");
    }
}
