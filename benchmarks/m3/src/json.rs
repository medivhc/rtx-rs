//! Minimal JSON tree, deterministic writer and parser.
//!
//! The harness deliberately avoids `serde`/`serde_json`: the result schema is
//! small and fixed, and the benchmark crate must stay offline-buildable with
//! path dependencies only. The writer emits object keys in insertion order
//! (deterministic across runs), and the parser exists so `--verify` can
//! re-read the files `run.sh` produced and check the schema after the fact.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// A JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// An integer (`M3-P` counters are integers).
    Int(i64),
    /// A floating-point number (rates, medians, percentages).
    Float(f64),
    /// A string.
    Str(String),
    /// An array.
    Array(Vec<Json>),
    /// An object; insertion order is preserved by the writer.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// Wraps a `u64` counter without losing precision when it fits an `i64`.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        i64::try_from(value).map_or_else(|_| Self::Float(value as f64), Self::Int)
    }

    /// Wraps a `usize` counter.
    #[must_use]
    pub fn from_usize(value: usize) -> Self {
        Self::from_u64(u64::try_from(value).unwrap_or(u64::MAX))
    }

    /// Wraps an optional counter.
    #[must_use]
    pub fn opt_u64(value: Option<u64>) -> Self {
        value.map_or(Self::Null, Self::from_u64)
    }

    /// Wraps an optional floating-point metric.
    #[must_use]
    pub fn opt_f64(value: Option<f64>) -> Self {
        value.map_or(Self::Null, Self::Float)
    }

    /// Builds an object from borrowed keys.
    #[must_use]
    pub fn object(entries: Vec<(&str, Self)>) -> Self {
        Self::Object(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }

    /// Looks up an object member.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(entries) => entries
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// The value as a finite `f64` (`Int` is promoted).
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Int(value) => Some(*value as f64),
            Self::Float(value) if value.is_finite() => Some(*value),
            _ => None,
        }
    }

    /// The value as a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(value) => Some(value),
            _ => None,
        }
    }

    /// The value as an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    /// The value as an object.
    #[must_use]
    pub fn as_object(&self) -> Option<&[(String, Self)]> {
        match self {
            Self::Object(entries) => Some(entries),
            _ => None,
        }
    }
}

/// Serializes a value with two-space indentation and a trailing newline.
#[must_use]
pub fn to_string(value: &Json) -> String {
    let mut output = String::new();
    write_value(&mut output, value, 0);
    output.push('\n');
    output
}

fn write_value(output: &mut String, value: &Json, indent: usize) {
    match value {
        Json::Null => output.push_str("null"),
        Json::Bool(flag) => output.push_str(if *flag { "true" } else { "false" }),
        Json::Int(number) => {
            let _ = write!(output, "{number}");
        }
        Json::Float(number) => write_float(output, *number),
        Json::Str(text) => write_string(output, text),
        Json::Array(values) => {
            if values.is_empty() {
                output.push_str("[]");
                return;
            }
            output.push_str("[\n");
            for (index, item) in values.iter().enumerate() {
                indent_into(output, indent + 1);
                write_value(output, item, indent + 1);
                output.push_str(if index + 1 == values.len() {
                    "\n"
                } else {
                    ",\n"
                });
            }
            indent_into(output, indent);
            output.push(']');
        }
        Json::Object(entries) => {
            if entries.is_empty() {
                output.push_str("{}");
                return;
            }
            output.push_str("{\n");
            for (index, (key, item)) in entries.iter().enumerate() {
                indent_into(output, indent + 1);
                write_string(output, key);
                output.push_str(": ");
                write_value(output, item, indent + 1);
                output.push_str(if index + 1 == entries.len() {
                    "\n"
                } else {
                    ",\n"
                });
            }
            indent_into(output, indent);
            output.push('}');
        }
    }
}

fn write_float(output: &mut String, value: f64) {
    if !value.is_finite() {
        output.push_str("null");
    } else if value.fract() == 0.0 && value.abs() < 9.0e15 {
        let _ = write!(output, "{value:.0}");
    } else {
        let _ = write!(output, "{value:.3}");
    }
}

fn write_string(output: &mut String, text: &str) {
    output.push('"');
    for character in text.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            control if control.is_control() => {
                let _ = write!(output, "\\u{:04x}", u32::from(control));
            }
            other => output.push(other),
        }
    }
    output.push('"');
}

fn indent_into(output: &mut String, indent: usize) {
    for _ in 0..indent {
        output.push_str("  ");
    }
}

/// Parses one JSON document.
///
/// # Errors
///
/// Returns a human-readable message with a byte offset when the text is not
/// valid JSON.
pub fn parse(text: &str) -> Result<Json, String> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        position: 0,
    };
    let value = parser.value()?;
    parser.skip_whitespace();
    if parser.position != parser.bytes.len() {
        return Err(format!("trailing data at byte {}", parser.position));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Parser<'_> {
    fn value(&mut self) -> Result<Json, String> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string().map(Json::Str),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(other) => Err(format!(
                "unexpected byte {:?} at byte {}",
                other as char, self.position
            )),
            None => Err("unexpected end of input".to_owned()),
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut entries = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.position += 1;
            return Ok(Json::Object(entries));
        }
        loop {
            self.skip_whitespace();
            let key = self.string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            let value = self.value()?;
            entries.push((key, value));
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.position += 1,
                Some(b'}') => {
                    self.position += 1;
                    return Ok(Json::Object(entries));
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.position)),
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut values = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.position += 1;
            return Ok(Json::Array(values));
        }
        loop {
            values.push(self.value()?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    return Ok(Json::Array(values));
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.position)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut output = String::new();
        loop {
            let byte = self
                .peek()
                .ok_or_else(|| "unterminated string".to_owned())?;
            match byte {
                b'"' => {
                    self.position += 1;
                    return Ok(output);
                }
                b'\\' => {
                    self.position += 1;
                    let escaped = self
                        .peek()
                        .ok_or_else(|| "unterminated escape".to_owned())?;
                    self.position += 1;
                    match escaped {
                        b'"' => output.push('"'),
                        b'\\' => output.push('\\'),
                        b'/' => output.push('/'),
                        b'n' => output.push('\n'),
                        b'r' => output.push('\r'),
                        b't' => output.push('\t'),
                        b'b' => output.push('\u{0008}'),
                        b'f' => output.push('\u{000c}'),
                        b'u' => {
                            let code = self.hex4()?;
                            let character = char::from_u32(code).ok_or_else(|| {
                                format!("invalid unicode escape at byte {}", self.position)
                            })?;
                            output.push(character);
                        }
                        other => {
                            return Err(format!(
                                "invalid escape {:?} at byte {}",
                                other as char, self.position
                            ));
                        }
                    }
                }
                _ => {
                    let remaining = std::str::from_utf8(&self.bytes[self.position..])
                        .map_err(|_| "invalid UTF-8 in string".to_owned())?;
                    let character = remaining
                        .chars()
                        .next()
                        .ok_or_else(|| "unterminated string".to_owned())?;
                    self.position += character.len_utf8();
                    output.push(character);
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let window = self
            .bytes
            .get(self.position..self.position + 4)
            .ok_or_else(|| "truncated unicode escape".to_owned())?;
        let text = std::str::from_utf8(window).map_err(|_| "invalid unicode escape".to_owned())?;
        let code = u32::from_str_radix(text, 16)
            .map_err(|_| format!("invalid unicode escape at byte {}", self.position))?;
        self.position += 4;
        Ok(code)
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.position;
        if self.peek() == Some(b'-') {
            self.position += 1;
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.position += 1;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.position += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.position += 1;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.position])
            .map_err(|_| "invalid number".to_owned())?;
        if is_float {
            text.parse::<f64>()
                .map(Json::Float)
                .map_err(|_| format!("invalid number {text:?}"))
        } else {
            text.parse::<i64>()
                .map(Json::Int)
                .map_err(|_| format!("invalid integer {text:?}"))
        }
    }

    fn literal(&mut self, word: &str, value: Json) -> Result<Json, String> {
        let end = self.position + word.len();
        if self.bytes.get(self.position..end) == Some(word.as_bytes()) {
            self.position = end;
            Ok(value)
        } else {
            Err(format!("invalid literal at byte {}", self.position))
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        self.skip_whitespace();
        if self.peek() == Some(byte) {
            self.position += 1;
            Ok(())
        } else {
            Err(format!(
                "expected {:?} at byte {}",
                byte as char, self.position
            ))
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.position += 1;
        }
    }
}

/// Rejects duplicate keys in a parsed object (the schema check relies on
/// unique names).
#[must_use]
pub fn duplicate_keys(value: &Json) -> Vec<String> {
    let mut duplicates = Vec::new();
    let mut seen: BTreeMap<&str, ()> = BTreeMap::new();
    collect_duplicates(value, &mut seen, &mut duplicates);
    duplicates
}

fn collect_duplicates<'a>(
    value: &'a Json,
    seen: &mut BTreeMap<&'a str, ()>,
    duplicates: &mut Vec<String>,
) {
    match value {
        Json::Object(entries) => {
            seen.clear();
            for (key, item) in entries {
                if seen.insert(key.as_str(), ()).is_some() {
                    duplicates.push(key.clone());
                }
                collect_duplicates(item, seen, duplicates);
            }
        }
        Json::Array(values) => {
            for item in values {
                collect_duplicates(item, seen, duplicates);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{Json, parse, to_string};

    #[test]
    fn round_trip_preserves_values_and_order() {
        let value = Json::object(vec![
            ("zenith", Json::Int(1)),
            ("alpha", Json::Str("hello \"world\"\n".to_owned())),
            ("empty", Json::Array(Vec::new())),
            ("nested", Json::object(vec![("ok", Json::Bool(true))])),
        ]);
        let text = to_string(&value);
        let parsed = parse(&text).expect("own output parses");
        assert_eq!(parsed, value);
        let rendered = to_string(&parsed);
        assert_eq!(rendered, text, "the writer is deterministic");
    }

    #[test]
    fn floats_render_without_trailing_noise() {
        assert_eq!(to_string(&Json::Float(12.5)), "12.500\n");
        assert_eq!(to_string(&Json::Float(7.0)), "7\n");
        assert_eq!(to_string(&Json::Float(f64::NAN)), "null\n");
    }

    #[test]
    fn parser_rejects_trailing_and_malformed_input() {
        assert!(parse("{} x").is_err());
        assert!(parse("{\"a\":}").is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse("\"unterminated").is_err());
    }

    #[test]
    fn duplicate_keys_are_reported() {
        let parsed = parse("{\"a\":1,\"a\":2}").expect("parses");
        assert_eq!(super::duplicate_keys(&parsed), vec!["a".to_owned()]);
    }
}
