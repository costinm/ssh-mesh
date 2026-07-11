use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use serde_json::{Value, json};

pub const STREAM_OPEN_METHOD: &str = "mesh.stream.open";
pub const STREAM_OPENED_METHOD: &str = "mesh.stream.opened";

// Keep service-side text stream conventions in sync with
// `fw/esp32/rust/src/commands/protocol.rs`: one newline-terminated record,
// record kind as the first token, and structured fields as logfmt-style
// `key=value` pairs. Use quoted values when strings contain whitespace or
// shell-sensitive separators.

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TextRecord {
    pub kind: String,
    pub args: Vec<String>,
    pub fields: BTreeMap<String, String>,
}

impl TextRecord {
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            args: Vec::new(),
            fields: BTreeMap::new(),
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn field(mut self, key: impl Into<String>, value: impl ToString) -> Self {
        self.fields.insert(key.into(), value.to_string());
        self
    }

    pub fn from_json_object(kind: impl Into<String>, value: &Value) -> Self {
        let mut record = Self::new(kind);
        if let Some(object) = value.as_object() {
            for (key, value) in object {
                record
                    .fields
                    .insert(key.clone(), text_value_from_json(value));
            }
        } else {
            record
                .fields
                .insert("value".to_string(), text_value_from_json(value));
        }
        record
    }

    pub fn parse(line: &str) -> Result<Self> {
        let tokens = split_text_tokens(line)?;
        let mut iter = tokens.into_iter();
        let kind = iter
            .next()
            .ok_or_else(|| anyhow!("text record requires a kind"))?;
        let mut record = Self::new(kind);
        for token in iter {
            if let Some((key, value)) = token.split_once('=') {
                if key.is_empty() {
                    return Err(anyhow!("text record field key cannot be empty"));
                }
                record.fields.insert(key.to_string(), value.to_string());
            } else {
                record.args.push(token);
            }
        }
        Ok(record)
    }

    pub fn format(&self) -> String {
        let mut out = quote_text_value(&self.kind);
        for arg in &self.args {
            out.push(' ');
            out.push_str(&quote_text_value(arg));
        }
        for (key, value) in &self.fields {
            out.push(' ');
            out.push_str(key);
            out.push('=');
            out.push_str(&quote_text_value(value));
        }
        out
    }
}

pub fn format_text_response(success: bool, error: Option<&str>, data: Option<&Value>) -> String {
    if success {
        match data {
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| TextRecord::from_json_object("response", item).format())
                .collect::<Vec<_>>()
                .join("\n"),
            Some(value) => TextRecord::from_json_object("response", value)
                .field("success", "true")
                .format(),
            None => TextRecord::new("response")
                .field("success", "true")
                .format(),
        }
    } else {
        TextRecord::new("error")
            .field("message", error.unwrap_or("unknown error"))
            .format()
    }
}

#[derive(Clone, Debug)]
pub enum LineProtocolFormat {
    Json(crate::jsonl::ProtocolFormat),
    Text,
    BinaryMux,
}

#[derive(Clone, Debug, Default)]
pub struct LineProtocolSession {
    format: Option<LineProtocolFormat>,
}

impl LineProtocolSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn format(&self) -> Option<&LineProtocolFormat> {
        self.format.as_ref()
    }

    pub fn parse_request_line(
        &mut self,
        line: &str,
    ) -> (LineProtocolFormat, Result<crate::protocol::Request, String>) {
        if self.format.is_none() {
            let selected = match line.as_bytes().first().copied() {
                Some(byte) => LineProtocolFormat::from_first_byte(byte),
                None => Err(anyhow!("empty protocol line")),
            };
            match selected {
                Ok(format) => self.format = Some(format),
                Err(err) => {
                    self.format = Some(LineProtocolFormat::Text);
                    return (LineProtocolFormat::Text, Err(err.to_string()));
                }
            }
        }

        let format = match self.format.as_mut().expect("protocol selected") {
            LineProtocolFormat::Json(json_format) => {
                if line.starts_with('{') {
                    let (new_format, _) =
                        crate::jsonl::parse_request::<crate::protocol::Request>(line);
                    *json_format = new_format;
                }
                LineProtocolFormat::Json(json_format.clone())
            }
            selected => selected.clone(),
        };
        let parsed = parse_request_line_with_format(line, &format);
        (format, parsed)
    }

    pub fn format_response(&self, response: crate::protocol::Response) -> Result<String> {
        let format = self
            .format
            .as_ref()
            .ok_or_else(|| anyhow!("protocol not selected"))?;
        format_protocol_response(response, format)
    }
}

impl LineProtocolFormat {
    pub fn from_first_byte(byte: u8) -> Result<Self> {
        match byte {
            b'{' => Ok(Self::Json(crate::jsonl::ProtocolFormat::FlatJson {
                id: None,
            })),
            b'a'..=b'z' | b'A'..=b'Z' => Ok(Self::Text),
            0x00 => Ok(Self::BinaryMux),
            _ => Err(anyhow!("unsupported protocol first byte 0x{byte:02x}")),
        }
    }
}

pub fn parse_request_line_with_format(
    line: &str,
    format: &LineProtocolFormat,
) -> Result<crate::protocol::Request, String> {
    match format {
        LineProtocolFormat::Json(_) => {
            let (_, parsed) = crate::jsonl::parse_request::<crate::protocol::Request>(line);
            parsed
        }
        LineProtocolFormat::Text => parse_text_request(line).map_err(|err| err.to_string()),
        LineProtocolFormat::BinaryMux => {
            Err("binary mux protocol is not implemented yet".to_string())
        }
    }
}

pub fn parse_request_line(
    line: &str,
) -> (LineProtocolFormat, Result<crate::protocol::Request, String>) {
    LineProtocolSession::new().parse_request_line(line)
}

pub fn format_protocol_response(
    response: crate::protocol::Response,
    format: &LineProtocolFormat,
) -> Result<String> {
    match format {
        LineProtocolFormat::Json(format) => crate::jsonl::format_response(response, format),
        LineProtocolFormat::Text => Ok(format_text_response(
            response.success,
            response.error.as_deref(),
            response.data.as_ref(),
        )),
        LineProtocolFormat::BinaryMux => Err(anyhow!("binary mux protocol is not implemented yet")),
    }
}

pub fn text_record_to_request(record: TextRecord) -> Result<crate::protocol::Request> {
    use crate::protocol::Request;

    match record.kind.as_str() {
        "status" => Ok(Request::Status {
            name: record.fields.get("name").cloned(),
        }),
        "start" => Ok(Request::Start {
            name: required_field(&record, "name")?,
            args: split_list_field(record.fields.get("args")),
            env: BTreeMap::new().into_iter().collect(),
            context: None,
        }),
        "stop" => Ok(Request::Stop {
            name: required_field(&record, "name")?,
            signal: record
                .fields
                .get("signal")
                .map(|value| value.parse())
                .transpose()?,
        }),
        "freeze" => Ok(Request::Freeze {
            name: required_field(&record, "name")?,
        }),
        "unfreeze" => Ok(Request::Unfreeze {
            name: required_field(&record, "name")?,
        }),
        "reload" => Ok(Request::Reload),
        "shutdown" => Ok(Request::Shutdown),
        command => Err(anyhow!("unsupported text command {command}")),
    }
}

pub fn parse_text_request(line: &str) -> Result<crate::protocol::Request> {
    text_record_to_request(TextRecord::parse(line)?)
}

fn required_field(record: &TextRecord, key: &str) -> Result<String> {
    record
        .fields
        .get(key)
        .cloned()
        .ok_or_else(|| anyhow!("text command {} requires {key}=...", record.kind))
}

fn split_list_field(value: Option<&String>) -> Vec<String> {
    value
        .map(|value| {
            value
                .split(',')
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub fn quote_text_value(value: &str) -> String {
    if is_bare_text_value(value) {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn is_bare_text_value(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\'' | b'\\' | b'='))
}

fn split_text_tokens(line: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted => quoted = false,
            '"' if current.is_empty() || current.ends_with('=') => quoted = true,
            '\\' if quoted => {
                let Some(escaped) = chars.next() else {
                    return Err(anyhow!("unterminated text escape"));
                };
                current.push(match escaped {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    other => other,
                });
            }
            ch if ch.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            ch => current.push(ch),
        }
    }
    if quoted {
        return Err(anyhow!("unterminated quoted text value"));
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

pub fn text_value_from_json(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamOpenRequest {
    pub id: Option<String>,
    pub session: String,
    pub stream: String,
    pub mode: String,
    pub kind: String,
}

impl StreamOpenRequest {
    pub fn parse(value: &Value, default_session: impl Into<String>) -> Option<Self> {
        let obj = value.as_object()?;
        if obj.get("method").and_then(Value::as_str)? != STREAM_OPEN_METHOD {
            return None;
        }

        let data = obj.get("data").and_then(Value::as_object);
        let mode = data
            .and_then(|data| data.get("mode"))
            .or_else(|| obj.get("mode"))
            .and_then(Value::as_str)?;
        if !matches!(mode, "binary" | "raw") {
            return None;
        }

        let default_session = default_session.into();
        let id = obj.get("id").map(json_value_to_string);
        let session = obj
            .get("session")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or(default_session);
        let stream = obj
            .get("stream")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("{session}:binary"));
        let kind = data
            .and_then(|data| data.get("kind"))
            .or_else(|| obj.get("kind"))
            .and_then(Value::as_str)
            .unwrap_or("shell")
            .to_string();

        Some(Self {
            id,
            session,
            stream,
            mode: mode.to_string(),
            kind,
        })
    }

    pub fn opened_response(&self) -> Value {
        json!({
            "id": self.id.clone(),
            "replyTo": self.id.clone(),
            "session": self.session.clone(),
            "stream": self.stream.clone(),
            "type": "response",
            "method": STREAM_OPENED_METHOD,
            "data": {
                "mode": self.mode.clone(),
                "kind": self.kind.clone(),
            }
        })
    }
}

pub fn canonical_method_name(name: &str) -> String {
    name.to_string()
}

fn json_value_to_string(v: &Value) -> String {
    v.as_str()
        .map(str::to_string)
        .unwrap_or_else(|| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_record_formats_and_parses_logfmt_style_fields() {
        let line = TextRecord::new("event")
            .field("type", "lora.rx")
            .field("message", "hello world")
            .field("count", 2)
            .format();

        assert_eq!(line, r#"event count=2 message="hello world" type=lora.rx"#);
        let parsed = TextRecord::parse(&line).unwrap();
        assert_eq!(parsed.kind, "event");
        assert_eq!(parsed.fields["type"], "lora.rx");
        assert_eq!(parsed.fields["message"], "hello world");
        assert_eq!(parsed.fields["count"], "2");
    }

    #[test]
    fn text_response_formats_objects_and_errors() {
        let response =
            format_text_response(true, None, Some(&json!({"state": "running", "pid": 42})));
        assert_eq!(response, "response pid=42 state=running success=true");

        let error = format_text_response(false, Some("bad service"), None);
        assert_eq!(error, r#"error message="bad service""#);
    }

    #[test]
    fn line_protocol_session_selects_once_from_first_byte() {
        let mut session = LineProtocolSession::new();
        let (format, parsed) = session.parse_request_line("status name=alpha");
        assert!(matches!(format, LineProtocolFormat::Text));
        assert!(matches!(
            parsed.unwrap(),
            crate::protocol::Request::Status { name } if name.as_deref() == Some("alpha")
        ));

        let (format, parsed) = session.parse_request_line(r#"{"method":"status","name":"json"}"#);
        assert!(matches!(format, LineProtocolFormat::Text));
        assert!(
            parsed.is_err(),
            "JSON-looking line stays text after text selection"
        );
    }

    #[test]
    fn line_protocol_session_selects_json_and_binary() {
        let mut json_session = LineProtocolSession::new();
        let (format, parsed) = json_session.parse_request_line(r#"{"method":"status","name":"x"}"#);
        assert!(matches!(format, LineProtocolFormat::Json(_)));
        assert!(parsed.is_ok());

        let mut binary_session = LineProtocolSession::new();
        let (format, parsed) = binary_session.parse_request_line("\0ignored");
        assert!(matches!(format, LineProtocolFormat::BinaryMux));
        assert!(parsed.unwrap_err().contains("binary mux"));
    }

    #[test]
    fn parses_nested_binary_stream_open() {
        let request = StreamOpenRequest::parse(
            &json!({
                "id": "stream-upgrade-1",
                "method": STREAM_OPEN_METHOD,
                "data": {
                    "mode": "binary",
                    "kind": "shell"
                }
            }),
            "ssh:7",
        )
        .expect("stream open");

        assert_eq!(request.id.as_deref(), Some("stream-upgrade-1"));
        assert_eq!(request.session, "ssh:7");
        assert_eq!(request.stream, "ssh:7:binary");
        assert_eq!(request.mode, "binary");
        assert_eq!(request.kind, "shell");

        assert_eq!(
            request.opened_response(),
            json!({
                "id": "stream-upgrade-1",
                "replyTo": "stream-upgrade-1",
                "session": "ssh:7",
                "stream": "ssh:7:binary",
                "type": "response",
                "method": STREAM_OPENED_METHOD,
                "data": {
                    "mode": "binary",
                    "kind": "shell"
                }
            })
        );
    }

    #[test]
    fn parses_flat_raw_stream_open_with_session_fields() {
        let request = StreamOpenRequest::parse(
            &json!({
                "method": STREAM_OPEN_METHOD,
                "mode": "raw",
                "kind": "binder",
                "session": "session-1",
                "stream": "stream-1"
            }),
            "ssh:7",
        )
        .expect("stream open");

        assert_eq!(request.id, None);
        assert_eq!(request.session, "session-1");
        assert_eq!(request.stream, "stream-1");
        assert_eq!(request.mode, "raw");
        assert_eq!(request.kind, "binder");
    }

    #[test]
    fn rejects_non_stream_open_method() {
        assert!(StreamOpenRequest::parse(&json!({"method": "mesh.message"}), "ssh:7").is_none());
    }

    #[test]
    fn rejects_text_mode() {
        assert!(
            StreamOpenRequest::parse(
                &json!({"method": STREAM_OPEN_METHOD, "mode": "text"}),
                "ssh:7"
            )
            .is_none()
        );
    }

    #[test]
    fn parses_method_name() {
        let request = StreamOpenRequest::parse(
            &json!({
                "id": "stream-upgrade-1",
                "method": STREAM_OPEN_METHOD,
                "data": {
                    "mode": "binary"
                }
            }),
            "ssh:7",
        )
        .expect("stream open");

        assert_eq!(request.stream, "ssh:7:binary");
    }
}
