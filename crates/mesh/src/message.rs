use serde_json::{json, Value};

pub const STREAM_OPEN_METHOD: &str = "mesh.stream.open";
pub const STREAM_OPENED_METHOD: &str = "mesh.stream.opened";

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
            StreamOpenRequest::parse(&json!({"method": STREAM_OPEN_METHOD, "mode": "text"}), "ssh:7")
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
