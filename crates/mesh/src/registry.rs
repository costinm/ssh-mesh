//! Protocol-neutral service identity, common handlers, and resource metadata.
//!
//! A worker can ship generated metadata without linking a gateway protocol.
//! JSON/text, tagged-CBOR, HTTP, CLI, or the optional `mesh-mcp` adapter may
//! all consume the same registry.

use serde_json::{Value, json};

use crate::protocol::Response;

pub use crate::jsonl::{JsonSource, ResourceSpec, ServiceRegistry};

/// Result of offering one decoded method and field map to the common registry.
/// Transport adapters retain ownership of framing, correlation, and encoding.
pub enum CommonDispatch {
    Response(Response),
    NotHandled,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::tagged::{NameOrTag, TaggedRecord};

    #[tokio::test]
    async fn registry_dispatches_named_tagged_common_methods() {
        let registry = ServiceRegistry::new("demo");
        let request = TaggedRecord {
            component: NameOrTag::Name("mesh".to_string()),
            method: NameOrTag::Name("initialize".to_string()),
            id: Some(json!(7)),
            ..Default::default()
        };
        let response = registry.dispatch_tagged(&request).await.unwrap().unwrap();
        assert_eq!(response.id, Some(json!(7)));
        assert_eq!(response.result.unwrap()["1"], "demo");
    }
}

impl ServiceRegistry {
    /// Offer a tagged request to the built-in mesh handlers and preserve its
    /// correlation ID in the tagged response. `None` means the request belongs
    /// to an application handler.
    pub async fn dispatch_tagged(
        &self,
        request: &crate::tagged::TaggedRecord,
    ) -> anyhow::Result<Option<crate::tagged::TaggedRecord>> {
        use anyhow::Context;

        let mut decoded = crate::tagged::to_json(request, None);
        let fields = decoded
            .as_object_mut()
            .context("tagged request must decode to an object")?;
        let method = fields
            .get("method")
            .and_then(Value::as_str)
            .context("tagged request is missing its method")?
            .to_string();
        let tagged_fields: &[(&str, u32)] = match method.as_str() {
            "mesh.lifecycle" => &[("action", 1), ("cause", 2), ("observed", 3)],
            "trace.set_level" => &[("level", 1)],
            _ => &[],
        };
        for (name, tag) in tagged_fields {
            if let Some(value) = fields.remove(&format!("@{tag}")) {
                fields.entry((*name).to_string()).or_insert(value);
            }
        }
        let CommonDispatch::Response(response) = self.dispatch(&method, fields).await else {
            return Ok(None);
        };
        let id = request
            .id
            .clone()
            .context("common method requires a correlation id")?;
        let response_fields: &[(&str, u32)] = match method.as_str() {
            "mesh.initialize" => &[
                ("name", 1),
                ("version", 2),
                ("title", 3),
                ("instructions", 4),
            ],
            "mesh.tools" => &[("tools", 1)],
            "mesh.lifecycle" => &[("subscribers", 1)],
            _ => &[],
        };
        Ok(Some(if response.success {
            let mut data = response.data.unwrap_or_default();
            if let Some(fields) = data.as_object_mut() {
                for (name, tag) in response_fields {
                    if let Some(value) = fields.remove(*name) {
                        fields.insert(tag.to_string(), value);
                    }
                }
            }
            crate::wire::response_ok(id, data)
        } else {
            crate::wire::response_error(id, response.error.unwrap_or_default().into())
        }))
    }

    /// Dispatch the handlers installed by every mesh service registry after an
    /// adapter has decoded its wire representation. These currently cover
    /// service discovery, supervisor lifecycle, and trace configuration.
    pub async fn dispatch(
        &self,
        method: &str,
        fields: &serde_json::Map<String, Value>,
    ) -> CommonDispatch {
        let response = match method {
            "mesh.lifecycle" | "lifecycle" => {
                match serde_json::from_value::<crate::lifecycle::LifecycleEvent>(Value::Object(
                    fields.clone(),
                )) {
                    Ok(event) => Response::ok_with_data(json!({
                        "subscribers": crate::lifecycle::publish(event),
                    })),
                    Err(error) => Response::err(format!("invalid mesh.lifecycle event: {error}")),
                }
            }
            "mesh.initialize" | "initialize" => self.initialize(),
            "mesh.tools" | "tools" => self.tools().await,
            "trace.set_level" | "set_level" | "set_trace_level" | "set_source_level" => {
                let level = fields
                    .get("level")
                    .and_then(Value::as_str)
                    .unwrap_or("info");
                let request = crate::local_trace::TraceLevelRequest {
                    level: level.to_string(),
                };
                match crate::local_trace::set_trace_level(&request) {
                    Ok(response) => {
                        Response::ok_with_data(serde_json::to_value(response).unwrap_or_default())
                    }
                    Err(response) => Response::err(
                        response
                            .message
                            .unwrap_or_else(|| "Failed to set trace level".to_string()),
                    ),
                }
            }
            "trace.get_level" | "get_level" | "get_trace_level" => Response::ok_with_data(
                serde_json::to_value(crate::local_trace::get_trace_level()).unwrap_or_default(),
            ),
            "trace.subscribe" | "subscribe" => Response::ok_with_data(json!({
                "subscribed": true,
                "service": self.name(),
            })),
            _ => return CommonDispatch::NotHandled,
        };
        CommonDispatch::Response(response)
    }
}
