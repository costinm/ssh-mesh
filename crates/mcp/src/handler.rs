//! MCP handler implementation for pmond.
//!
//! This module provides the `PmonMcpHandler` which implements the MCP
//! `ServerHandler` trait, allowing pmond to be accessed via the MCP protocol.

use pmond::ProcMon;
use pmond::{
    CgroupHighArgs, ClearRefsArgs, GetCgroupArgs, GetProcessArgs, MoveProcessArgs,
    ProcessDetailedInfo,
};
use rmcp::{
    RoleServer,
    handler::server::ServerHandler,
    model::{
        Annotated, CallToolResult, ErrorCode, ErrorData, Implementation, InitializeRequestParam,
        InitializeResult, ListResourcesResult, ListToolsResult, PaginatedRequestParam,
        ProtocolVersion, RawContent, RawResource, RawTextContent, ReadResourceRequestParam,
        ReadResourceResult, Resource, ResourceContents, ResourcesCapability, ServerCapabilities,
        Tool, ToolsCapability,
    },
    service::RequestContext,
};
use schemars::schema_for;
use serde_json::{Value, json};
use std::sync::Arc;

/// MCP handler for the Process Memory monitor.
#[derive(Clone)]
pub struct PmonMcpHandler {
    proc_mon: Arc<ProcMon>,
}

impl PmonMcpHandler {
    pub fn new(proc_mon: Arc<ProcMon>) -> Self {
        Self { proc_mon }
    }
}

/// Helper to convert Value to input_schema type (Arc<Map<String, Value>>)
fn to_schema(v: Value) -> Arc<serde_json::Map<String, Value>> {
    if let Value::Object(map) = v {
        Arc::new(map)
    } else {
        Arc::new(serde_json::Map::new())
    }
}

impl ServerHandler for PmonMcpHandler {
    async fn initialize(
        &self,
        _params: InitializeRequestParam,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        Ok(InitializeResult {
            protocol_version: ProtocolVersion::default(),
            server_info: Implementation {
                name: "pmond".to_string(),
                version: "0.1.0".to_string(),
                icons: None,
                title: None,
                website_url: None,
            },
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: Some(false),
                }),
                resources: Some(ResourcesCapability {
                    list_changed: Some(false),
                    subscribe: Some(false),
                }),
                ..Default::default()
            },
            instructions: None,
        })
    }

    async fn list_tools(
        &self,
        _params: Option<PaginatedRequestParam>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tools = vec![
            Tool {
                name: "list_processes".into(),
                description: Some("List all running processes".into()),
                input_schema: to_schema(json!({"type": "object", "properties": {}})),
                annotations: None,
                icons: None,
                meta: None,
                title: None,
                output_schema: None,
            },
            Tool {
                name: "get_process".into(),
                description: Some("Get details of a specific process by PID".into()),
                input_schema: to_schema(serde_json::to_value(schema_for!(GetProcessArgs)).unwrap()),
                annotations: None,
                icons: None,
                meta: None,
                title: None,
                output_schema: None,
            },
            Tool {
                name: "list_cgroups".into(),
                description: Some("List all cgroups used by processes".into()),
                input_schema: to_schema(json!({"type": "object", "properties": {}})),
                annotations: None,
                icons: None,
                meta: None,
                title: None,
                output_schema: None,
            },
            Tool {
                name: "get_cgroup".into(),
                description: Some("Get memory info for a specific cgroup path".into()),
                input_schema: to_schema(serde_json::to_value(schema_for!(GetCgroupArgs)).unwrap()),
                annotations: None,
                icons: None,
                meta: None,
                title: None,
                output_schema: None,
            },
            Tool {
                name: "move_process".into(),
                description: Some("Move a process to a new cgroup subdirectory".into()),
                input_schema: to_schema(
                    serde_json::to_value(schema_for!(MoveProcessArgs)).unwrap(),
                ),
                annotations: None,
                icons: None,
                meta: None,
                title: None,
                output_schema: None,
            },
            Tool {
                name: "clear_refs".into(),
                description: Some(
                    "Clear process memory references via /proc/[pid]/clear_refs".into(),
                ),
                input_schema: to_schema(serde_json::to_value(schema_for!(ClearRefsArgs)).unwrap()),
                annotations: None,
                icons: None,
                meta: None,
                title: None,
                output_schema: None,
            },
            Tool {
                name: "cgroup_high".into(),
                description: Some(
                    "Adjust memory.high for a cgroup to a percentage of current usage".into(),
                ),
                input_schema: to_schema(serde_json::to_value(schema_for!(CgroupHighArgs)).unwrap()),
                annotations: None,
                icons: None,
                meta: None,
                title: None,
                output_schema: None,
            },
            Tool {
                name: "psi_watches".into(),
                description: Some("Get current PSI (Pressure Stall Information) watches".into()),
                input_schema: to_schema(json!({"type": "object", "properties": {}})),
                annotations: None,
                icons: None,
                meta: None,
                title: None,
                output_schema: None,
            },
        ];

        Ok(ListToolsResult {
            tools,
            next_cursor: None,
            meta: None,
        })
    }

    async fn call_tool(
        &self,
        params: rmcp::model::CallToolRequestParam,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let args = Value::Object(params.arguments.unwrap_or_default());
        let name = params.name.as_ref();

        // Directly dispatch to appropriate handler
        let result: Result<Value, ErrorData> = match name {
            "list_processes" => {
                let processes = self.proc_mon.get_all_processes(1);
                let process_list: Vec<_> = processes.values().collect();
                Ok(json!(process_list))
            }
            "get_process" => {
                let args: GetProcessArgs = serde_json::from_value(args).map_err(|e| ErrorData {
                    code: ErrorCode(-32602),
                    message: e.to_string().into(),
                    data: None,
                })?;

                let pid: u32 = args.process.parse().map_err(|_| ErrorData {
                    code: ErrorCode(-32602),
                    message: format!("Invalid PID: {}", args.process).into(),
                    data: None,
                })?;

                match self.proc_mon.get_process(pid) {
                    Some(process) => {
                        let cgroup = process
                            .cgroup_path
                            .as_ref()
                            .and_then(|p| pmond::read_cgroup_detailed(p));

                        let parent_cgroups = process
                            .cgroup_path
                            .as_ref()
                            .map(|p| pmond::get_parent_cgroups(p))
                            .unwrap_or_default();

                        let detailed_info = ProcessDetailedInfo {
                            process,
                            cgroup,
                            parent_cgroups,
                        };

                        Ok(json!(detailed_info))
                    }
                    None => Err(ErrorData {
                        code: ErrorCode(-32001),
                        message: format!("Process {} not found", pid).into(),
                        data: None,
                    }),
                }
            }
            "list_cgroups" => {
                let cgroups = self.proc_mon.get_all_cgroups();
                Ok(json!(cgroups))
            }
            "get_cgroup" => {
                let args: GetCgroupArgs = serde_json::from_value(args).map_err(|e| ErrorData {
                    code: ErrorCode(-32602),
                    message: e.to_string().into(),
                    data: None,
                })?;

                match self.proc_mon.read_cgroup(&args.path) {
                    Some(cgroup) => Ok(json!(cgroup)),
                    None => Err(ErrorData {
                        code: ErrorCode(-32001),
                        message: format!("Cgroup {} not found", args.path).into(),
                        data: None,
                    }),
                }
            }
            "move_process" => {
                let args: MoveProcessArgs =
                    serde_json::from_value(args).map_err(|e| ErrorData {
                        code: ErrorCode(-32602),
                        message: e.to_string().into(),
                        data: None,
                    })?;

                self.proc_mon
                    .move_process_to_cgroup(args.pid, args.cgroup_name)
                    .map_err(|e| ErrorData {
                        code: ErrorCode(-32000),
                        message: e.to_string().into(),
                        data: None,
                    })?;

                Ok(json!({"status": "ok"}))
            }
            "clear_refs" => {
                let args: ClearRefsArgs = serde_json::from_value(args).map_err(|e| ErrorData {
                    code: ErrorCode(-32602),
                    message: e.to_string().into(),
                    data: None,
                })?;

                self.proc_mon
                    .clear_refs(args.pid, &args.value)
                    .map_err(|e| ErrorData {
                        code: ErrorCode(-32000),
                        message: e.to_string().into(),
                        data: None,
                    })?;

                Ok(json!({
                    "status": "ok",
                    "message": format!("Cleared refs for process {} with value {}", args.pid, args.value)
                }))
            }
            "cgroup_high" => {
                let args: CgroupHighArgs = serde_json::from_value(args).map_err(|e| ErrorData {
                    code: ErrorCode(-32602),
                    message: e.to_string().into(),
                    data: None,
                })?;

                self.proc_mon
                    .adjust_cgroup_memory_high(args.path, args.percentage, args.interval)
                    .map_err(|e| ErrorData {
                        code: ErrorCode(-32000),
                        message: e.to_string().into(),
                        data: None,
                    })?;

                Ok(json!({"status": "ok"}))
            }
            "psi_watches" => {
                let watches = self.proc_mon.get_psi_watches();
                Ok(json!(watches))
            }
            _ => Err(ErrorData {
                code: ErrorCode(-32601),
                message: format!("Method not found: {}", name).into(),
                data: None,
            }),
        };

        match result {
            Ok(value) => {
                let text = serde_json::to_string_pretty(&value).unwrap_or_default();
                Ok(CallToolResult {
                    content: vec![Annotated {
                        raw: RawContent::Text(RawTextContent { text, meta: None }),
                        annotations: None,
                    }],
                    is_error: None,
                    meta: None,
                    structured_content: None,
                })
            }
            Err(e) => Err(e),
        }
    }

    async fn list_resources(
        &self,
        _params: Option<PaginatedRequestParam>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let resources = vec![
            Resource {
                annotations: None,
                raw: RawResource {
                    uri: "process://list".to_string(),
                    name: "Process List".to_string(),
                    description: Some("List of all processes".to_string()),
                    mime_type: Some("application/json".to_string()),
                    size: None,
                    meta: None,
                    icons: None,
                    title: None,
                },
            },
            Resource {
                annotations: None,
                raw: RawResource {
                    uri: "cgroup://list".to_string(),
                    name: "CGroup List".to_string(),
                    description: Some("List of all cgroups and their memory info".to_string()),
                    mime_type: Some("application/json".to_string()),
                    size: None,
                    meta: None,
                    icons: None,
                    title: None,
                },
            },
        ];

        Ok(ListResourcesResult {
            resources,
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        params: ReadResourceRequestParam,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        let result = if params.uri == "process://list" {
            let processes = self.proc_mon.get_all_processes(1);
            let process_list: Vec<_> = processes.values().collect();
            json!(process_list)
        } else if params.uri == "cgroup://list" {
            let cgroups = self.proc_mon.get_all_cgroups();
            json!(cgroups)
        } else {
            return Err(ErrorData {
                code: ErrorCode(-32602),
                message: format!("Resource not found: {}", params.uri).into(),
                data: None,
            });
        };

        Ok(ReadResourceResult {
            contents: vec![ResourceContents::TextResourceContents {
                uri: params.uri,
                mime_type: Some("application/json".to_string()),
                text: serde_json::to_string(&result).unwrap(),
                meta: None,
            }],
        })
    }
}
