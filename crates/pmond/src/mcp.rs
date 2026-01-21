use crate::{ProcMemInfo, ProcMon};
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::{
    handler::server::ServerHandler,
    model::{
        Annotated, CallToolResult, ErrorCode, ErrorData, Implementation, InitializeRequestParam,
        InitializeResult, ListResourcesResult, ListToolsResult, PaginatedRequestParam,
        ProtocolVersion, RawContent, RawResource, RawTextContent, ReadResourceRequestParam,
        ReadResourceResult, Resource, ResourceContents, ResourcesCapability, ServerCapabilities,
        Tool, ToolsCapability,
    },
    service::RequestContext,
    RoleServer, ServiceExt,
};
use schemars::{schema_for, JsonSchema};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Clone)]
pub struct PmonMcpHandler {
    proc_mon: Arc<ProcMon>,
}

impl PmonMcpHandler {
    pub fn new(proc_mon: Arc<ProcMon>) -> Self {
        Self { proc_mon }
    }
}

pub fn mcp_service(proc_mon: Arc<ProcMon>) -> StreamableHttpService<PmonMcpHandler> {
    let config = StreamableHttpServerConfig::default();
    let session_manager = Arc::new(LocalSessionManager::default());

    StreamableHttpService::new(
        move || Ok(PmonMcpHandler::new(proc_mon.clone())),
        session_manager,
        config,
    )
}

#[derive(Deserialize, JsonSchema)]
struct GetProcessArgs {
    process: String,
}

#[derive(Serialize, Deserialize)]
struct SimplifiedProcess {
    pid: u32,
    ppid: u32,
    name: String,
    cgroup_path: Option<String>,
    cmdline: Option<String>,
    rss: u64,
    mem_info: Option<ProcMemInfo>,
    user: Option<u32>,
}

// Helper to convert Value to input_schema type (Arc<Map<String, Value>>)
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
        tracing::info!("MCP Initialize called");
        Ok(InitializeResult {
            protocol_version: ProtocolVersion::default(),
            server_info: Implementation {
                name: "pmond".to_string().into(),
                version: "0.1.0".to_string().into(),
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
        tracing::info!("list_tools called");
        let tools = vec![
            Tool {
                name: "list_processes".to_string().into(),
                description: Some("List all running processes".to_string().into()),
                input_schema: to_schema(json!({
                    "type": "object",
                    "properties": {},
                })),
                annotations: None,
                icons: None,
                meta: None,
                title: None,
                output_schema: None,
            },
            Tool {
                name: "get_process".to_string().into(),
                description: Some(
                    "Get details of a specific process by PID"
                        .to_string()
                        .into(),
                ),
                input_schema: to_schema(serde_json::to_value(schema_for!(GetProcessArgs)).unwrap()),
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
        match params.name.as_ref() {
            "list_processes" => {
                let processes = self.proc_mon.get_all_processes();
                // Convert to a simplified list for display
                let process_list: Vec<SimplifiedProcess> = processes
                    .values()
                    .map(|p| SimplifiedProcess {
                        pid: p.pid,
                        ppid: p.ppid,
                        name: p.comm.clone(),
                        cgroup_path: p.cgroup_path.clone(),
                        cmdline: p.cmdline.clone(),
                        rss: p.mem_info.as_ref().map(|m| m.anon).unwrap_or(0),
                        mem_info: p.mem_info.clone(),
                        user: p.uid,
                    })
                    .collect();

                Ok(CallToolResult {
                    content: vec![Annotated {
                        raw: RawContent::Text(RawTextContent {
                            text: serde_json::to_string_pretty(&process_list).unwrap().into(),
                            meta: None,
                        }),
                        annotations: None,
                    }],
                    is_error: None,
                    meta: None,
                    structured_content: None,
                })
            }
            "get_process" => {
                let args_val = serde_json::Value::Object(params.arguments.unwrap_or_default());
                let args: GetProcessArgs =
                    serde_json::from_value(args_val).map_err(|e| ErrorData {
                        code: ErrorCode(-32602),
                        message: format!("Invalid arguments: {}", e).into(),
                        data: None,
                    })?;

                let pid = args.process.parse::<u32>().map_err(|_| ErrorData {
                    code: ErrorCode(-32602),
                    message: format!("Invalid PID: {}", args.process).into(),
                    data: None,
                })?;

                match self.proc_mon.get_process(pid) {
                    Some(process) => Ok(CallToolResult {
                        content: vec![Annotated {
                            raw: RawContent::Text(RawTextContent {
                                text: serde_json::to_string_pretty(&process).unwrap().into(),
                                meta: None,
                            }),
                            annotations: None,
                        }],
                        is_error: None,
                        meta: None,
                        structured_content: None,
                    }),
                    None => Err(ErrorData {
                        code: ErrorCode(-32001),
                        message: format!("Process {} not found", pid).into(),
                        data: None,
                    }),
                }
            }
            _ => Err(ErrorData {
                code: ErrorCode(-32601),
                message: format!("Tool not found: {}", params.name).into(),
                data: None,
            }),
        }
    }

    async fn list_resources(
        &self,
        _params: Option<PaginatedRequestParam>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let resources = vec![Resource {
            annotations: None,
            raw: RawResource {
                uri: "process://list".to_string().into(),
                name: "Process List".to_string().into(),
                description: Some("List of all processes".to_string().into()),
                mime_type: Some("application/json".to_string().into()),
                size: None,
                meta: None,
                icons: None,
                title: None,
            },
        }];

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
        if params.uri == "process://list" {
            let processes = self.proc_mon.get_all_processes();
            Ok(ReadResourceResult {
                contents: vec![ResourceContents::TextResourceContents {
                    uri: params.uri,
                    mime_type: Some("application/json".to_string().into()),
                    text: serde_json::to_string(&processes).unwrap().into(),
                    meta: None,
                }],
            })
        } else {
            Err(ErrorData {
                code: ErrorCode(-32602),
                message: format!("Resource not found: {}", params.uri).into(),
                data: None,
            })
        }
    }
}

pub async fn run_stdio_server(proc_mon: Arc<ProcMon>) -> Result<(), Box<dyn std::error::Error>> {
    let handler = PmonMcpHandler::new(proc_mon);
    let transport = rmcp::transport::stdio();
    let service = handler.serve(transport).await?;
    service.waiting().await?;
    Ok(())
}
