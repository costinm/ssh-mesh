use std::path::Path;

use anyhow::{Context, Result, bail};
use mesh_api_gen::{
    api_markdown_from_rust, api_markdown_from_tools_json_for_component, json_schema,
    merge_tools_json, parse_api_markdown, parse_required_path, rust_api, rust_ids, tools_json,
};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut api = None;
    let mut rust = None;
    let mut tools = None;
    let mut out_api = None;
    let mut out_tools = None;
    let mut out_schema = None;
    let mut out_ids = None;
    let mut out_rust = None;
    let mut base_tools = None;
    let mut component = None;
    let mut check = false;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--api" => api = Some(args.next().context("--api requires a path")?),
            "--rust" => rust = Some(args.next().context("--rust requires a path")?),
            "--tools" => tools = Some(args.next().context("--tools requires a path")?),
            "--out-api" => out_api = Some(args.next().context("--out-api requires a path")?),
            "--out-tools" => out_tools = Some(args.next().context("--out-tools requires a path")?),
            "--out-schema" => {
                out_schema = Some(args.next().context("--out-schema requires a path")?)
            }
            "--out-ids" => out_ids = Some(args.next().context("--out-ids requires a path")?),
            "--out-rust" => out_rust = Some(args.next().context("--out-rust requires a path")?),
            "--base-tools" => {
                base_tools = Some(args.next().context("--base-tools requires a path")?)
            }
            "--component" => component = Some(args.next().context("--component requires a name")?),
            "--check" => check = true,
            "--help" | "-h" => {
                println!(
                    "mesh-api-gen --api API.md [--base-tools legacy-tools.json] --out-tools tools.json --out-schema schema.json --out-ids ids.rs --out-rust src/api.rs [--check]\nmesh-api-gen --rust api.rs --out-api generated.md\nmesh-api-gen --tools legacy-tools.json --component service --out-api migration.md"
                );
                return Ok(());
            }
            _ => bail!("unknown argument {argument}"),
        }
    }

    if let Some(rust) = rust {
        let generated = api_markdown_from_rust(&std::fs::read_to_string(&rust)?)?;
        write_or_check(
            &parse_required_path(out_api, "--out-api")?,
            &generated,
            check,
        )?;
        return Ok(());
    }
    if let Some(tools) = tools {
        let generated = api_markdown_from_tools_json_for_component(
            &serde_json::from_str(&std::fs::read_to_string(tools)?)?,
            component.as_deref(),
        )?;
        write_or_check(
            &parse_required_path(out_api, "--out-api")?,
            &generated,
            check,
        )?;
        return Ok(());
    }
    let api = parse_required_path(api, "--api")?;
    let methods = parse_api_markdown(&std::fs::read_to_string(&api)?)?;
    if let Some(path) = out_tools {
        let generated = if let Some(base_tools) = base_tools {
            merge_tools_json(
                &serde_json::from_str(&std::fs::read_to_string(base_tools)?)?,
                &methods,
            )?
        } else {
            tools_json(&methods)
        };
        write_or_check(
            &path,
            &format!("{}\n", serde_json::to_string_pretty(&generated)?),
            check,
        )?;
    }
    if let Some(path) = out_schema {
        write_or_check(
            &path,
            &format!(
                "{}\n",
                serde_json::to_string_pretty(&json_schema(&methods))?
            ),
            check,
        )?;
    }
    if let Some(path) = out_ids {
        write_or_check(&path, &rust_ids(&methods), check)?;
    }
    if let Some(path) = out_rust {
        write_or_check(&path, &rust_api(&methods), check)?;
    }
    Ok(())
}

fn write_or_check(path: &str, contents: &str, check: bool) -> Result<()> {
    if check {
        let current = std::fs::read_to_string(path)
            .with_context(|| format!("read generated artifact {path}"))?;
        if current != contents {
            bail!("generated artifact is stale: {path}");
        }
        return Ok(());
    }
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents).with_context(|| format!("write generated artifact {path}"))
}
