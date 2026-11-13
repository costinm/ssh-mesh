use std::path::Path;

use anyhow::{Context, Result, bail};
use mesh_api_gen::{
    api_markdown_from_tools_json_for_component, java::java_api, json_schema, manifest_cbor,
    merge_tools_json, parse_api_markdown, parse_required_path, rust_api, rust_api_tagged,
    rust_cbor_api, rust_component, rust_ids, rust_specs, tools_json,
};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut api = None;
    let mut tools = None;
    let mut out_api = None;
    let mut out_tools = None;
    let mut out_schema = None;
    let mut out_ids = None;
    let mut out_specs = None;
    let mut out_component = None;
    let mut out_rust = None;
    let mut out_rust_cbor = None;
    let mut out_manifest = None;
    let mut more_apis: Vec<String> = Vec::new();
    let mut out_console_catalog = None;
    let mut out_console_native = None;
    let mut out_console_native_rs = None;
    let mut out_api_json = None;
    let mut rustdoc_json = None;
    let mut pointer_width = 4u32;
    let mut autostart = None;
    let mut selected_method = None;
    let mut out_java = None;
    let mut java_package = None;
    let mut base_tools = None;
    let mut component = None;
    let mut check = false;
    let mut rust_tags = false;
    let mut vtable_conf = None;
    let mut out_vtable_schema = None;
    let mut out_vtable_shims = None;
    let mut out_tables_json = None;
    let mut tables_json = None;
    let mut xip_types = None;
    let mut out_xip_vtable = None;
    let mut out_xip_module = None;
    let mut xip_local_only = false;
    let mut xip_dispatch_only = false;
    let mut xip_methods: Option<String> = None;
    let mut xip_table_methods: Option<String> = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--api" => {
                let path = args.next().context("--api requires a path")?;
                if api.is_none() {
                    api = Some(path);
                } else {
                    more_apis.push(path);
                }
            }
            "--out-console-native" => out_console_native = Some(args.next().context("--out-console-native requires a path")?),
            "--out-console-native-rs" => out_console_native_rs = Some(args.next().context("--out-console-native-rs requires a path")?),
            "--out-console-catalog" => out_console_catalog = Some(args.next().context("--out-console-catalog requires a path")?),
            "--tools" => tools = Some(args.next().context("--tools requires a path")?),
            "--out-api" => out_api = Some(args.next().context("--out-api requires a path")?),
            "--out-tools" => out_tools = Some(args.next().context("--out-tools requires a path")?),
            "--out-schema" => {
                out_schema = Some(args.next().context("--out-schema requires a path")?)
            }
            "--out-ids" => out_ids = Some(args.next().context("--out-ids requires a path")?),
            "--out-specs" => out_specs = Some(args.next().context("--out-specs requires a path")?),
            "--out-component" => {
                out_component = Some(args.next().context("--out-component requires a path")?)
            }
            "--out-rust" => out_rust = Some(args.next().context("--out-rust requires a path")?),
            "--out-rust-cbor" => {
                out_rust_cbor = Some(args.next().context("--out-rust-cbor requires a path")?)
            }
            "--out-manifest" => {
                out_manifest = Some(args.next().context("--out-manifest requires a path")?)
            }
            "--out-api-json" => out_api_json = Some(args.next().context("--out-api-json requires a path")?),
            "--rustdoc" => rustdoc_json = Some(args.next().context("--rustdoc requires the path of a rustdoc JSON file")?),
            "--pointer-width" => pointer_width = args.next().context("--pointer-width requires bytes")?.parse().context("--pointer-width")?,
            "--autostart" => autostart = Some(args.next().context("--autostart requires a start request (may be empty)")?),
            "--method" => selected_method = Some(args.next().context("--method requires a name")?),
            "--out-java" => out_java = Some(args.next().context("--out-java requires a path")?),
            "--java-package" => {
                java_package = Some(args.next().context("--java-package requires a name")?)
            }
            "--base-tools" => {
                base_tools = Some(args.next().context("--base-tools requires a path")?)
            }
            "--component" => component = Some(args.next().context("--component requires a name")?),
            "--vtable-conf" => vtable_conf = Some(args.next().context("--vtable-conf requires a path")?),
            "--out-vtable-schema" => out_vtable_schema = Some(args.next().context("--out-vtable-schema requires a path")?),
            "--out-vtable-shims" => out_vtable_shims = Some(args.next().context("--out-vtable-shims requires a path")?),
            "--out-tables-json" => out_tables_json = Some(args.next().context("--out-tables-json requires a path")?),
            "--tables-json" => tables_json = Some(args.next().context("--tables-json requires a path")?),
            "--xip-types" => xip_types = Some(args.next().context("--xip-types requires a path")?),
            "--out-xip-vtable" => out_xip_vtable = Some(args.next().context("--out-xip-vtable requires a path")?),
            "--out-xip-module" => out_xip_module = Some(args.next().context("--out-xip-module requires a path")?),
            "--xip-local-only" => xip_local_only = true,
            "--xip-dispatch-only" => xip_dispatch_only = true,
            "--xip-methods" => xip_methods = Some(args.next().context("--xip-methods requires a list")?),
            "--xip-table-methods" => xip_table_methods = Some(args.next().context("--xip-table-methods requires a list")?),
            "--check" => check = true,
            "--rust-tags" => rust_tags = true,
            "--help" | "-h" => {
                println!(
                    "mesh-api-gen --api API.md [--base-tools tools.json] --out-tools tools.json --out-schema schema.json --out-ids ids.rs --out-rust src/api.rs [--rust-tags] [--api more/API.md ... --out-console-catalog catalog.h] [--out-console-native native.h --rustdoc crate.json] [--out-console-native-rs tables.rs --rustdoc crate.json] [--out-api-json api.json [--rustdoc crate.json] [--pointer-width 4]] [--out-manifest module.manifest [--autostart REQUEST]] [--java-package p] --out-java MeshApi.java [--check]\nmesh-api-gen --vtable-conf vtables.conf --rustdoc crate.json --out-tables-json tables.api.json\nmesh-api-gen --tables-json tables.api.json --out-vtable-schema schema_data.rs [--out-vtable-shims vt_shims.rs]\nmesh-api-gen --api API.md --xip-types types.rs [--out-xip-vtable component_vtable.rs] [--out-xip-module api_gen.rs] [--xip-local-only] [--xip-dispatch-only] [--xip-methods a,b] [--xip-table-methods a,b]\nmesh-api-gen --tools tools.json --component service --out-api migration.md"
                );
                return Ok(());
            }
            _ => bail!("unknown argument {argument}"),
        }
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
    // function tables: the Rust declarations into an api.json (--vtable-conf, --rustdoc, --out-tables-json), and from such an api.json the
    // schema and the module-side stubs (--tables-json, --out-vtable-schema, --out-vtable-shims)
    if let Some(conf) = vtable_conf {
        let catalog = mesh_api_gen::rustdoc::RustCatalog::from_rustdoc(
            &serde_json::from_str(&std::fs::read_to_string(rustdoc_json.context("--vtable-conf requires --rustdoc")?)?)?,
            pointer_width,
        )?;
        let config = mesh_api_gen::vtable::Config::parse(&std::fs::read_to_string(conf)?)?;
        let tables = mesh_api_gen::vtable::tables_json(&config, &catalog)?;
        let path = out_tables_json.context("--vtable-conf requires --out-tables-json")?;
        write_or_check(&path, &format!("{}\n", serde_json::to_string_pretty(&tables)?), check)?;
        return Ok(());
    }
    if let Some(file) = tables_json {
        let tables: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(file)?)?;
        let (schema, shims) = mesh_api_gen::vtable::generate(&tables, "mesh-api-gen")?;
        if let Some(path) = out_vtable_schema {
            write_or_check(&path, &schema, check)?;
        }
        if let Some(path) = out_vtable_shims {
            write_or_check(&path, &shims, check)?;
        }
        return Ok(());
    }
    let api = parse_required_path(api, "--api")?;
    let mut methods = parse_api_markdown(&std::fs::read_to_string(&api)?)?;
    if let Some(selected) = selected_method {
        methods.retain(|method| method.id == selected);
        if methods.is_empty() {
            bail!("API method not found: {selected}");
        }
    }
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
    if let Some(path) = out_specs {
        write_or_check(&path, &rust_specs(&methods), check)?;
    }
    if let Some(path) = out_component {
        write_or_check(&path, &rust_component(&methods), check)?;
    }
    if let Some(path) = out_rust {
        let generated = if rust_tags {
            rust_api_tagged(&methods)
        } else {
            rust_api(&methods)
        };
        write_or_check(&path, &generated, check)?;
    }
    if let Some(path) = out_rust_cbor {
        write_or_check(&path, &rust_cbor_api(&methods), check)?;
    }
    if let Some(path) = out_manifest {
        // binary CBOR, written as is (the check compares bytes)
        let bytes = manifest_cbor(&methods, autostart.as_deref())?;
        if check {
            if std::fs::read(&path).with_context(|| format!("read generated artifact {path}"))? != bytes {
                bail!("generated artifact is stale: {path}");
            }
        } else {
            if let Some(parent) = Path::new(&path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, bytes).with_context(|| format!("write generated artifact {path}"))?;
        }
    }
    if let Some(path) = out_console_catalog {
        let mut sources = vec![api.clone()];
        sources.extend(more_apis.iter().cloned());
        let mut parsed = vec![methods.clone()];
        for extra in &more_apis {
            parsed.push(parse_api_markdown(&std::fs::read_to_string(extra)?)?);
        }
        let names: Vec<String> = sources.iter().map(|s| s.rsplit('/').next().unwrap_or(s).to_owned()).collect();
        write_or_check(&path, &mesh_api_gen::console::console_catalog(&names, &parsed), check)?;
    }
    if out_console_native.is_some() || out_console_native_rs.is_some() {
        let catalog = match &rustdoc_json {
            Some(file) => mesh_api_gen::rustdoc::RustCatalog::from_rustdoc(
                &serde_json::from_str(&std::fs::read_to_string(file)?)?,
                pointer_width,
            )?,
            None => bail!("--out-console-native / --out-console-native-rs requires --rustdoc"),
        };
        let mut sources = vec![api.clone()];
        sources.extend(more_apis.iter().cloned());
        let mut documents = Vec::new();
        for source in &sources {
            let markdown = std::fs::read_to_string(source)?;
            documents.push(mesh_api_gen::apijson::api_json(
                &parse_api_markdown(&markdown)?,
                &mesh_api_gen::document::scan(&markdown)?,
                Some(&catalog),
            )?);
        }
        let names: Vec<String> = sources
            .iter()
            .map(|s| s.rsplit('/').next().unwrap_or(s).to_owned())
            .collect();
        if let Some(path) = out_console_native {
            write_or_check(
                &path,
                &mesh_api_gen::console::console_native(&documents, &names, u64::from(pointer_width))?,
                check,
            )?;
        }
        if let Some(path) = out_console_native_rs {
            write_or_check(
                &path,
                &mesh_api_gen::console::console_native_rs(&documents, &names, u64::from(pointer_width))?,
                check,
            )?;
        }
    }
    if out_xip_vtable.is_some() || out_xip_module.is_some() {
        let types_path = xip_types.as_deref().context("--out-xip-vtable / --out-xip-module requires --xip-types")?;
        let selected_methods = xip_table_methods
            .or(xip_methods)
            .map(|list| {
                list.split(',')
                    .map(|item| item.trim().to_owned())
                    .filter(|item| !item.is_empty())
                    .collect::<Vec<_>>()
            });
        let generated = mesh_api_gen::xip_vtable::generate_xip_vtable(
            Path::new(&api),
            Path::new(types_path),
            &mesh_api_gen::xip_vtable::XipVtableOptions {
                dispatch_only: xip_dispatch_only,
                local_only: xip_local_only,
                selected_methods,
            },
        )?;
        if let Some(path) = out_xip_vtable {
            let abi = generated
                .abi_rs
                .as_deref()
                .context("--out-xip-vtable cannot be used with --xip-dispatch-only")?;
            write_or_check(&path, abi, check)?;
        }
        if let Some(path) = out_xip_module {
            write_or_check(&path, &generated.module_rs, check)?;
        }
    }
    if let Some(path) = out_api_json {
        let markdown = std::fs::read_to_string(&api)?;
        let docs = mesh_api_gen::document::scan(&markdown)?;
        let catalog = match &rustdoc_json {
            Some(file) => Some(mesh_api_gen::rustdoc::RustCatalog::from_rustdoc(
                &serde_json::from_str(&std::fs::read_to_string(file)?)?,
                pointer_width,
            )?),
            None => None,
        };
        let generated = mesh_api_gen::apijson::api_json(&methods, &docs, catalog.as_ref())?;
        write_or_check(&path, &format!("{}\n", serde_json::to_string_pretty(&generated)?), check)?;
    }
    if let Some(path) = out_java {
        let class_name = java_class_name(&path)?;
        write_or_check(
            &path,
            &java_api(&methods, java_package.as_deref(), &class_name),
            check,
        )?;
    }
    Ok(())
}

/// Derive the generated Java class name from the output file stem, so the
/// class follows the artifact file the way generated Rust does.
fn java_class_name(path: &str) -> Result<String> {
    let stem = Path::new(path)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .context("--out-java requires a file name")?;
    let class: String = stem
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut characters = part.chars();
            match characters.next() {
                Some(first) => format!("{}{}", first.to_ascii_uppercase(), characters.as_str()),
                None => String::new(),
            }
        })
        .collect();
    if class.is_empty() {
        bail!("--out-java file stem {stem:?} has no usable class name");
    }
    Ok(class)
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
