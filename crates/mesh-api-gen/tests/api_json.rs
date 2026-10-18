//! `api.json`: documents, enums and the native layout joined to the API of `tests/data/api-json-demo-API.md`.
use mesh_api_gen::{apijson::api_json, document::scan, parse_api_markdown, rustdoc::RustCatalog};
use serde_json::{Value, json};

const API: &str = include_str!("data/api-json-demo-API.md");

/// What rustdoc writes for `#[repr(C)] pub struct Item { pub name: [u8; 8], pub name_len: u8, pub mode: u8 }` and
/// `#[repr(C)] pub struct Table { pub version: u32, pub size: u32, pub set: Option<unsafe extern "C" fn(ctx: *mut c_void, item: *const Item, generation: *mut u32) -> c_int> }`.
fn rustdoc(mode_type: &str) -> Value {
    let repr = json!([{"repr": {"kind": "c", "align": null, "packed": null, "int": null}}]);
    let field = |name: &str, ty: Value| json!({"name": name, "docs": format!("The {name}."), "inner": {"struct_field": ty}});
    json!({
        "format_version": 57,
        "index": {
            "1": {"name": "Item", "visibility": "public", "docs": "", "attrs": repr, "inner": {"struct": {"kind": {"plain": {"fields": [2, 3, 4]}}}}},
            "2": field("name", json!({"array": {"type": {"primitive": "u8"}, "len": "8"}})),
            "3": field("name_len", json!({"primitive": "u8"})),
            "4": field("mode", json!({"primitive": mode_type})),
            "5": {"name": "Table", "visibility": "public", "docs": "", "attrs": repr, "inner": {"struct": {"kind": {"plain": {"fields": [7, 8, 6]}}}}},
            "7": field("version", json!({"primitive": "u32"})),
            "8": field("size", json!({"primitive": "u32"})),
            "6": field("set", json!({"resolved_path": {"path": "Option", "id": 9, "args": {"angle_bracketed": {"args": [{"type": {"function_pointer": {"sig": {"inputs": [
                ["ctx", {"raw_pointer": {"is_mutable": true, "type": {"resolved_path": {"path": "core::ffi::c_void", "id": 8, "args": null}}}}],
                ["item", {"raw_pointer": {"is_mutable": false, "type": {"resolved_path": {"path": "Item", "id": 1, "args": null}}}}],
                ["generation", {"raw_pointer": {"is_mutable": true, "type": {"primitive": "u32"}}}]
            ], "output": null}}}}]}}}})),
        }
    })
}

fn build(mode_type: &str) -> anyhow::Result<Value> {
    let methods = parse_api_markdown(API)?;
    let docs = scan(API)?;
    let catalog = RustCatalog::from_rustdoc(&rustdoc(mode_type), 4)?;
    api_json(&methods, &docs, Some(&catalog))
}

#[test]
fn the_document_is_joined_to_the_native_layout() {
    let api = build("u8").unwrap();
    assert_eq!(api["format"], "mesh-api/1");
    let method = &api["methods"][0];
    assert_eq!(method["name"], "demo.set");
    assert!(method["doc"].as_str().unwrap().starts_with("Stores `value`"));
    assert_eq!(method["request"]["type"], "Item");
    assert_eq!(method["x-c"]["member"], "set");
    assert_eq!(method["x-c"]["offset"], 8);
    assert_eq!(method["x-c"]["params"][1]["role"], "in");
    let item = api["types"].as_array().unwrap().iter().find(|t| t["name"] == "Item").unwrap();
    assert_eq!(item["x-c"]["size"], 10);
    assert_eq!(item["doc"], "An item.");
    // the description falls back to the Rust doc, the length field is found
    assert_eq!(item["fields"][1]["description"], "The mode.");
    assert_eq!(item["fields"][0]["x-c"]["len_field"]["name"], "name_len");
    let mode = api["types"].as_array().unwrap().iter().find(|t| t["name"] == "Mode").unwrap();
    assert_eq!(mode["values"][1]["name"], "on");
}

#[test]
fn a_field_that_does_not_fit_the_native_type_is_an_error() {
    let error = build("u64").unwrap_err().to_string();
    assert!(error.contains("disagree") && error.contains("Item.mode"), "{error}");
}

#[test]
fn the_json_is_the_same_every_time() {
    assert_eq!(build("u8").unwrap().to_string(), build("u8").unwrap().to_string());
}

#[test]
fn the_native_header_names_the_slot_and_the_layout() {
    let api = build("u8").unwrap();
    let header = mesh_api_gen::console::console_native(&[api], &["demo".to_owned()], 4).unwrap();
    // demo.set is component 7, method 1, in slot 0 of the table `demo` (right after the 8-byte header), 3 parameters
    assert!(header.contains("{7,1,1,0,0,3}"), "{header}");
    // the struct (no size header): 10 bytes, a text field with its length field, a one-byte enum
    assert!(header.contains("{10,0,2}"), "{header}");
    assert!(header.contains("{1,0,8,3,1,8,0}"), "{header}");
}
