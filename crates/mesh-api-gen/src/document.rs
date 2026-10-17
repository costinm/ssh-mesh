//! The parts of an `API.md` that the method model of `parse_api_markdown` drops: prose, field descriptions, enums and the
//! `**C type:**` / `**C function:**` links to a native layout. They are scanned separately, line by line, with the same
//! heading rules, and joined to the methods by name when `api.json` is built.

use std::collections::BTreeMap;

use anyhow::{Result, bail};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnumValue {
    pub value: i64,
    pub name: String,
    pub description: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnumDoc {
    pub name: String,
    pub doc: String,
    pub values: Vec<EnumValue>,
}

/// Everything in an `API.md` that is not the method structure.
#[derive(Clone, Debug, Default)]
pub struct DocIndex {
    /// Component name -> the text between its heading and its first method.
    pub component_docs: BTreeMap<String, String>,
    /// `component.method` -> prose of the method (without metadata lines and field tables).
    pub method_docs: BTreeMap<String, String>,
    /// Named record -> prose.
    pub record_docs: BTreeMap<String, String>,
    pub enums: Vec<EnumDoc>,
    /// Field table owner -> field -> description. Owners: `method#request`, `method#response`, `type:Name`, `row:Name`.
    pub descriptions: BTreeMap<String, BTreeMap<String, String>>,
    /// `component.method` -> `component/Table.field` of its `**C function:**` line.
    pub c_functions: BTreeMap<String, String>,
    /// Named record -> the native type of its `**C type:**` line.
    pub c_types: BTreeMap<String, String>,
    /// `component.method` -> the named type of its `**Request:**` / `**Response:**` line.
    pub request_types: BTreeMap<String, String>,
    pub response_types: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Section {
    None,
    Component(String),
    Method(String),
    Record(String),
    Enum(usize),
}

fn cells(line: &str) -> Vec<String> {
    line.trim().trim_matches('|').split('|').map(|c| c.trim().to_owned()).collect()
}

fn unquote(value: &str) -> String {
    value.trim().trim_matches('`').to_owned()
}

fn type_ref(value: &str) -> Option<String> {
    let inner = value.trim().strip_prefix('[')?.split_once(']')?.0;
    Some(inner.trim_matches('`').to_owned())
}

fn append(target: &mut String, line: &str) {
    target.push_str(line);
    target.push('\n');
}

pub fn scan(markdown: &str) -> Result<DocIndex> {
    let lines: Vec<&str> = markdown.lines().collect();
    let mut index = DocIndex::default();
    let mut component = String::new();
    let mut in_types = false;
    let mut section = Section::None;
    let mut sub: Option<&'static str> = None; // request, response, errors, doc
    let mut row: Option<String> = None;
    let mut fence = false;
    let mut docs: BTreeMap<Section, String> = BTreeMap::new();
    let mut i = 0;
    while i < lines.len() {
        let raw = lines[i];
        let line = raw.trim();
        if line.starts_with("```") {
            fence = !fence;
            if let Some(target) = doc_target(&section, sub, &mut docs) {
                append(target, raw);
            }
            i += 1;
            continue;
        }
        if fence {
            if let Some(target) = doc_target(&section, sub, &mut docs) {
                append(target, raw);
            }
            i += 1;
            continue;
        }
        if let Some(value) = line.strip_prefix("# ") {
            if let Some((name, _)) = value.split_once("` API") {
                component = name.trim().trim_matches('`').to_owned();
                section = Section::Component(component.clone());
                in_types = false;
                sub = None;
                row = None;
                i += 1;
                continue;
            }
            if value.trim() == "Types" {
                in_types = true;
                section = Section::None;
                sub = None;
                row = None;
                i += 1;
                continue;
            }
        }
        if let Some(value) = line.strip_prefix("## ") {
            sub = None;
            row = None;
            if let Some(rest) = value.strip_prefix("enum ") {
                index.enums.push(EnumDoc { name: unquote(rest), ..Default::default() });
                section = Section::Enum(index.enums.len() - 1);
            } else if value.contains(" — ") || value.contains(". `") || (!in_types && value.trim().starts_with('`')) {
                let before = value.split_once(" — ").map_or(value, |(b, _)| b);
                let name = before.rsplit_once(". `").map_or(before, |(_, n)| n);
                section = Section::Method(format!("{component}.{}", unquote(name)));
            } else {
                section = Section::Record(unquote(value));
            }
            i += 1;
            continue;
        }
        if let Some(value) = line.strip_prefix("### ") {
            sub = match value.trim() {
                "Request" => Some("request"),
                "Response" => Some("response"),
                "Errors" => Some("errors"),
                _ => Some("doc"),
            };
            if sub == Some("doc") {
                if let Some(target) = doc_target(&section, sub, &mut docs) {
                    append(target, raw);
                }
            }
            i += 1;
            continue;
        }
        if let Some(name) = line.strip_suffix(" fields:") {
            row = Some(unquote(name));
            i += 1;
            continue;
        }
        if let Some(rest) = line.strip_prefix("**") {
            if let Some((key, value)) = rest.split_once(":**") {
                let value = value.trim();
                match (key, &section) {
                    ("C function", Section::Method(id)) => {
                        index.c_functions.insert(id.clone(), unquote(value));
                    }
                    ("C type", Section::Record(name)) => {
                        index.c_types.insert(name.clone(), unquote(value));
                    }
                    ("Request", Section::Method(id)) => {
                        if let Some(name) = type_ref(value) {
                            index.request_types.insert(id.clone(), name);
                        }
                    }
                    ("Response", Section::Method(id)) => {
                        if let Some(name) = type_ref(value) {
                            index.response_types.insert(id.clone(), name);
                        }
                    }
                    _ => {}
                }
                if key != "Note" {
                    i += 1;
                    continue;
                }
            }
        }
        if line.starts_with('|') {
            let header = cells(line);
            let start = i;
            let mut end = i + 2;
            while end < lines.len() && lines[end].trim_start().starts_with('|') {
                end += 1;
            }
            let has = |name: &str| header.iter().position(|h| h == name);
            if let (Some(tag), Some(field)) = (has("Tag"), has("Field")) {
                let _ = tag;
                let owner = match (&section, sub, &row) {
                    (Section::Method(_), _, Some(row)) => format!("row:{row}"),
                    (Section::Method(id), Some("request"), _) => format!("{id}#request"),
                    (Section::Method(id), Some("response"), _) => format!("{id}#response"),
                    (Section::Record(name), _, _) => format!("type:{name}"),
                    _ => String::new(),
                };
                if !owner.is_empty() {
                    let description = has("Description");
                    for line in &lines[start + 2..end] {
                        let row = cells(line);
                        let name = unquote(row.get(field).map_or("", String::as_str));
                        let text = description.and_then(|d| row.get(d)).cloned().unwrap_or_default();
                        index.descriptions.entry(owner.clone()).or_default().insert(name, text);
                    }
                }
                if matches!(section, Section::Method(_)) {
                    row = None;
                }
            } else if let (Some(value), Some(name), Section::Enum(n)) = (has("Value"), has("Name"), &section) {
                let description = has("Description");
                for line in &lines[start + 2..end] {
                    let row = cells(line);
                    let number = row.get(value).map_or("", String::as_str);
                    let Ok(number) = number.parse() else {
                        bail!("enum value is not a number: {line}");
                    };
                    index.enums[*n].values.push(EnumValue {
                        value: number,
                        name: unquote(row.get(name).map_or("", String::as_str)),
                        description: description.and_then(|d| row.get(d)).cloned().unwrap_or_default(),
                    });
                }
            }
            i = end;
            continue;
        }
        if let Some(target) = doc_target(&section, sub, &mut docs) {
            append(target, raw);
        }
        i += 1;
    }
    for (section, text) in docs {
        let text = text.trim().to_owned();
        match section {
            Section::Component(name) => {
                index.component_docs.insert(name, text);
            }
            Section::Method(id) => {
                index.method_docs.insert(id, text);
            }
            Section::Record(name) => {
                index.record_docs.insert(name, text);
            }
            Section::Enum(n) => index.enums[n].doc = text,
            Section::None => {}
        }
    }
    Ok(index)
}

/// Where a prose line goes, if anywhere: the tail of a method after `### Request/Response/Errors` is structure, not prose.
fn doc_target<'a>(section: &Section, sub: Option<&str>, docs: &'a mut BTreeMap<Section, String>) -> Option<&'a mut String> {
    if matches!(sub, Some("request" | "response" | "errors")) || *section == Section::None {
        return None;
    }
    Some(docs.entry(section.clone()).or_default())
}

impl PartialOrd for Section {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Section {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let key = |s: &Section| match s {
            Section::None => (0, String::new(), 0),
            Section::Component(n) => (1, n.clone(), 0),
            Section::Method(n) => (2, n.clone(), 0),
            Section::Record(n) => (3, n.clone(), 0),
            Section::Enum(i) => (4, String::new(), *i),
        };
        key(self).cmp(&key(other))
    }
}
