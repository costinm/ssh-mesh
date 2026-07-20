//! Compact, schema-guided CBOR records for mesh transports.
//!
//! A record has a compact envelope map and a nested payload map. JSON-RPC's
//! `jsonrpc`, `params`, and `result` wrappers are not part of this wire format.

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use minicbor::{Decoder, Encoder, data::Type};
use serde_json::{Map, Number, Value};

use crate::mux::{MESH_META_RPC, decode_frame};
use crate::tagged::{NameOrTag, TaggedRecord};

pub const STREAM_TYPE: [u8; 4] = MESH_META_RPC.0;
pub const STREAM_HEADER_LEN: usize = 8;
pub const MAX_RECORD_LEN: usize = 64 * 1024;
pub const ESP_RECORD_MAX: usize = 512;
pub const METHOD: u16 = 0;
pub const ID: u16 = 1;
pub const FROM: u16 = 2;
pub const TO: u16 = 3;
pub const STATUS: u16 = 4;
pub const ERROR: u16 = 5;
pub const PAYLOAD: u16 = 6;
pub const TYPE: u16 = 7;
pub const SEQ: u16 = 8;
pub const TS_MS: u16 = 9;
pub const NAME: u16 = 10;
pub const FLAGS: u16 = 11;
pub const COUNT: u16 = 12;
pub const TOTAL: u16 = 13;
pub const MORE: u16 = 14;
pub const CODE: u16 = 15;
pub const SEGMENT_ID: u16 = 32;
pub const SEGMENT_OFFSET: u16 = 33;
pub const SEGMENT_TOTAL: u16 = 34;
pub const SEGMENT_HASH: u16 = 35;
pub const SEGMENT_INDEX: u16 = 36;
pub const SEGMENT_COUNT: u16 = 37;
pub const SEGMENT_METHOD: u16 = 0;

const COMMON: &[(u16, &str)] = &[
    (METHOD, "method"),
    (ID, "id"),
    (FROM, "from"),
    (TO, "to"),
    (STATUS, "status"),
    (ERROR, "error"),
    (PAYLOAD, "payload"),
    (TYPE, "type"),
    (SEQ, "seq"),
    (TS_MS, "ts_ms"),
    (NAME, "name"),
    (FLAGS, "flags"),
    (COUNT, "count"),
    (TOTAL, "total"),
    (MORE, "more"),
    (SEGMENT_ID, "segment_id"),
    (SEGMENT_OFFSET, "segment_offset"),
    (SEGMENT_TOTAL, "segment_total"),
    (SEGMENT_HASH, "segment_hash"),
    (SEGMENT_INDEX, "segment_index"),
    (SEGMENT_COUNT, "segment_count"),
    (CODE, "code"),
];

/// Encode the format-neutral gateway record. Root keys are deliberately
/// one-based so the same schema IDs are valid protobuf field numbers.
pub fn encode_record(record: &TaggedRecord) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    let fields = 2
        + usize::from(record.id.is_some())
        + usize::from(!record.params.is_empty())
        + usize::from(!record.env.is_empty());
    encoder.map(fields as u64)?;
    encoder.u8(1)?;
    encode_name_or_tag(&mut encoder, &record.component)?;
    encoder.u8(2)?;
    encode_name_or_tag(&mut encoder, &record.method)?;
    if let Some(id) = &record.id {
        encoder.u8(3)?;
        encode_value(&mut encoder, id)?;
    }
    if !record.params.is_empty() {
        encoder.u8(4)?.array(record.params.len() as u64)?;
        for value in &record.params {
            encode_value(&mut encoder, value)?;
        }
    }
    if !record.env.is_empty() {
        encoder.u8(5)?.map(record.env.len() as u64)?;
        for (key, value) in &record.env {
            encode_name_or_tag(&mut encoder, key)?;
            encode_value(&mut encoder, value)?;
        }
    }
    Ok(bytes)
}

/// Decode a gateway record without requiring a schema. Unknown numeric names
/// remain numeric and become `@N` only in text/JSON adapters.
pub fn decode_record(bytes: &[u8]) -> Result<TaggedRecord> {
    let mut decoder = Decoder::new(bytes);
    let value = decode_value(&mut decoder)?;
    if decoder.position() != bytes.len() {
        bail!("trailing CBOR data");
    }
    let root = value
        .as_object()
        .ok_or_else(|| anyhow!("record must be a CBOR map"))?;
    let component = decode_name_or_tag(
        root.get("1")
            .ok_or_else(|| anyhow!("record lacks component"))?,
    )?;
    let method = decode_name_or_tag(
        root.get("2")
            .ok_or_else(|| anyhow!("record lacks method"))?,
    )?;
    let params = root
        .get("4")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut env = BTreeMap::new();
    if let Some(values) = root.get("5").and_then(Value::as_object) {
        for (key, value) in values {
            env.insert(NameOrTag::parse(key), value.clone());
        }
    }
    Ok(TaggedRecord {
        component,
        method,
        id: root.get("3").cloned(),
        params,
        env,
    })
}

fn encode_name_or_tag(encoder: &mut Encoder<&mut Vec<u8>>, value: &NameOrTag) -> Result<()> {
    match value {
        NameOrTag::Name(value) => encoder.str(value)?,
        NameOrTag::Tag(value) => encoder.u32(*value)?,
    };
    Ok(())
}

fn decode_name_or_tag(value: &Value) -> Result<NameOrTag> {
    match value {
        Value::String(value) => Ok(NameOrTag::parse(value)),
        Value::Number(value) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(NameOrTag::Tag)
            .ok_or_else(|| anyhow!("invalid numeric tag")),
        _ => bail!("name/tag must be text or integer"),
    }
}

/// Numeric tags loaded from a curated `tools.json` catalog.
#[derive(Clone, Debug, Default)]
pub struct Catalog {
    methods: BTreeMap<String, u16>,
    method_names: BTreeMap<u16, String>,
    fields: BTreeMap<String, BTreeMap<String, u16>>,
}

impl Catalog {
    /// Build a catalog from either the legacy array or `{ "tools": [...] }` form.
    pub fn from_tools_json(value: &Value) -> Result<Self> {
        let tools = value
            .get("tools")
            .and_then(Value::as_array)
            .or_else(|| value.as_array())
            .ok_or_else(|| anyhow!("tools catalog must be an array or object with tools"))?;
        let mut catalog = Self::default();
        for tool in tools {
            let Some(name) = tool.get("name").and_then(Value::as_str) else {
                continue;
            };
            let annotation = tool.get("x-mesh-cbor").or_else(|| tool.get("x-cbor"));
            let Some(annotation) = annotation else {
                continue;
            };
            if let Some(id) = annotation.get("id").and_then(Value::as_u64) {
                let id = u16::try_from(id).context("CBOR method id exceeds u16")?;
                catalog.methods.insert(name.to_owned(), id);
                catalog.method_names.insert(id, name.to_owned());
            }
            if let Some(properties) = tool
                .pointer("/inputSchema/properties")
                .and_then(Value::as_object)
            {
                let fields = catalog.fields.entry(name.to_owned()).or_default();
                for (field, schema) in properties {
                    if let Some(id) = schema
                        .get("x-mesh-cbor")
                        .and_then(|x| x.get("id"))
                        .and_then(Value::as_u64)
                    {
                        fields.insert(
                            field.clone(),
                            u16::try_from(id).context("CBOR field id exceeds u16")?,
                        );
                    }
                }
            }
        }
        Ok(catalog)
    }
}

#[derive(Clone, Debug)]
enum Key {
    Num(u16),
    Text(String),
}

/// Convert JSON or JSON-RPC to a compact envelope and nested payload record.
pub fn encode_json(value: &Value, catalog: &Catalog) -> Result<Vec<u8>> {
    let object = flatten(value)?;
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut encoded = Vec::new();
    let mut encoder = Encoder::new(&mut encoded);
    // Indefinite maps permit a gateway to stream a payload without first
    // materialising it merely to calculate its map length.
    encoder.begin_map()?;
    for (id, name) in COMMON {
        if *id == PAYLOAD {
            continue;
        }
        if let Some(value) = object.get(*name) {
            encoder.u16(*id)?;
            if *id == METHOD {
                if let Some(name) = value.as_str() {
                    if let Some(id) = catalog.methods.get(name) {
                        encoder.u16(*id)?;
                        continue;
                    }
                }
            }
            encode_value(&mut encoder, value)?;
        }
    }
    encoder.u16(PAYLOAD)?.begin_map()?;
    for (name, value) in &object {
        if COMMON.iter().any(|(_, common)| *common == name) {
            continue;
        }
        match catalog
            .fields
            .get(method.as_deref().unwrap_or_default())
            .and_then(|fields| fields.get(name))
        {
            Some(id) => encoder.u16(*id)?,
            None => encoder.str(name)?,
        };
        encode_value(&mut encoder, value)?;
    }
    if let Some(value) = object.get("payload") {
        encoder.str("data")?;
        encode_value(&mut encoder, value)?;
    }
    encoder.end()?.end()?;
    if encoded.len() > MAX_RECORD_LEN {
        bail!("CBOR record exceeds {MAX_RECORD_LEN} bytes");
    }
    Ok(encoded)
}

/// Decode a compact CBOR envelope to a JSON object with a nested `payload`.
pub fn decode_json(bytes: &[u8], catalog: &Catalog) -> Result<Value> {
    if bytes.len() > MAX_RECORD_LEN {
        bail!("CBOR record exceeds {MAX_RECORD_LEN} bytes");
    }
    let mut decoder = Decoder::new(bytes);
    let root = decode_value(&mut decoder)?;
    if decoder.position() != bytes.len() {
        bail!("trailing CBOR data");
    }
    let root = root
        .as_object()
        .ok_or_else(|| anyhow!("CBOR record must be a map"))?;
    let mut object = Map::new();
    let method = root.get(&METHOD.to_string()).and_then(|value| match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => value
            .as_u64()
            .and_then(|id| catalog.method_names.get(&(id as u16)).cloned()),
        _ => None,
    });
    for (id, name) in COMMON {
        if *id == PAYLOAD {
            continue;
        }
        if let Some(value) = root.get(&id.to_string()) {
            object.insert((*name).to_owned(), value.clone());
        }
    }
    if let Some(ref method) = method {
        object.insert("method".to_owned(), Value::String(method.clone()));
    }
    let payload = root
        .get(&PAYLOAD.to_string())
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let payload = rename_payload(payload, method.as_deref(), catalog)?;
    object.insert("payload".to_owned(), payload);
    Ok(Value::Object(object))
}

fn rename_payload(value: Value, method: Option<&str>, catalog: &Catalog) -> Result<Value> {
    let Value::Object(values) = value else {
        bail!("CBOR payload must be a map");
    };
    let mut payload = Map::new();
    for (key, value) in values {
        let name = key
            .parse::<u16>()
            .ok()
            .and_then(|id| {
                method
                    .and_then(|method| catalog.fields.get(method))
                    .and_then(|fields| {
                        fields
                            .iter()
                            .find(|(_, value)| **value == id)
                            .map(|(name, _)| name.clone())
                    })
            })
            .unwrap_or(key);
        payload.insert(name, value);
    }
    Ok(Value::Object(payload))
}

/// Add the stream-only length/type envelope. Radio payloads use CBOR directly.
pub fn encode_stream_frame(cbor: &[u8]) -> Result<Vec<u8>> {
    let len = STREAM_TYPE.len() + cbor.len();
    if len > MAX_RECORD_LEN {
        bail!("stream frame exceeds {MAX_RECORD_LEN} bytes");
    }
    Ok(crate::mux::build_frame(MESH_META_RPC, cbor))
}

/// Return the CBOR payload from one complete stream frame.
pub fn decode_stream_frame(frame: &[u8]) -> Result<&[u8]> {
    let (meta, payload) = decode_frame(frame)?;
    if frame.len() - 4 > MAX_RECORD_LEN {
        bail!("stream frame exceeds {MAX_RECORD_LEN} bytes");
    }
    if meta != MESH_META_RPC {
        bail!("not a mesh CBOR stream frame");
    }
    Ok(payload)
}

fn flatten(value: &Value) -> Result<Map<String, Value>> {
    let source = value
        .as_object()
        .ok_or_else(|| anyhow!("CBOR input must be a JSON object"))?;
    let mut flat = Map::new();
    for (key, value) in source {
        if key == "jsonrpc" {
            continue;
        }
        if (key == "params" || key == "result") && value.is_object() {
            for (name, item) in value.as_object().unwrap() {
                flat.insert(name.clone(), item.clone());
            }
        } else {
            flat.insert(key.clone(), value.clone());
        }
    }
    Ok(flat)
}

fn encode_value(encoder: &mut Encoder<&mut Vec<u8>>, value: &Value) -> Result<()> {
    match value {
        Value::Null => {
            encoder.null()?;
        }
        Value::Bool(value) => {
            encoder.bool(*value)?;
        }
        Value::Number(value) => {
            if let Some(value) = value.as_u64() {
                encoder.u64(value)?;
            } else if let Some(value) = value.as_i64() {
                encoder.i64(value)?;
            } else {
                encoder.f64(value.as_f64().unwrap())?;
            }
        }
        Value::String(value) => {
            encoder.str(value)?;
        }
        Value::Array(values) => {
            encoder.array(values.len() as u64)?;
            for value in values {
                encode_value(encoder, value)?;
            }
        }
        Value::Object(values) => {
            encoder.map(values.len() as u64)?;
            for (key, value) in values {
                encoder.str(key)?;
                encode_value(encoder, value)?;
            }
        }
    }
    Ok(())
}

fn decode_key(decoder: &mut Decoder<'_>) -> Result<Key> {
    match decoder.datatype()? {
        Type::U8 | Type::U16 | Type::U32 => Ok(Key::Num(
            u16::try_from(decoder.u32()?).context("CBOR map key exceeds u16")?,
        )),
        Type::String => Ok(Key::Text(decoder.str()?.to_owned())),
        value => bail!("unsupported CBOR map key {value:?}"),
    }
}

fn decode_value(decoder: &mut Decoder<'_>) -> Result<Value> {
    Ok(match decoder.datatype()? {
        Type::Null => {
            decoder.null()?;
            Value::Null
        }
        Type::Bool => Value::Bool(decoder.bool()?),
        Type::U8 | Type::U16 | Type::U32 => Value::Number(Number::from(decoder.u64()?)),
        Type::U64 => Value::Number(Number::from(decoder.u64()?)),
        Type::I8 | Type::I16 | Type::I32 | Type::I64 | Type::Int => {
            Value::Number(Number::from(decoder.i64()?))
        }
        Type::F16 | Type::F32 | Type::F64 => Number::from_f64(decoder.f64()?)
            .map(Value::Number)
            .ok_or_else(|| anyhow!("non-finite CBOR float"))?,
        Type::String => Value::String(decoder.str()?.to_owned()),
        Type::Bytes => Value::String(format!("base64:{}", base64(decoder.bytes()?))),
        Type::Array | Type::ArrayIndef => {
            let count = decoder.array()?;
            let mut out = Vec::new();
            while count
                .map(|count| out.len() < count as usize)
                .unwrap_or_else(|| decoder.datatype().ok() != Some(Type::Break))
            {
                out.push(decode_value(decoder)?);
            }
            if count.is_none() {
                decoder.skip()?;
            }
            Value::Array(out)
        }
        Type::Map | Type::MapIndef => {
            let count = decoder.map()?;
            let mut out = Map::new();
            while count
                .map(|count| out.len() < count as usize)
                .unwrap_or_else(|| decoder.datatype().ok() != Some(Type::Break))
            {
                let key = match decode_key(decoder)? {
                    Key::Num(id) => id.to_string(),
                    Key::Text(key) => key,
                };
                out.insert(key, decode_value(decoder)?);
            }
            if count.is_none() {
                decoder.skip()?;
            }
            Value::Object(out)
        }
        value => bail!("unsupported CBOR value {value:?}"),
    })
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(TABLE[((value >> 18) & 63) as usize] as char);
        out.push(TABLE[((value >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn jsonrpc_is_flattened_and_stream_framed() {
        let input =
            json!({"jsonrpc":"2.0","id":7,"method":"wifi.status","params":{"iface":"wlan0"}});
        let cbor = encode_json(&input, &Catalog::default()).unwrap();
        assert_eq!(
            decode_json(&cbor, &Catalog::default()).unwrap(),
            json!({"id":7,"method":"wifi.status","payload":{"iface":"wlan0"}})
        );
        let frame = encode_stream_frame(&cbor).unwrap();
        assert_eq!(decode_stream_frame(&frame).unwrap(), cbor.as_slice());
    }
}
