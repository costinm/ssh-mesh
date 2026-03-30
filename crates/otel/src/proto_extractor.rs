use std::collections::HashMap;
use std::fmt;

// Re-use the varint decoder from perfetto_pull
use crate::perfetto_pull::decode_varint;

/// Extracted protobuf value - can be numeric or string/bytes.
#[derive(Debug, Clone, PartialEq)]
pub enum ProtoValue {
    Varint(u64),
    Fixed64(u64),
    Fixed32(u32),
    Bytes(Vec<u8>),
    String(String),
}

impl ProtoValue {
    /// Interpret as i64 for comparison purposes.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            ProtoValue::Varint(v) => Some(*v as i64),
            ProtoValue::Fixed64(v) => Some(*v as i64),
            ProtoValue::Fixed32(v) => Some(*v as i64),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            ProtoValue::String(s) => Some(s),
            _ => None,
        }
    }
}

impl fmt::Display for ProtoValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtoValue::Varint(v) => write!(f, "{}", v),
            ProtoValue::Fixed64(v) => write!(f, "{}", v),
            ProtoValue::Fixed32(v) => write!(f, "{}", v),
            ProtoValue::Bytes(b) => write!(f, "{:?}", b),
            ProtoValue::String(s) => write!(f, "{}", s),
        }
    }
}

/// Comparison operator for rule conditions.
#[derive(Debug, Clone, PartialEq)]
pub enum Operator {
    Less,
    Greater,
    Equal,
}

/// A single condition: "path operator value".
#[derive(Debug, Clone)]
pub struct Condition {
    pub path: Vec<u32>,
    pub operator: Operator,
    pub value: String,
}

impl Condition {
    /// Parse from "1.2.3 < 100" format.
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(format!("Expected 'PATH OP VALUE', got: {}", s));
        }
        let path = parse_path(parts[0])?;
        let operator = match parts[1] {
            "<" => Operator::Less,
            ">" => Operator::Greater,
            "=" => Operator::Equal,
            other => return Err(format!("Unknown operator: {}", other)),
        };
        Ok(Condition {
            path,
            operator,
            value: parts[2].to_string(),
        })
    }

    /// Evaluate this condition against an extracted value.
    pub fn evaluate(&self, val: &ProtoValue) -> bool {
        // Try numeric comparison first
        if let Some(extracted_num) = val.as_i64() {
            if let Ok(cond_num) = self.value.parse::<i64>() {
                return match self.operator {
                    Operator::Less => extracted_num < cond_num,
                    Operator::Greater => extracted_num > cond_num,
                    Operator::Equal => extracted_num == cond_num,
                };
            }
        }
        // Fall back to string comparison
        let extracted_str = val.to_string();
        match self.operator {
            Operator::Equal => extracted_str == self.value,
            Operator::Less => extracted_str < self.value,
            Operator::Greater => extracted_str > self.value,
        }
    }
}

/// A rule: when all conditions match, the action fires.
#[derive(Debug, Clone)]
pub struct Rule {
    pub action: String,
    pub conditions: Vec<Condition>,
}

/// Index of a rule within ProtoExtractor's rules vec.
type RuleIdx = usize;
/// Index of a condition within a Rule's conditions vec.
type CondIdx = usize;

/// A node in the tag-path trie. Children are keyed by proto field number.
#[derive(Debug, Default)]
struct TrieNode {
    children: HashMap<u32, TrieNode>,
    /// If this node is a leaf for extraction, the field name.
    extract_name: Option<String>,
    /// Conditions that reference this exact path: (rule_idx, cond_idx).
    condition_refs: Vec<(RuleIdx, CondIdx)>,
}

/// Action handler type.
pub type ActionFn = Box<dyn Fn(&str, &HashMap<String, ProtoValue>) + Send + Sync>;

/// Main extractor: holds a trie of paths, rules, and action handlers.
pub struct ProtoExtractor {
    root: TrieNode,
    rules: Vec<Rule>,
    actions: HashMap<String, ActionFn>,
}

impl Default for ProtoExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtoExtractor {
    pub fn new() -> Self {
        let mut actions: HashMap<String, ActionFn> = HashMap::new();
        actions.insert(
            "LOG".to_string(),
            Box::new(|action, values| {
                let pairs: Vec<String> =
                    values.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
                tracing::info!(action = action, "Rule fired: {}", pairs.join(", "));
            }),
        );
        ProtoExtractor {
            root: TrieNode::default(),
            rules: Vec::new(),
            actions,
        }
    }

    /// Register a custom action handler.
    pub fn register_action<F>(&mut self, name: &str, f: F)
    where
        F: Fn(&str, &HashMap<String, ProtoValue>) + Send + Sync + 'static,
    {
        self.actions.insert(name.to_string(), Box::new(f));
    }

    /// Add an extractor: a dot-separated tag path and a name for the extracted value.
    pub fn add_extractor(&mut self, path_str: &str, name: &str) -> Result<(), String> {
        let path = parse_path(path_str)?;
        let node = self.get_or_create_node(&path);
        node.extract_name = Some(name.to_string());
        Ok(())
    }

    /// Add a rule with an action and a list of condition strings ("PATH OP VALUE").
    pub fn add_rule(&mut self, action: &str, condition_strs: &[&str]) -> Result<(), String> {
        let conditions: Vec<Condition> = condition_strs
            .iter()
            .map(|s| Condition::parse(s))
            .collect::<Result<Vec<_>, _>>()?;

        let rule_idx = self.rules.len();
        // Register each condition's path in the trie
        for (cond_idx, cond) in conditions.iter().enumerate() {
            let node = self.get_or_create_node(&cond.path);
            node.condition_refs.push((rule_idx, cond_idx));
        }
        self.rules.push(Rule {
            action: action.to_string(),
            conditions,
        });
        Ok(())
    }

    fn get_or_create_node(&mut self, path: &[u32]) -> &mut TrieNode {
        let mut current = &mut self.root;
        for &tag in path {
            current = current.children.entry(tag).or_default();
        }
        current
    }

    /// Process a single protobuf message (no schema). Returns extracted values map
    /// and fires any rules whose conditions are all satisfied.
    pub fn handle_message(&self, data: &[u8]) -> HashMap<String, ProtoValue> {
        let mut extracted = HashMap::new();
        // Track which conditions matched: rule_idx -> set of matched cond indices
        let mut matched_conds: HashMap<RuleIdx, Vec<bool>> = HashMap::new();
        for (ri, rule) in self.rules.iter().enumerate() {
            matched_conds.insert(ri, vec![false; rule.conditions.len()]);
        }

        self.parse_message(data, &self.root, &mut extracted, &mut matched_conds);

        // Fire rules where all conditions matched
        for (ri, rule) in self.rules.iter().enumerate() {
            if let Some(cond_matched) = matched_conds.get(&ri) {
                if !cond_matched.is_empty() && cond_matched.iter().all(|m| *m) {
                    if let Some(action_fn) = self.actions.get(&rule.action) {
                        action_fn(&rule.action, &extracted);
                    }
                }
            }
        }

        extracted
    }

    /// Recursively parse a protobuf message, walking the trie in parallel.
    fn parse_message(
        &self,
        data: &[u8],
        trie_node: &TrieNode,
        extracted: &mut HashMap<String, ProtoValue>,
        matched_conds: &mut HashMap<RuleIdx, Vec<bool>>,
    ) {
        let mut offset = 0;
        while offset < data.len() {
            let Some((tag_wire, tag_len)) = decode_varint(&data[offset..]) else {
                break;
            };
            let field_number = (tag_wire >> 3) as u32;
            let wire_type = tag_wire & 0x07;

            let child_node = trie_node.children.get(&field_number);

            match wire_type {
                0 => {
                    // Varint
                    let Some((val, val_len)) = decode_varint(&data[offset + tag_len..]) else {
                        break;
                    };
                    if let Some(node) = child_node {
                        let pv = ProtoValue::Varint(val);
                        self.record_value(node, &pv, extracted, matched_conds);
                    }
                    offset += tag_len + val_len;
                }
                1 => {
                    // 64-bit fixed
                    if offset + tag_len + 8 > data.len() {
                        break;
                    }
                    if let Some(node) = child_node {
                        let val = u64::from_le_bytes(
                            data[offset + tag_len..offset + tag_len + 8]
                                .try_into()
                                .unwrap(),
                        );
                        let pv = ProtoValue::Fixed64(val);
                        self.record_value(node, &pv, extracted, matched_conds);
                    }
                    offset += tag_len + 8;
                }
                2 => {
                    // Length-delimited
                    let Some((len, len_len)) = decode_varint(&data[offset + tag_len..]) else {
                        break;
                    };
                    let data_start = offset + tag_len + len_len;
                    let data_end = data_start + len as usize;
                    if data_end > data.len() {
                        break;
                    }
                    let field_data = &data[data_start..data_end];

                    if let Some(node) = child_node {
                        if node.extract_name.is_some() || !node.condition_refs.is_empty() {
                            // Leaf: extract as string or bytes
                            let pv = match std::str::from_utf8(field_data) {
                                Ok(s) => ProtoValue::String(s.to_string()),
                                Err(_) => ProtoValue::Bytes(field_data.to_vec()),
                            };
                            self.record_value(node, &pv, extracted, matched_conds);
                        }
                        if !node.children.is_empty() {
                            // Non-leaf: recurse into sub-message
                            self.parse_message(field_data, node, extracted, matched_conds);
                        }
                    }
                    offset = data_end;
                }
                5 => {
                    // 32-bit fixed
                    if offset + tag_len + 4 > data.len() {
                        break;
                    }
                    if let Some(node) = child_node {
                        let val = u32::from_le_bytes(
                            data[offset + tag_len..offset + tag_len + 4]
                                .try_into()
                                .unwrap(),
                        );
                        let pv = ProtoValue::Fixed32(val);
                        self.record_value(node, &pv, extracted, matched_conds);
                    }
                    offset += tag_len + 4;
                }
                _ => {
                    break; // Unknown wire type
                }
            }
        }
    }

    /// Record extracted value and evaluate any conditions at this trie node.
    fn record_value(
        &self,
        node: &TrieNode,
        value: &ProtoValue,
        extracted: &mut HashMap<String, ProtoValue>,
        matched_conds: &mut HashMap<RuleIdx, Vec<bool>>,
    ) {
        if let Some(name) = &node.extract_name {
            extracted.insert(name.clone(), value.clone());
        }
        for &(rule_idx, cond_idx) in &node.condition_refs {
            let cond = &self.rules[rule_idx].conditions[cond_idx];
            if cond.evaluate(value) {
                if let Some(cond_vec) = matched_conds.get_mut(&rule_idx) {
                    if cond_idx < cond_vec.len() {
                        cond_vec[cond_idx] = true;
                    }
                }
            }
        }
    }
}

fn parse_path(s: &str) -> Result<Vec<u32>, String> {
    s.split('.')
        .map(|p| {
            p.parse::<u32>()
                .map_err(|_| format!("Invalid tag number: {}", p))
        })
        .collect()
}

// --- Low-level protobuf encoding helpers (for tests) ---

/// Encode a varint into bytes.
pub fn encode_varint(mut val: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
    buf
}

/// Encode a varint field (wire type 0).
pub fn encode_varint_field(field_number: u32, value: u64) -> Vec<u8> {
    let tag = (field_number as u64) << 3;
    let mut buf = encode_varint(tag);
    buf.extend(encode_varint(value));
    buf
}

/// Encode a length-delimited field (wire type 2) with raw bytes.
pub fn encode_bytes_field(field_number: u32, data: &[u8]) -> Vec<u8> {
    let tag = ((field_number as u64) << 3) | 2;
    let mut buf = encode_varint(tag);
    buf.extend(encode_varint(data.len() as u64));
    buf.extend_from_slice(data);
    buf
}

/// Encode a string field (wire type 2).
pub fn encode_string_field(field_number: u32, s: &str) -> Vec<u8> {
    encode_bytes_field(field_number, s.as_bytes())
}

/// Encode a fixed32 field (wire type 5).
pub fn encode_fixed32_field(field_number: u32, value: u32) -> Vec<u8> {
    let tag = ((field_number as u64) << 3) | 5;
    let mut buf = encode_varint(tag);
    buf.extend(&value.to_le_bytes());
    buf
}

/// Encode a fixed64 field (wire type 1).
pub fn encode_fixed64_field(field_number: u32, value: u64) -> Vec<u8> {
    let tag = ((field_number as u64) << 3) | 1;
    let mut buf = encode_varint(tag);
    buf.extend(&value.to_le_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    // --- Encoding helper tests ---

    #[test]
    fn test_encode_varint() {
        assert_eq!(encode_varint(0), vec![0]);
        assert_eq!(encode_varint(1), vec![1]);
        assert_eq!(encode_varint(150), vec![0x96, 0x01]);
        assert_eq!(encode_varint(300), vec![0xAC, 0x02]);
    }

    #[test]
    fn test_roundtrip_varint() {
        for val in [0u64, 1, 127, 128, 255, 1000, 100000, u64::MAX] {
            let encoded = encode_varint(val);
            let (decoded, len) = decode_varint(&encoded).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(len, encoded.len());
        }
    }

    // --- Basic extraction tests ---

    #[test]
    fn test_extract_single_varint() {
        let mut ext = ProtoExtractor::new();
        ext.add_extractor("1", "field_one").unwrap();

        let msg = encode_varint_field(1, 42);
        let result = ext.handle_message(&msg);
        assert_eq!(result.get("field_one"), Some(&ProtoValue::Varint(42)));
    }

    #[test]
    fn test_extract_multiple_flat_fields() {
        let mut ext = ProtoExtractor::new();
        ext.add_extractor("1", "id").unwrap();
        ext.add_extractor("2", "name").unwrap();
        ext.add_extractor("3", "count").unwrap();

        let mut msg = encode_varint_field(1, 99);
        msg.extend(encode_string_field(2, "hello"));
        msg.extend(encode_varint_field(3, 7));

        let result = ext.handle_message(&msg);
        assert_eq!(result.get("id"), Some(&ProtoValue::Varint(99)));
        assert_eq!(
            result.get("name"),
            Some(&ProtoValue::String("hello".into()))
        );
        assert_eq!(result.get("count"), Some(&ProtoValue::Varint(7)));
    }

    #[test]
    fn test_extract_nested_path() {
        let mut ext = ProtoExtractor::new();
        ext.add_extractor("1.2.3", "deep_val").unwrap();

        // Build: field 3 = varint 55
        let inner2 = encode_varint_field(3, 55);
        // field 2 = message containing inner2
        let inner1 = encode_bytes_field(2, &inner2);
        // field 1 = message containing inner1
        let msg = encode_bytes_field(1, &inner1);

        let result = ext.handle_message(&msg);
        assert_eq!(result.get("deep_val"), Some(&ProtoValue::Varint(55)));
    }

    #[test]
    fn test_extract_deeply_nested() {
        let mut ext = ProtoExtractor::new();
        ext.add_extractor("1.2.3.4.5", "level5").unwrap();

        let l5 = encode_varint_field(5, 999);
        let l4 = encode_bytes_field(4, &l5);
        let l3 = encode_bytes_field(3, &l4);
        let l2 = encode_bytes_field(2, &l3);
        let msg = encode_bytes_field(1, &l2);

        let result = ext.handle_message(&msg);
        assert_eq!(result.get("level5"), Some(&ProtoValue::Varint(999)));
    }

    #[test]
    fn test_extract_fixed32() {
        let mut ext = ProtoExtractor::new();
        ext.add_extractor("1", "f32_val").unwrap();

        let msg = encode_fixed32_field(1, 12345);
        let result = ext.handle_message(&msg);
        assert_eq!(result.get("f32_val"), Some(&ProtoValue::Fixed32(12345)));
    }

    #[test]
    fn test_extract_fixed64() {
        let mut ext = ProtoExtractor::new();
        ext.add_extractor("1", "f64_val").unwrap();

        let msg = encode_fixed64_field(1, 9876543210);
        let result = ext.handle_message(&msg);
        assert_eq!(
            result.get("f64_val"),
            Some(&ProtoValue::Fixed64(9876543210))
        );
    }

    #[test]
    fn test_unregistered_fields_ignored() {
        let mut ext = ProtoExtractor::new();
        ext.add_extractor("2", "only_two").unwrap();

        let mut msg = encode_varint_field(1, 111);
        msg.extend(encode_varint_field(2, 222));
        msg.extend(encode_varint_field(3, 333));

        let result = ext.handle_message(&msg);
        assert_eq!(result.len(), 1);
        assert_eq!(result.get("only_two"), Some(&ProtoValue::Varint(222)));
    }

    // --- Rule and condition tests ---

    #[test]
    fn test_condition_parse() {
        let c = Condition::parse("1.2.3 < 100").unwrap();
        assert_eq!(c.path, vec![1, 2, 3]);
        assert_eq!(c.operator, Operator::Less);
        assert_eq!(c.value, "100");
    }

    #[test]
    fn test_rule_fires_when_all_conditions_met() {
        let fired = Arc::new(Mutex::new(false));
        let fired_clone = fired.clone();

        let mut ext = ProtoExtractor::new();
        ext.add_extractor("1", "temperature").unwrap();
        ext.add_extractor("2", "pressure").unwrap();

        ext.register_action("TEST_ACTION", move |_action, _vals| {
            *fired_clone.lock().unwrap() = true;
        });

        ext.add_rule("TEST_ACTION", &["1 > 50", "2 < 200"]).unwrap();

        // temperature=100 (>50), pressure=150 (<200): should fire
        let mut msg = encode_varint_field(1, 100);
        msg.extend(encode_varint_field(2, 150));
        ext.handle_message(&msg);

        assert!(*fired.lock().unwrap());
    }

    #[test]
    fn test_rule_does_not_fire_partial_match() {
        let fired = Arc::new(Mutex::new(false));
        let fired_clone = fired.clone();

        let mut ext = ProtoExtractor::new();
        ext.register_action("TEST", move |_, _| {
            *fired_clone.lock().unwrap() = true;
        });
        ext.add_rule("TEST", &["1 > 50", "2 < 10"]).unwrap();

        // field 1 = 100 (>50 OK), field 2 = 20 (NOT <10)
        let mut msg = encode_varint_field(1, 100);
        msg.extend(encode_varint_field(2, 20));
        ext.handle_message(&msg);

        assert!(!*fired.lock().unwrap());
    }

    #[test]
    fn test_string_equality_condition() {
        let fired = Arc::new(Mutex::new(false));
        let fired_clone = fired.clone();

        let mut ext = ProtoExtractor::new();
        ext.add_extractor("1", "status").unwrap();
        ext.register_action("ALERT", move |_, _| {
            *fired_clone.lock().unwrap() = true;
        });
        ext.add_rule("ALERT", &["1 = ERROR"]).unwrap();

        let msg = encode_string_field(1, "ERROR");
        ext.handle_message(&msg);
        assert!(*fired.lock().unwrap());
    }

    #[test]
    fn test_multiple_rules_independent() {
        let r1_fired = Arc::new(Mutex::new(false));
        let r2_fired = Arc::new(Mutex::new(false));
        let r1 = r1_fired.clone();
        let r2 = r2_fired.clone();

        let mut ext = ProtoExtractor::new();
        ext.register_action("R1", move |_, _| {
            *r1.lock().unwrap() = true;
        });
        ext.register_action("R2", move |_, _| {
            *r2.lock().unwrap() = true;
        });

        ext.add_rule("R1", &["1 > 10"]).unwrap();
        ext.add_rule("R2", &["1 < 5"]).unwrap();

        // value=3: R1 should NOT fire, R2 should fire
        let msg = encode_varint_field(1, 3);
        ext.handle_message(&msg);

        assert!(!*r1_fired.lock().unwrap());
        assert!(*r2_fired.lock().unwrap());
    }

    // --- Large-scale integration test ---

    /// Builds a complex protobuf mimicking a Perfetto TracePacket with 20+ fields
    /// across multiple nesting levels, and evaluates 10 rules.
    #[test]
    fn test_large_scale_extraction_and_rules() {
        let mut ext = ProtoExtractor::new();
        let action_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

        // --- Register 20 extractors across varied depths ---
        // Top-level fields
        ext.add_extractor("1", "timestamp").unwrap(); // varint
        ext.add_extractor("2", "event_name").unwrap(); // string
        ext.add_extractor("3", "pid").unwrap(); // varint
        ext.add_extractor("4", "tid").unwrap(); // varint
        ext.add_extractor("5", "cpu_id").unwrap(); // varint
                                                   // Nested in field 10 (sub-message)
        ext.add_extractor("10.1", "trace_id").unwrap(); // varint
        ext.add_extractor("10.2", "span_name").unwrap(); // string
        ext.add_extractor("10.3", "duration_ns").unwrap(); // varint
        ext.add_extractor("10.4", "status_code").unwrap(); // varint
        ext.add_extractor("10.5", "parent_id").unwrap(); // varint
                                                         // Nested in 10.20 (sub-sub-message)
        ext.add_extractor("10.20.1", "attr_key").unwrap(); // string
        ext.add_extractor("10.20.2", "attr_value").unwrap(); // string
        ext.add_extractor("10.20.3", "attr_type").unwrap(); // varint
                                                            // Nested in 11 (another sub-message)
        ext.add_extractor("11.1", "counter_name").unwrap(); // string
        ext.add_extractor("11.2", "counter_value").unwrap(); // varint
        ext.add_extractor("11.3", "counter_unit").unwrap(); // string
                                                            // Deeper nesting: 12.1.1, 12.1.2
        ext.add_extractor("12.1.1", "src_file").unwrap(); // string
        ext.add_extractor("12.1.2", "src_line").unwrap(); // varint
                                                          // Top-level continued
        ext.add_extractor("15", "severity").unwrap(); // varint
        ext.add_extractor("16", "log_body").unwrap(); // string

        // --- Register 10 rules ---
        for i in 0..10 {
            let log = action_log.clone();
            let action_name = format!("RULE_{}", i);
            let an = action_name.clone();
            ext.register_action(&action_name, move |action, _vals| {
                log.lock().unwrap().push(an.clone());
                let _ = action;
            });
        }

        // Rule 0: high timestamp + specific event
        ext.add_rule("RULE_0", &["1 > 1000", "2 = sched_switch"])
            .unwrap();
        // Rule 1: pid in range
        ext.add_rule("RULE_1", &["3 > 100", "3 < 10000"]).unwrap();
        // Rule 2: duration above threshold
        ext.add_rule("RULE_2", &["10.3 > 5000"]).unwrap();
        // Rule 3: error status
        ext.add_rule("RULE_3", &["10.4 = 2"]).unwrap();
        // Rule 4: counter above threshold
        ext.add_rule("RULE_4", &["11.2 > 90"]).unwrap();
        // Rule 5: severity critical
        ext.add_rule("RULE_5", &["15 > 3"]).unwrap();
        // Rule 6: specific cpu + high tid
        ext.add_rule("RULE_6", &["5 = 2", "4 > 500"]).unwrap();
        // Rule 7: attr type check
        ext.add_rule("RULE_7", &["10.20.3 = 1"]).unwrap();
        // Rule 8: source line > 100
        ext.add_rule("RULE_8", &["12.1.2 > 100"]).unwrap();
        // Rule 9: combined multi-depth
        ext.add_rule("RULE_9", &["1 > 500", "10.3 > 1000", "15 > 2"])
            .unwrap();

        // --- Build the protobuf message ---
        let mut msg = Vec::new();
        msg.extend(encode_varint_field(1, 5000)); // timestamp=5000
        msg.extend(encode_string_field(2, "sched_switch")); // event_name
        msg.extend(encode_varint_field(3, 1234)); // pid=1234
        msg.extend(encode_varint_field(4, 5678)); // tid=5678
        msg.extend(encode_varint_field(5, 2)); // cpu_id=2

        // Sub-message field 10
        let mut sub10 = Vec::new();
        sub10.extend(encode_varint_field(1, 42)); // trace_id
        sub10.extend(encode_string_field(2, "my_span")); // span_name
        sub10.extend(encode_varint_field(3, 10000)); // duration_ns=10000
        sub10.extend(encode_varint_field(4, 2)); // status_code=2 (error)
        sub10.extend(encode_varint_field(5, 41)); // parent_id

        // Sub-sub-message field 10.20
        let mut sub10_20 = Vec::new();
        sub10_20.extend(encode_string_field(1, "http.method")); // attr_key
        sub10_20.extend(encode_string_field(2, "GET")); // attr_value
        sub10_20.extend(encode_varint_field(3, 1)); // attr_type=1
        sub10.extend(encode_bytes_field(20, &sub10_20));
        msg.extend(encode_bytes_field(10, &sub10));

        // Sub-message field 11
        let mut sub11 = Vec::new();
        sub11.extend(encode_string_field(1, "cpu_usage"));
        sub11.extend(encode_varint_field(2, 95)); // counter_value=95
        sub11.extend(encode_string_field(3, "percent"));
        msg.extend(encode_bytes_field(11, &sub11));

        // Sub-message field 12
        let mut sub12_1 = Vec::new();
        sub12_1.extend(encode_string_field(1, "main.rs"));
        sub12_1.extend(encode_varint_field(2, 250)); // src_line=250
        let sub12 = encode_bytes_field(1, &sub12_1);
        msg.extend(encode_bytes_field(12, &sub12));

        msg.extend(encode_varint_field(15, 4)); // severity=4
        msg.extend(encode_string_field(16, "Connection refused")); // log_body

        // --- Execute ---
        let result = ext.handle_message(&msg);

        // --- Verify all 20 extractions ---
        assert_eq!(result.get("timestamp"), Some(&ProtoValue::Varint(5000)));
        assert_eq!(
            result.get("event_name"),
            Some(&ProtoValue::String("sched_switch".into()))
        );
        assert_eq!(result.get("pid"), Some(&ProtoValue::Varint(1234)));
        assert_eq!(result.get("tid"), Some(&ProtoValue::Varint(5678)));
        assert_eq!(result.get("cpu_id"), Some(&ProtoValue::Varint(2)));
        assert_eq!(result.get("trace_id"), Some(&ProtoValue::Varint(42)));
        assert_eq!(
            result.get("span_name"),
            Some(&ProtoValue::String("my_span".into()))
        );
        assert_eq!(result.get("duration_ns"), Some(&ProtoValue::Varint(10000)));
        assert_eq!(result.get("status_code"), Some(&ProtoValue::Varint(2)));
        assert_eq!(result.get("parent_id"), Some(&ProtoValue::Varint(41)));
        assert_eq!(
            result.get("attr_key"),
            Some(&ProtoValue::String("http.method".into()))
        );
        assert_eq!(
            result.get("attr_value"),
            Some(&ProtoValue::String("GET".into()))
        );
        assert_eq!(result.get("attr_type"), Some(&ProtoValue::Varint(1)));
        assert_eq!(
            result.get("counter_name"),
            Some(&ProtoValue::String("cpu_usage".into()))
        );
        assert_eq!(result.get("counter_value"), Some(&ProtoValue::Varint(95)));
        assert_eq!(
            result.get("counter_unit"),
            Some(&ProtoValue::String("percent".into()))
        );
        assert_eq!(
            result.get("src_file"),
            Some(&ProtoValue::String("main.rs".into()))
        );
        assert_eq!(result.get("src_line"), Some(&ProtoValue::Varint(250)));
        assert_eq!(result.get("severity"), Some(&ProtoValue::Varint(4)));
        assert_eq!(
            result.get("log_body"),
            Some(&ProtoValue::String("Connection refused".into()))
        );

        // --- Verify rules fired ---
        let fired = action_log.lock().unwrap();
        // Rule 0: ts>1000 AND event=sched_switch => YES
        assert!(fired.contains(&"RULE_0".to_string()), "Rule 0 should fire");
        // Rule 1: pid>100 AND pid<10000 => 1234 in (100,10000) => YES
        assert!(fired.contains(&"RULE_1".to_string()), "Rule 1 should fire");
        // Rule 2: duration>5000 => 10000>5000 => YES
        assert!(fired.contains(&"RULE_2".to_string()), "Rule 2 should fire");
        // Rule 3: status=2 => YES
        assert!(fired.contains(&"RULE_3".to_string()), "Rule 3 should fire");
        // Rule 4: counter>90 => 95>90 => YES
        assert!(fired.contains(&"RULE_4".to_string()), "Rule 4 should fire");
        // Rule 5: severity>3 => 4>3 => YES
        assert!(fired.contains(&"RULE_5".to_string()), "Rule 5 should fire");
        // Rule 6: cpu=2 AND tid>500 => YES
        assert!(fired.contains(&"RULE_6".to_string()), "Rule 6 should fire");
        // Rule 7: attr_type=1 => YES
        assert!(fired.contains(&"RULE_7".to_string()), "Rule 7 should fire");
        // Rule 8: src_line>100 => 250>100 => YES
        assert!(fired.contains(&"RULE_8".to_string()), "Rule 8 should fire");
        // Rule 9: ts>500 AND dur>1000 AND sev>2 => YES
        assert!(fired.contains(&"RULE_9".to_string()), "Rule 9 should fire");
    }

    /// Test where some rules should NOT fire.
    #[test]
    fn test_selective_rule_firing() {
        let action_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let mut ext = ProtoExtractor::new();

        for name in &["FIRE", "NOFIRE_A", "NOFIRE_B"] {
            let log = action_log.clone();
            let n = name.to_string();
            ext.register_action(name, move |_, _| {
                log.lock().unwrap().push(n.clone());
            });
        }

        ext.add_extractor("1", "val_a").unwrap();
        ext.add_extractor("2", "val_b").unwrap();
        ext.add_extractor("3.1", "val_c").unwrap();

        // FIRE: val_a > 10 (satisfied by 50)
        ext.add_rule("FIRE", &["1 > 10"]).unwrap();
        // NOFIRE_A: val_b = 999 (we send 42)
        ext.add_rule("NOFIRE_A", &["2 = 999"]).unwrap();
        // NOFIRE_B: val_a > 10 AND val_c < 5 (val_c=100, fails)
        ext.add_rule("NOFIRE_B", &["1 > 10", "3.1 < 5"]).unwrap();

        let inner3 = encode_varint_field(1, 100);
        let mut msg = encode_varint_field(1, 50);
        msg.extend(encode_varint_field(2, 42));
        msg.extend(encode_bytes_field(3, &inner3));

        ext.handle_message(&msg);

        let fired = action_log.lock().unwrap();
        assert!(fired.contains(&"FIRE".to_string()));
        assert!(!fired.contains(&"NOFIRE_A".to_string()));
        assert!(!fired.contains(&"NOFIRE_B".to_string()));
    }

    #[test]
    fn test_empty_message() {
        let ext = ProtoExtractor::new();
        let result = ext.handle_message(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_no_extractors_returns_empty() {
        let ext = ProtoExtractor::new();
        let msg = encode_varint_field(1, 42);
        let result = ext.handle_message(&msg);
        assert!(result.is_empty());
    }

    /// Performance-oriented: wide message with many fields at depth.
    #[test]
    fn test_wide_and_deep_message() {
        let mut ext = ProtoExtractor::new();
        // Extract 20 fields from depth-3 paths: 1.N.1 for N in 1..=20
        for n in 1..=20u32 {
            ext.add_extractor(&format!("1.{}.1", n), &format!("field_{}", n))
                .unwrap();
        }

        // 10 rules checking various fields
        for i in 0..10 {
            let field_a = (i % 20) + 1;
            let field_b = ((i + 5) % 20) + 1;
            ext.add_rule(
                "LOG",
                &[
                    &format!("1.{}.1 > 0", field_a),
                    &format!("1.{}.1 > 0", field_b),
                ],
            )
            .unwrap();
        }

        // Build the message: field 1 contains 20 sub-messages
        let mut outer = Vec::new();
        for n in 1..=20u32 {
            let leaf = encode_varint_field(1, n as u64 * 100);
            outer.extend(encode_bytes_field(n, &leaf));
        }
        let msg = encode_bytes_field(1, &outer);

        let result = ext.handle_message(&msg);
        assert_eq!(result.len(), 20);
        for n in 1..=20u32 {
            assert_eq!(
                result.get(&format!("field_{}", n)),
                Some(&ProtoValue::Varint(n as u64 * 100))
            );
        }
    }
}
