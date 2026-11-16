#![cfg(feature = "program")]
use micro_cel::{
    Code,
    program::{Program, ProgramLimits, Rule, RuleList, wire},
};

#[test]
fn roundtrip_and_reject_bad_input() {
    let limits = ProgramLimits::default();
    let program = Program {
        lists: vec![RuleList {
            name: "one".into(),
            context: vec![0xa0],
            rules: vec![Rule::After { delay_ms: 12 }],
        }],
    };
    let encoded = wire::encode(&program, &limits).unwrap();
    let decoded = wire::decode(&encoded, &limits).unwrap();
    assert_eq!(decoded.lists[0].name, "one");
    assert!(matches!(
        decoded.lists[0].rules[0],
        Rule::After { delay_ms: 12 }
    ));
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(wire::decode(&trailing, &limits).is_err());
    assert!(wire::decode(&[0xa2, 1, 1, 1, 0x80], &limits).is_err());
    let small = ProgramLimits {
        max_input_bytes: encoded.len() - 1,
        ..ProgramLimits::default()
    };
    assert!(matches!(wire::decode(&encoded, &small), Err(Code::Size)));
    let small = ProgramLimits {
        max_lists: 0,
        ..ProgramLimits::default()
    };
    assert!(matches!(wire::decode(&encoded, &small), Err(Code::Size)));
    let small = ProgramLimits {
        max_rules: 0,
        ..ProgramLimits::default()
    };
    assert!(matches!(wire::decode(&encoded, &small), Err(Code::Size)));
}

#[test]
fn decoder_leaves_semantic_depth_validation_to_host() {
    let mut expr = vec![0xa1, 1, 0xa1, 1, 1];
    for _ in 0..9 {
        let mut parent = vec![0xa1, 4, 0xa2, 1, 13, 2, 0x81];
        parent.extend(expr);
        expr = parent;
    }
    let program = Program {
        lists: vec![RuleList {
            name: "deep".into(),
            context: vec![0xa0],
            rules: vec![Rule::Eval { expr }],
        }],
    };
    let encoded = wire::encode(&program, &ProgramLimits::default()).unwrap();
    let limits = ProgramLimits {
        max_frames: 8,
        ..ProgramLimits::default()
    };
    // Device decoding is bounded parsing, not a duplicate AST preflight.
    assert_eq!(wire::decode(&encoded, &limits), Ok(program));
}
