#![cfg(feature = "program-host")]

use micro_cel::{
    Code,
    host::program::{self, Format},
    program::{Program, ProgramLimits, Rule, RuleList, wire},
};

fn program(expr: Vec<u8>) -> Program {
    Program {
        lists: vec![RuleList {
            name: "test".into(),
            context: vec![0xa0],
            rules: vec![Rule::Eval { expr }],
        }],
    }
}

#[test]
fn malformed_ast_is_structurally_decodable_but_not_host_encodable() {
    let limits = ProgramLimits::default();
    let p = program(vec![0xa0]);
    let artifact = wire::encode(&p, &limits).unwrap();
    assert_eq!(wire::decode(&artifact, &limits).unwrap(), p);
    assert!(program::validate_program(&p, &limits).is_err());
    assert!(program::encode(&p, &limits).is_err());
}

#[test]
fn validates_unexecuted_branch_and_depth() {
    // true ? 1 : <malformed expression>
    let p = program(vec![
        0xa1, 4, 0xa2, 1, 4, 2, 0x83, 0xa1, 1, 0xa1, 3, 0xf5, 0xa1, 1, 0xa1, 1, 1, 0xa0,
    ]);
    let limits = ProgramLimits::default();
    assert!(program::encode(&p, &limits).is_err());
    let mut expr = vec![0xa1, 1, 0xa1, 1, 1];
    for _ in 0..9 {
        let mut parent = vec![0xa1, 4, 0xa2, 1, 13, 2, 0x81];
        parent.extend(expr);
        expr = parent;
    }
    let p = program(expr);
    let limits = ProgramLimits {
        max_frames: 8,
        ..limits
    };
    assert_eq!(program::validate_program(&p, &limits), Err(Code::Depth));
    assert!(wire::decode(&wire::encode(&p, &limits).unwrap(), &limits).is_ok());
}

#[test]
fn compiler_checks_limits_and_checked_artifact_roundtrips() {
    let source = "version = 1\nschema = {}\n[[lists]]\nname = 'test'\nrules = [{expr = '1 + 2'}]\n";
    let limits = ProgramLimits::default();
    let p = program::compile(source, Format::Toml, &limits).unwrap();
    let artifact = program::encode(&p, &limits).unwrap();
    assert_eq!(wire::decode(&artifact, &limits).unwrap(), p);
    let limits = ProgramLimits {
        max_frames: 1,
        ..limits
    };
    assert!(program::compile(source, Format::Toml, &limits).is_err());
}
