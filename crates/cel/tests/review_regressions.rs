#![cfg(feature = "translate")]

use mesh_api::cbor::Writer;
use micro_cel::{
    Limits, NoInvoke, eval,
    host::translate::{Schema, translate},
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct CountingAllocator;
thread_local! {
    static COUNT: Cell<Option<usize>> = const { Cell::new(None) };
}
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        COUNT.with(|count| {
            if let Some(n) = count.get() {
                count.set(Some(n + 1));
            }
        });
        // SAFETY: delegate the allocator contract unchanged.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: allocations are obtained from System with the same layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn ast(source: &str) -> Vec<u8> {
    translate(source, &Schema::parse("x=1").unwrap()).unwrap()
}

fn run(source: &str) -> Vec<u8> {
    let mut scratch = [0; 8192];
    let mut out = [0; 128];
    eval(
        &ast(source),
        &[0xa0],
        &mut scratch,
        &mut out,
        Limits::default(),
        &mut NoInvoke,
    )
    .unwrap()
    .to_vec()
}

#[test]
fn mixed_equality_and_unicode_size() {
    for source in [
        "1 != true",
        "[1] != [true]",
        "{1: 1} != {1: true}",
        "size(\"é🙂\") == 2",
        "size(b\"é🙂\") == 6",
    ] {
        assert_eq!(run(source), [0xf5], "{source}");
    }
}

#[test]
fn translator_bounds_recursive_syntax_and_flat_chains() {
    let schema = Schema::default();
    for source in [
        format!("{}true{}", "(".repeat(2000), ")".repeat(2000)),
        format!("{}true", "!".repeat(2000)),
        format!("{}1", "-".repeat(2000)),
        format!("1{}", "+1".repeat(2000)),
        format!("{{}}{}", ".x".repeat(2000)),
        format!("[0]{}", "[0]".repeat(2000)),
    ] {
        assert!(translate(&source, &schema).unwrap_err().contains("depth"));
    }
}

#[test]
fn container_equality_and_validation_allocate_nothing() {
    let expression = ast("x == x");
    let mut context = [0; 256];
    let mut writer = Writer::new(&mut context);
    writer
        .map(1)
        .uint(1)
        .map(2)
        .text("a")
        .array(2)
        .int(1)
        .boolean(true)
        .text("b")
        .map(1)
        .text("c")
        .int(2);
    let context = writer.finish().unwrap();
    let mut scratch = [0; 8192];
    let mut out = [0; 128];
    COUNT.with(|count| count.set(Some(0)));
    let result = eval(
        &expression,
        context,
        &mut scratch,
        &mut out,
        Limits::default(),
        &mut NoInvoke,
    );
    let allocations = COUNT.with(|count| count.replace(None).unwrap());
    assert_eq!(result, Ok(&[0xf5][..]));
    assert_eq!(allocations, 0);
}

#[cfg(feature = "service")]
#[test]
fn service_zero_expression_depth_reports_depth() {
    let result = micro_cel::service::evaluate_one(
        &ast("true"),
        &[0xa0],
        Limits {
            max_depth: 0,
            ..Limits::default()
        },
        false,
        micro_cel::program::ProgramLimits::default(),
        32,
        |_, _, _| panic!(),
    );
    assert_eq!(result, Err(micro_cel::Code::Depth));
}
