# Experimental expression and program encoding

For compiler interoperability only; this experimental format is not a stability promise. Applications should treat compiled artifacts as opaque. See the [component RPC contract](ABI.md).

## Values and expression CBOR

The contract is the decoded CBOR values and structural fields, not a unique
byte encoding of integer heads: both minimal 16-bit and valid 32-bit heads
are accepted for values 256 through 65535. Booleans and null use `f4`, `f5`,
and `f6` respectively; undefined, indefinite-length items, floats, and tags
are not supported.

Expressions are definite-length one-entry maps keyed by kind: 1 constant,
2 identifier, 3 selection, 4 call, 5 list, 6 struct. Comprehension (7) is
unsupported. Payloads are:

* Constant: `{k: value}`, where k=1 signed i32, 2 unsigned fitting i32,
  3 boolean, 5 text, 6 bytes, 7 CBOR null (`f6`); double (4) is unsupported.
* Identifier: `{1: unsignedTag}`. Contexts are CBOR maps with unique unsigned
  tags; a host schema maps source names to tags.
* Selection: `{1: operand, 2: unsignedTagOrText}`.
* Call: `{1: functionId, 2: [arguments], 3: optionalTarget}`.
* List: `{1: [expressions]}`. Struct: `{1: [[staticKey, expression], ...]}`;
  static keys are text, bytes, or i32 integers, and text and bytes with the
  same content count as duplicates.

Function IDs: 1 `||`, 2 `&&`, 3 `!`, 4 `?:`, 5 `==`, 6 `!=`, 7 `<`,
8 `<=`, 9 `>`, 10 `>=`, 11 `in`, 12 `+`, 13 unary `-`, 14 binary `-`,
15 `*`, 16 `/`, 17 `%`, 18 index, 19 `size`, 20 `startsWith`,
21 `endsWith`, 22 `contains`, 23 `call`, 24 `has`. Other IDs are unsupported.
`call(component, method, params)` requires literal i32 component and method
arguments and an evaluated CBOR map for parameters. `has` only converts a
missing final selection/index into false; errors in the receiver or index
propagate. Logical short circuiting can absorb ordinary expression errors,
but not structural or resource errors. Lists and maps compare structurally;
text and bytes compare by byte content. Other mixed-type equality is false,
including inside containers. `size(text)` counts Unicode scalar values and
`size(bytes)` counts bytes. String matching is byte-oriented. As a subset
extension, `in` on text or bytes performs substring matching. Null equals null, but other null
operations are type errors. CBOR undefined (`f7`) is not null and is rejected.

Values have unique scalar map keys (integer, boolean, null, text or bytes),
at most 128 entries per map, and nesting at most 32 levels; lists in expression
literals have at most 128 elements. Each AST, variables value and callback
value is capped at 16 KiB. Evaluation/check depth has a hard ceiling of 128;
default expression limits are depth 32 and 512 nodes. Embedders can impose
smaller limits. Resource limits do not yet meter all comparison and scan work.

`Code` maps Ok to 0, Unsupported -1001, Depth -1002, Nodes -1003,
Malformed -1004, Type -1005, NotFound -1006, Arith -1007 and Size -1008.
`Invoke(i32)` preserves the component error code; integer conversion cannot
distinguish a coincident invocation code from a micro-CEL code.

## Program CBOR

The wire format is `{1: 1, 2: [list, ...]}`, with list
`{1: name, 2: contextMap, 3: [rule, ...]}`. Names are nonempty, unique UTF-8.
Rules are `{1: 1, 2: ast}` (eval), `{1: 2, 2: ast, 3: tag}` (set),
`{1: 3, 2: ast}` (break-if), or `{1: 4, 2: delayMs}` (after). Structural
map keys must be in ascending order and the decoder rejects trailing data.
`ProgramLimits` bounds input bytes, lists, total rules, pending calls, context
and value sizes, frames, node fuel and timeout. The generic `program::wire`
encoder and decoder check structure and bounds, not full AST semantics.
Use `host::program::compile`, `validate_program`, or checked `encode` on a
trusted host before distributing compiled CBOR. TOML is a host input, not an
on-device format.
