# lmesh resources

`tools.json` is the curated public command catalog for `lmesh` and radio-adapter
control surfaces exposed through `tools/list`, `tools/call`, the ssh-mesh admin
web UI, and the `mesh lmesh tools` CLI command.

Keep this file independent of code generation. It is allowed to hide, group, or
simplify the internal method surface. When changing the JSONL API in
`../API.md`, update `tools.json` in the same change when the public command
catalog should change.
