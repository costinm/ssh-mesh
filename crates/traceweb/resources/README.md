# traceweb resources

`tools.json` is the curated public command catalog for traceweb. It is used by
the lightweight MCP `tools/list` method and by local CLI/UI clients.

Keep this file hand-maintained and intentionally smaller than the internal code
surface when needed. When `../API.md` changes, update `tools.json` in the same
change if the user-facing command catalog changes.
