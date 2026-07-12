# mesh-init resources

`tools.json` is the curated public command catalog for mesh-init control
methods. It is not generated from `mesh::protocol::Request`; the catalog may
hide dangerous or low-level methods, group related actions, or simplify schemas.

When `../API.md` or `../USAGE.md` changes the user-facing control surface,
update `tools.json` in the same change if the command catalog should change.
