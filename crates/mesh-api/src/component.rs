//! Passive, compile-time component and method descriptors generated from `API.md`.
//!
//! Unlike imperative boot-time registries, [`ComponentSpec`] and [`MethodSpec`]
//! live in read-only static memory (`.rodata`), mirroring XIP's `.xip_comp`
//! tables and Android's manifest component declarations. Routers and loaders
//! inspect these descriptors passively and instantiate handlers lazily on the
//! first matching request.

use crate::envelope::Name;

/// Execution mode of an API method declared in `API.md`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MethodExecution {
    /// Standard request/response or one-way message.
    #[default]
    Unary,
    /// Long-running or blocking unary operation (`**Execution:** blocking`).
    Blocking,
    /// Bidirectional stream opened after the initial self-delimiting envelope
    /// (`**Execution:** stream`).
    Stream,
}

/// Passive, compile-time metadata for a single method within a [`ComponentSpec`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MethodSpec {
    /// Method name within its owning component (for example `"nodes"`, `"status"`, or `"start"`).
    pub name: &'static str,
    /// Optional compact numeric method ID (`## N. \`method\`` in `API.md`).
    /// Host-only methods may omit numeric IDs (`None`).
    pub id: Option<u32>,
    /// Execution mode (`Unary`, `Blocking`, or `Stream`).
    pub execution: MethodExecution,
}

impl MethodSpec {
    /// Return whether this method upgrades the transport into a bidirectional body stream.
    #[inline]
    pub const fn is_stream(&self) -> bool {
        matches!(self.execution, MethodExecution::Stream)
    }

    /// Return whether `method` matches either [`Self::name`] or [`Self::id`].
    #[inline]
    pub fn matches(&self, method: Name<'_>) -> bool {
        match method {
            Name::Text(bytes) => self.name.as_bytes() == bytes,
            Name::Tag(tag) => u32::try_from(tag)
                .ok()
                .is_some_and(|id| self.matches_id(id)),
            Name::Bytes(_) => false,
        }
    }

    /// Return whether `name` equals [`Self::name`].
    #[inline]
    pub fn matches_str(&self, name: &str) -> bool {
        self.name == name
    }

    /// Return whether [`Self::id`] equals `id`.
    #[inline]
    pub const fn matches_id(&self, id: u32) -> bool {
        matches!(self.id, Some(own) if own == id)
    }
}

/// Passive, compile-time metadata for a component, generated from `API.md`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentSpec {
    /// Canonical component name or path prefix (for example `"discovery"`, `"wifi"`,
    /// or `"host.diagnostics"`).
    pub name: &'static str,
    /// Optional compact numeric component ID (`# \`name\` API (ID)` in `API.md`).
    pub id: Option<u32>,
    /// Schema version (defaults to `1`, matching XIP component manifest version 1).
    pub version: u32,
    /// Static list of methods belonging to this component.
    pub methods: &'static [MethodSpec],
}

impl ComponentSpec {
    /// Return whether `component` matches either [`Self::name`] or [`Self::id`].
    #[inline]
    pub fn matches(&self, component: Name<'_>) -> bool {
        match component {
            Name::Text(bytes) => self.name.as_bytes() == bytes,
            Name::Tag(tag) => u32::try_from(tag)
                .ok()
                .is_some_and(|id| self.matches_id(id)),
            Name::Bytes(_) => false,
        }
    }

    /// Return whether `name` equals [`Self::name`].
    #[inline]
    pub fn matches_str(&self, name: &str) -> bool {
        self.name == name
    }

    /// Return whether [`Self::id`] equals `id`.
    #[inline]
    pub const fn matches_id(&self, id: u32) -> bool {
        matches!(self.id, Some(own) if own == id)
    }

    /// Look up a method by borrowed envelope [`Name`] (text name or numeric tag).
    pub fn find_method(&self, method: Name<'_>) -> Option<&'static MethodSpec> {
        self.methods.iter().find(|spec| spec.matches(method))
    }

    /// Look up a method by its string name.
    pub fn find_method_by_name(&self, name: &str) -> Option<&'static MethodSpec> {
        self.methods.iter().find(|spec| spec.matches_str(name))
    }

    /// Look up a method by its compact numeric ID.
    pub fn find_method_by_id(&self, id: u32) -> Option<&'static MethodSpec> {
        self.methods.iter().find(|spec| spec.matches_id(id))
    }
}

/// Find a matching [`ComponentSpec`] in a passive component slice.
pub fn find_component<'a>(
    specs: &'a [ComponentSpec],
    component: Name<'_>,
) -> Option<&'a ComponentSpec> {
    specs.iter().find(|spec| spec.matches(component))
}

/// Resolve both `(component, method)` in a passive component slice without allocation.
pub fn resolve_method<'a>(
    specs: &'a [ComponentSpec],
    component: Name<'_>,
    method: Name<'_>,
) -> Option<(&'a ComponentSpec, &'static MethodSpec)> {
    let comp = find_component(specs, component)?;
    let meth = comp.find_method(method)?;
    Some((comp, meth))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROBE_METHODS: &[MethodSpec] = &[
        MethodSpec {
            name: "start",
            id: Some(1),
            execution: MethodExecution::Unary,
        },
        MethodSpec {
            name: "handler",
            id: Some(2),
            execution: MethodExecution::Stream,
        },
    ];

    const DIAG_METHODS: &[MethodSpec] = &[MethodSpec {
        name: "version",
        id: None,
        execution: MethodExecution::Unary,
    }];

    const SPECS: &[ComponentSpec] = &[
        ComponentSpec {
            name: "probe",
            id: Some(8),
            version: 1,
            methods: PROBE_METHODS,
        },
        ComponentSpec {
            name: "host.diagnostics",
            id: None,
            version: 1,
            methods: DIAG_METHODS,
        },
    ];

    #[test]
    fn resolves_by_string_numeric_and_mixed_identifiers() {
        let (c1, m1) = resolve_method(SPECS, Name::Text(b"probe"), Name::Text(b"handler")).unwrap();
        assert_eq!(c1.name, "probe");
        assert_eq!(m1.name, "handler");
        assert!(m1.is_stream());

        let (c2, m2) = resolve_method(SPECS, Name::Tag(8), Name::Tag(1)).unwrap();
        assert_eq!(c2.name, "probe");
        assert_eq!(m2.name, "start");
        assert!(!m2.is_stream());

        let (c3, m3) = resolve_method(SPECS, Name::Tag(8), Name::Text(b"start")).unwrap();
        assert_eq!(c3.id, Some(8));
        assert_eq!(m3.id, Some(1));
    }

    #[test]
    fn resolves_string_only_components_and_rejects_unknowns() {
        let (comp, meth) =
            resolve_method(SPECS, Name::Text(b"host.diagnostics"), Name::Text(b"version"))
                .unwrap();
        assert_eq!(comp.name, "host.diagnostics");
        assert_eq!(comp.id, None);
        assert_eq!(meth.name, "version");
        assert_eq!(meth.id, None);

        assert!(resolve_method(SPECS, Name::Tag(99), Name::Tag(1)).is_none());
        assert!(resolve_method(SPECS, Name::Text(b"probe"), Name::Text(b"missing")).is_none());
    }
}
