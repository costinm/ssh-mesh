use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "capng stub error")
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    DacOverride,
    // Add others if needed, but we can just return a dummy
    Other(u32),
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Type {
    EFFECTIVE,
    PERMITTED,
    INHERITABLE,
    BOUNDING,
}

#[derive(Debug, Clone, Copy)]
pub enum Set {
    CAPS,
    BOUNDS,
    BOTH,
}

#[derive(Debug, Clone, Copy)]
pub enum Action {
    DROP,
    ADD,
}

pub struct CUpdate {
    pub action: Action,
    pub cap_type: Type,
    pub capability: Capability,
}

pub fn name_to_capability(_name: &str) -> Result<Capability> {
    Ok(Capability::Other(0))
}

pub fn have_capability(_cap_type: Type, _cap: Capability) -> bool {
    // Return true to avoid attempts to drop/add if that helps,
    // or false to avoid entering certain blocks.
    // In credentials.rs, it drops if have_capability is true.
    false
}

pub fn update(_updates: Vec<CUpdate>) -> Result<()> {
    Ok(())
}

pub fn apply(_set: Set) -> Result<()> {
    Ok(())
}

pub fn clear(_set: Set) {}

pub fn get_caps_process() -> Result<()> {
    Ok(())
}
