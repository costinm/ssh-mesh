use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::config::NetworkType;

/// System events, matching Android JobScheduler triggers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SystemEvent {
    NetworkChanged {
        network_type: NetworkType,
        connected: bool,
    },
    ChargingChanged {
        is_charging: bool,
    },
    IdleChanged {
        is_idle: bool,
    },
    BatteryChanged {
        level: u8,
        is_low: bool,
    },
    StorageChanged {
        is_low: bool,
    },
    ContentChanged {
        uri: String,
    },
    BootCompleted,
    TimerTick,
    CustomCondition {
        key: String,
        value: bool,
    },
}

/// Snapshot of current system state, maintained by the scheduler.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemState {
    pub network_type: NetworkType,
    pub network_connected: bool,
    pub is_charging: bool,
    pub is_idle: bool,
    pub battery_level: u8,
    pub battery_low: bool,
    pub storage_low: bool,
    pub custom: HashMap<String, bool>,
}

impl SystemState {
    pub fn update(&mut self, event: &SystemEvent) {
        match event {
            SystemEvent::NetworkChanged {
                network_type,
                connected,
            } => {
                self.network_type = network_type.clone();
                self.network_connected = *connected;
            }
            SystemEvent::ChargingChanged { is_charging } => {
                self.is_charging = *is_charging;
            }
            SystemEvent::IdleChanged { is_idle } => {
                self.is_idle = *is_idle;
            }
            SystemEvent::BatteryChanged { level, is_low } => {
                self.battery_level = *level;
                self.battery_low = *is_low;
            }
            SystemEvent::StorageChanged { is_low } => {
                self.storage_low = *is_low;
            }
            SystemEvent::CustomCondition { key, value } => {
                self.custom.insert(key.clone(), *value);
            }
            _ => {}
        }
    }
}
