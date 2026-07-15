pub mod battery;
pub mod ble_bt;
pub mod button;
pub mod console;
pub mod frames;
pub mod gpio;
pub mod i2c;
pub mod l3dmesh;
pub mod lora;
pub mod mode;
pub mod nan;
pub mod nvs;
pub mod settings;
pub mod sleep;
pub mod telemetry;
pub mod wake;
pub mod wifi;

use crate::commands::CommandRegistry;

use settings::SharedSettings;

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    battery::register_commands(registry, settings.clone());
    button::register_commands(registry, settings.clone());
    console::register_commands(registry);
    gpio::register_commands(registry);
    i2c::register_commands(registry, settings.clone());
    lora::register_commands(registry, settings.clone());
    mode::register_commands(registry, settings.clone());
    ble_bt::register_commands(registry, settings.clone());
    nan::register_commands(registry, settings.clone());
    sleep::register_commands(registry, settings.clone());
    telemetry::register_commands(registry, settings.clone());
    nvs::register_commands(registry, settings);
    wifi::register_commands(registry);
}
