# ESP32 Rust Firmware API

The ESP32 Rust firmware exposes a line-oriented command API. UART is the
current direct transport; BLE GATT and raw Wi-Fi command frames should dispatch
to the same command registry. In normal product use, this API is expected to be
proxied and exposed by `crates/lmesh`, which can translate MCP/JSONL calls into
serial, BLE, or raw Wi-Fi firmware commands.

The firmware does not currently serve MCP JSONL itself. The MCP-style catalog in
`resources/tools.json` is for lmesh or another host adapter to expose.

`lmesh` is the product-facing API boundary. Its high-level methods such as
`send`, `ping`, `radios.list`, `links.list`, and `messages.history` should be
able to use Linux radios, Android JNI radios, local ESP serial/BLE adapters, or
SSH-forwarded remote lmesh adapters. ESP-specific methods are diagnostics and
direct firmware controls unless there is no high-level method yet.

## Wire Shape

One text command is sent per line:

```text
lora status=true
```

UART responses are text records followed by the prompt:

```text
lora status=true chip=sx127x rx_running=true ...
dm-rs>
```

Errors use:

```text
error message="..."
```

Parsing guidance:

- parse command prefix and `key=value` fields;
- tolerate extra fields;
- use `hex:...` for binary inputs;
- use bounded `max_bytes` on `logs`, `messages`, and `local_messages`;
- prefer counters/log events over exact full-line matching.

## Host Workflow

Use repo-local dependencies only:

```bash
cd /ws/rust/ssh-mesh
scripts/esp32-deps.sh
. fw/esp32/env.sh
cd fw/esp32/rust
```

Normal host/CI testing should access firmware through `crates/lmesh` USB
forwarding. Direct `/dev/ttyUSB*` flashing is a local recovery path.

Local recovery flash for classic ESP32:

```bash
cargo espflash flash --release --port /dev/ttyUSBX \
  --chip esp32 --flash-size 4mb --non-interactive
```

Flash the 16 MB ESP32-S3 test board:

```bash
ESP_IDF_SDKCONFIG_DEFAULTS=sdkconfig.heltec_v3.defaults \
  cargo espflash flash --release --target xtensa-esp32s3-espidf \
  --port /dev/ttyACMX --chip esp32s3 --flash-size 16mb --non-interactive
```

The ESP32-S3 partition profile keeps the first 4 MB layout compatible with the
classic ESP32 image and adds `dmesh_store` at `0x400000`. On 16 MB flash this
reserves 12 MB for future logs, message payloads, and radio-store experiments.

Fleet flash helper:

```bash
LMESH_CONTROL_SOCKET=/run/mesh/lmesh-radio-build/mesh.sock \
  python tools/flash_test_fleet.py --lmesh-mode=tcp \
    --port ACM1 --port USB0 --port USB1 --port USB2 --port USB3
```

The helper discovers logical lmesh USB ports with `usb.serial.list`, starts a
UDS plus TCP forward for each selected device, probes/flashes through
`rfc2217://127.0.0.1:<port>`, and configures through the UDS socket. Use
logical `--port USB0`/`--port ACM1` or `DMESH_FLASH_PORTS=USB0,USB1` when
device order matters.

The RFC2217 flash path must preserve NVS. Do not write the padded merged image
at `0x0`: the merged image contains `0xff` bytes across the NVS partition
`0x9000..0xefff`, which erases saved settings. The fleet helper slices the real
merged Rust image into sparse bootloader, partition-table, and app chunks and
skips NVS/PHY. This also avoids transferring some padding; the remaining speed
limit is the conservative `--no-stub` RFC2217 path.

The helper configures every flashed ESP for the current default: infra mode,
DFS, raw-NAN duty cycle, Wi-Fi off between active windows, and LoRa receive on
expected TLORA boards. By default `USB0`, `USB1`, and `USB2` are expected
TLORA/SX127x boards; configure overrides with
`DMESH_EXPECTED_LORA_PORTS=USB0,USB1` or repeated `--expected-lora-port`.
Expected LoRa ports are probed/saved with the TLORA V2.1-1.6 SX127x pin map
(`spi_host=2 sck=5 miso=19 mosi=27 cs=18 rst=23 dio0=26`) and the feature test
fails if any expected LoRa port is missing. Test-specific modes, such as
`wifi.mode=nan_sleep` or `sleep test=...`, belong in serial commands or
dedicated test scripts. See `docs/lmesh-firmware-handoff.md` for the current
lmesh-first workflow.

Run direct firmware commands through the lmesh UDS forward:

```bash
python tools/serial_cmd.py \
  --port uds:///run/mesh/lmesh-radio-build/USB0.sock \
  --cmd 'status'
```

NAN/LoRa command payloads should include explicit mesh addressing:
`to=<last4>` and `from=<last4>`, where each value is the last four bytes of the
device Wi-Fi STA MAC as lowercase hex without separators. The same value is the
planned LoRa short address. Current firmware still accepts payloads without
`to=` for manual debugging. If `to=` is present and does not match the local
suffix, the command is dropped, except broadcast discovery targets
`to=ffffffff`, `to=0xffffffff`, `to=broadcast`, or `to=all`, which every awake
device accepts.

Run multiple checks through lmesh:

```bash
python tools/serial_cmd.py --port uds:///run/mesh/lmesh-radio-build/USB0.sock \
  --cmd 'lora status=true' \
  --cmd 'nan stats=true' \
  --cmd 'stats'
```

## Core Commands

| Command | Purpose |
| --- | --- |
| `help` | List command summaries. |
| `status` | Compact golden health line intended to fit in one small packet: uptime, CPU/PM, heap, idle/top task, packet counters, queue depth, and battery. |
| `xstatus` | Extended debug status: compact status plus wake/UART loop counters, sleep summary, runtime stats, and radio summaries. `reset=true` clears counters. |
| `stats` | Legacy/full packet, loop, wake, runtime, and battery counters. `reset=true` clears counters. |
| `test` | Non-blocking radio test state. `test cnt=NN` sends two discovery pings followed by `NN` broadcast status pings over raw/custom NAN as active windows permit. |
| `logs` | Recent structured event lines. Supports `count`, `depth`, `max_bytes`, `clear=true`. |
| `messages` | Recent packet buffer. Supports `transport`, `direction`, bounded output, pull/ACK fields. |
| `local_messages` | Local-address packet buffer. |
| `namespace`, `set`, `get`, `list` | NVS/settings namespace and key/value operations. |

## LoRa

| Command | Params | Result |
| --- | --- | --- |
| `lora` | `status=true` | Chip, mode, pins, modulation, RX state, CAD settings, counters. |
| `lora` | `rx=true\|false` | Start/stop background receive. |
| `lora` | `mode=meshtastic\|meshcore` | Set boot preset mode (persisted in NVS). Background RX applies this preset at startup. |
| `lora` | `preset=medium_fast\|medium_slow\|meshcore`, `freq`, `bw`, `sf`, `cr`, `sync_word`, `preamble`, `apply=true` | Update modulation settings. |
| `lora` | `chip=sx127x\|sx1262`, `board=heltec_v3`, pin/PA/TCXO args | Update hardware mapping. |
| `lora` | `cad=true`, `cad_timeout=<ms>` | One channel-activity probe. |
| `lora` | `cad_rx=true\|false`, `cad_tx=true\|false`, `cad_interval_ms`, `cad_rx_ms`, `cad_tx_tries` | Update CAD policy. |
| `lorasend` | `text=...` or `data=hex:...`, `format=meshtastic\|raw`, `hop=0..7`, `portnum`, `timeout` | Send one LoRa packet. |
| `loralisten` | `ms`, `count`, `local_only=true` | Synchronous receive window. |
| `loradump` | none | Radio register/status dump. |
| `loraprobe` | pin lists, `chip`, `save=true` | Probe LoRa wiring candidates. |

### Presets

| Preset | Frequency | BW | SF | CR | Sync Word | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `medium_fast` | (unchanged) | 250 kHz | 9 | 5 | `0x2b` | Meshtastic default channel. |
| `medium_slow` | (unchanged) | 250 kHz | 10 | 5 | `0x2b` | Meshtastic slow channel. |
| `meshcore` | 910.525 MHz | 62.5 kHz | 7 | 5 | `0x34` | MeshCore (US ISM 902–928 MHz). |

Current behavior:

- Background RX reads `lora.mode` from NVS at startup and applies the
  corresponding preset. Default mode is `meshtastic` (MEDIUM_FAST).
- SX127x CAD RX caps effective receive cadence based on preamble airtime. For
  SF9/BW250/preamble 16, configured `cad_interval_ms=2000` effectively runs at
  about 20 ms while CAD RX is active.
- Current SX127x CAD regression status: CAD detects activity with preamble 16,
  but the background CAD RX path has not reliably decoded the packet. The
  required post-flash LoRa feature test is synchronous `loralisten` +
  `lorasend`; keep CAD as a separate regression until decode timing is fixed.
- SX1262 uses hardware duty-cycle RX (`SetRxDutyCycle`) when `cad_rx=true`.
- Default firmware-originated Meshtastic hop limit is `0`.

## Wi-Fi Raw

| Command | Params | Result |
| --- | --- | --- |
| `wifi` | `mode=off` | Stop Wi-Fi/raw modes. |
| `wifi` | `mode=raw` | MGMT/action DMesh raw receive, channel 6 by default. |
| `wifi` | `mode=raw_data` | Explicit promiscuous MGMT+DATA test mode. |
| `wifi` | `mode=sta_idle`, `channel` | STA mode on a fixed channel without association, promiscuous receive, or connect attempts. |
| `wifi` | `mode=sta_idle`, `bssid`, `channel` | STA-idle with a configured target BSSID but no connect attempt. |
| `wifi` | `mode=ap_idle`, `ssid`, `psk`, `channel`, `beacon_ms` | SoftAP without promiscuous receive or mesh IP services. |
| `wifi` | `mode=raw_sta`, `ssid`, `psk`, `channel`, `timeout` | STA plus raw action mode. |
| `wifi` | `mode=raw_ap`, `ssid`, `psk`, `channel` | SoftAP plus raw action mode. |
| `wifi` | `mode=raw_ap_sta` | AP+STA plus raw action mode. |
| `wifi` | `wake_interval_ms=7000` | Set ESP-IDF connectionless-module wake interval before starting raw/NAN Wi-Fi tests. `0` restores ESP-IDF default mode. |
| `wifi` | `raw_action=TEXT` | Send a DMesh raw-NAN SDF action-frame text payload. |
| `wifi` | `raw=hex:...` | Send raw 802.11 frame bytes. |
| `wifi` | `raw_data=TEXT`, `dst`, `bssid`, `ds=none\|to_ap\|from_ap` | Inject one experimental data-frame payload for tests. |
| `wifi` | `raw_stats=true` | Raw RX/TX counters and last-frame summary. |
| `wifi` | `netif_stats=true` | Reports disabled counters; the old esp-netif probe is removed from the normal firmware profile. |
| `wifi` | `scan=true` | Scan visible Wi-Fi networks. |

Default raw mode must stay management/action-frame only. Promiscuous data-frame
receive can flood the ESP32 and belongs only in explicit test modes:
`raw_data`, `raw_sta_data`, `raw_ap_data`, and `raw_ap_sta_data`.

ESP32 product Wi-Fi should use DMesh MGMT/action frames for long-distance
no-association communication. Use normal AP+STA association chains when the
network needs infrastructure forwarding or IP-style connectivity. ESP32 Wi-Fi
modes used for mesh operation should keep MGMT/action receive enabled; data
frame receive remains debug/test-only unless the device is normally associated.
Raw mesh modes do not create default `esp_netif` STA/AP objects, run DHCP, start
SNTP, or assign IPv4/IPv6 addresses. lwIP/IPv6 remains enabled in the ESP-IDF
build because official Wi-Fi NAN selects it in Kconfig, but DMesh Wi-Fi comms
must not depend on IP services.

DMesh action-frame command frames now use NAN SDF action frames with the DMesh
service ID from `nan.rs`:

```text
802.11 action + NAN OUI/body + service_descriptor(dmesh service id, payload)
```

The old vendor-marker raw-action experiment is intentionally not used for
action-frame commands. ESP-IDF promiscuous filters cannot match the DMesh body
pattern; they only select broad packet classes or control-frame subtypes, so
firmware uses MGMT/action hardware filtering plus a fast NAN SDF software
check.

DMesh data-frame payloads are experimental and currently use an IPv4/UDP shim
so Linux/lmesh can reuse packet tooling while the ESP parses only the DMesh
payload:

```text
802.11 data + LLC/SNAP IPv4 + UDP src/dst port 15009
  + 7f 18 fe 34 <mesh-dst4> 04 <payload>
```

The synthetic IPv4 source is `10.<last three source-MAC bytes>` and the
destination is the lmesh announce multicast address `224.0.0.250`. The UDP
payload uses the debug-only DMesh data marker shown above followed by the text
payload.

For data-frame injection, `bssid=...` defaults to a no-DS data frame with
`addr1=dst`, `addr2=sender`, and `addr3=bssid`. Use `ds=to_ap` for STA-to-AP
frames (`addr1=bssid`, `addr3=dst`) or `ds=from_ap` for AP-to-STA frames
(`addr1=dst`, `addr2/addr3=bssid`).

Raw Wi-Fi command routing:

- payloads without a terminal prefix are dispatched as firmware commands;
- action-frame commands receive action-frame responses to the sender MAC;
- data-frame commands receive unicast data-frame responses to the source MAC;
- firmware responses are sent as `resp <response-line>`;
- console notifications to the last valid Wi-Fi command peer are sent as
  `notify <event-line>` over that peer's last response path;
- received `resp ` and `notify ` payloads are terminal records and are not
  dispatched as commands.

`wifi raw_stats=true` includes the last response path (`action` or `data`) and
the last command peer. `mode ping=true` sends a ping on all enabled transports:
LoRa, raw Wi-Fi action broadcast (`ff:ff:ff:ff:ff:ff`), and NAN when running.
Ping responses are directed: action response for action-frame RX and unicast
data response for data-frame RX.

Action-frame sizing:

- ESP-IDF TX accepts raw 802.11 frames up to 1500 bytes in this path;
- firmware `raw_action=TEXT` currently caps the NAN SDF service payload at 255
  bytes;
- official NAN accepts lmesh/Android DMesh `command_text` follow-ups as
  firmware text commands. Firmware `nan send=TEXT` emits `command_text`;
  `packet_chunk` remains accepted for older tests;
- raw/custom NAN SDF follow-ups also dispatch UTF-8 text commands through the
  same registry and return `resp ...` as directed raw NAN SDF follow-ups;
- raw/custom NAN command tests should send `to=<dst-last4>` and
  `from=<src-last4>` inside the text payload. `nan stats=true` exposes
  `raw_cmd_rx`, `raw_resp_rx`, and `raw_resp_tx` for deterministic validation;
- larger payloads need chunking above this command path.

## Sleep / Power

| Command | Params | Result |
| --- | --- | --- |
| `sleep` | `status=true` | RTC deep-sleep state and light-sleep test counters. |
| `sleep` | `test=nan wake_ms=5000 ps=max restore=true` | Official NAN plus light-sleep timer test on targets where official NAN links. |
| `sleep` | `mode=nan_raw wake_ms=7000 active_ms=1000 channel=6 serial=false` | Deep-sleep loop with Wi-Fi fully stopped during sleep, then a raw-NAN SDF receive/transmit window after timer or PRG wake. |
| `sleep` | `mode=deep wake_ms=5000 active_ms=1000 lora=true` | Deep-sleep loop with optional LoRa DIO0 wake. |
| `nan` | `cycle=true wake_ms=2000 active_ms=500 count=5 sync=true dw_tu=512 offset_tu=0 filter=nan` | Non-deep-sleep raw NAN timing test: turn Wi-Fi off between windows, start raw NAN, sync to beacon TSF phase, and log radio start/beacon/window timing. |

For the current S3 raw-NAN experiment, use:

```text
sleep mode=nan_raw wake_ms=7000 active_ms=1000 channel=6 serial=false
```

This is the intended measurement path for "Wi-Fi off for about 7 seconds,
awake for about 1 second". PRG/BOOT remains configured as a deep-sleep wake
source. Any command that promotes the device out of the loop should be followed
by `wifi mode=off` if the test window left Wi-Fi enabled unexpectedly.

Short-loop lab result: USB1 with `wake_ms=2000 active_ms=500` repeatedly woke by
timer and averaged about 37 mA, with about 10 mA during the sleep portion and
about 83 mA during the active raw-NAN Wi-Fi window. Directed commands did not
reliably land in the 500 ms window; use a longer active window for command
latency tests.

Raw NAN timing instrumentation:

- `nan stats=true` includes `last_beacon_local_us`, `last_beacon_tsf_us`, and
  `beacon_age_ms` when the raw NAN sniffer has seen NAN beacons;
- `nan cycle=true ... sync=true` uses that beacon TSF estimate to align active
  windows to `TSF % (dw_tu * 1024) == offset_tu * 1024`;
- USB1 measured raw-NAN radio startup at about 10.5 ms in the no-deep-sleep
  off/on test. With official NAN beacons from USB0/USB2 on channel 6, the first
  beacon after raw radio start was usually seen within about 60-160 ms.

ESP-IDF 5.5 official NAN exposes `op_channel`, `master_pref`, `scan_time`, and
`warm_up_sec` in the public `wifi_nan_config_t`. It does not expose a public
awake Discovery Window interval or an 8 second NAN radio-off schedule knob in
the headers we build against. Official NAN power behavior must therefore be
measured with modem sleep enabled rather than assumed from configuration.

ESP-IDF does expose `esp_wifi_connectionless_module_set_wake_interval()` for
connectionless modules. Firmware exposes it as `wifi wake_interval_ms=<ms>`;
call it before starting the raw/NAN Wi-Fi mode under test, then use
`sleep mode=light ...` or a manual power profile to measure whether the radio
actually idles between wake intervals. This is separate from `esp_now` wake
window APIs and does not enable ESP-NOW.

Verification status:

- raw action command/response works between ESP32 boards;
- verified on USB0/USB1 after flashing: USB0 sent
  `wifi raw_action="wifi raw_stats=true" dst=<USB1 STA MAC> channel=6`, USB1
  dispatched it as a command, and USB0 received a `resp raw_monitor=...`
  action-frame response;
- received ESP-IDF action frames include a four-byte trailer in the promiscuous
  buffer; firmware strips that trailer before command dispatch;
- official NAN start on USB0 with `nan start=true backend=official ... channel=6`
  kept the reported Wi-Fi channel at `ch=6 second=none`; action-frame commands
  from USB1 to USB0 still reached the raw command path while official NAN was
  running;
- AP+STA plus raw action works as a control path: USB1 `raw_ap` open AP on
  channel 6 and USB0 `raw_ap_sta` associated to it while retaining
  `raw_monitor=true filter=dmesh`; action-frame commands from USB0 reached USB1;
- raw promiscuous data command/response works between ESP32 boards with the
  IPv4/UDP shim above;
- unassociated `sta_idle` netif receive did not deliver injected unicast or
  multicast data frames (`netif_rx=0`) in the old esp-netif probe experiment.
  That probe has been removed; efficient non-promiscuous data RX still needs an
  associated AP/STA test path or a lower-level Wi-Fi driver callback that does
  not create IP services.
- `ap_idle` and `sta_idle bssid=...` are the non-promiscuous data-frame test
  modes. `wifi netif_stats=true` now reports disabled counters because the old
  esp-netif callback path was removed.
- Tested no-association data-frame delivery with receiver promiscuous disabled:
  AP receiver `ap_idle` did not receive unicast-to-AP, broadcast, no-DS+BSSID,
  or ToDS frames from an unassociated sender; STA receiver `sta_idle bssid=...`
  did not receive unicast-to-STA, broadcast, no-DS+BSSID, or FromDS frames.
  Both stayed at `netif_rx=0`.
- Repeating the STA fake-BSSID test with the well-known NAN BSSID
  `50:6f:9a:01:05:01` also stayed at `netif_rx=0`. Starting official NAN on
  the receiver and injecting data frames from a non-NAN sender with the NAN
  BSSID did not produce a DMesh data command; observed NAN `match`/`followup`
  counters came from proper NAN service traffic from another peer.
- AP/AP+STA chaining test: USB0 in `raw_ap` and USB1 in `raw_ap_sta` both kept
  `raw_monitor=true filter=dmesh`. An earlier build used default esp-netifs and
  briefly showed `sta_ip=192.168.4.2`; this was an unwanted lwIP/DHCP side
  effect and raw mesh modes now avoid creating those default netifs. Directed
  DMesh MGMT/action pings worked both directions between USB0 and USB1, with
  action-frame responses received on the sender.

Infra boot radio settings:

- `wifi.mode=nan` is the default infra Wi-Fi mode and now means raw/custom NAN
  duty cycle on all ESP targets;
- raw-NAN duty cycle starts a short raw-NAN SDF active window, drains queued
  messages, sends a reboot discovery ping with `from=<last4>`, then turns Wi-Fi
  off until the next window. Defaults: `nan.wake_ms=2000`,
  `nan.active_ms=500`, `nan.channel=6`;
- `power.profile=dfs` is the default on all ESP targets: dynamic frequency
  scaling enabled, automatic light sleep disabled;
- `wifi.mode=nan_sleep` makes infra boot enter the raw-NAN deep-sleep loop.
  It wakes on timer/PRG, opens a raw-NAN active window, then deep-sleeps again.
  Tune with `nan.wake_ms`, `nan.active_ms`, and `nan.channel`. If
  `lora.enabled=true`, LoRa is also armed as a wake/listen source.
- `wifi.mode=official_nan` starts Espressif official NAN explicitly on classic
  ESP32 boards for comparison tests;
- `wifi.mode=sta_idle` starts unassociated STA-idle mode;
- `wifi.mode=off` disables infra Wi-Fi startup;
- `wifi.mode=raw` starts the older raw monitor test mode explicitly;
- `wifi.ssid` is used by STA-oriented tests;
- `lora.enabled=true` is the default and starts LoRa background RX when a radio
  is detected; `lora.enabled=false` disables infra LoRa RX startup.

## BLE

| Command | Params | Result |
| --- | --- | --- |
| `ble` | `start=true\|stop=true` | Start/stop BLE runtime. |
| `ble` | `mode=gatt\|connectable` | Start local GATT/connectable mode. |
| `ble` | `companion=true save=true` | Persist companion mode and start companion runtime. |
| `ble` | `pairing=request`, `timeout_ms`, `confirm_ms` | Open pairing request/confirm windows. |
| `ble` | `pairing_recovery=true` | Clear bonds and advertise for recovery. |
| `ble` | `reset_pairing=true` | Clear pairing state and saved companion flags. |
| `ble` | `advertise=true`, `event=...`, `payload=hex:...` | Advertise DMesh event payload. |
| `ble` | `send=hex:...` | Notify a connected client. |
| `ble` | `stats=true`, `bonds=true` | BLE state, counters, and bond summary. |

BLE is for nearby companion-phone control. Infra mode should not depend on BLE
unless explicitly started for testing.

## Mode and Sleep

| Command | Params | Result |
| --- | --- | --- |
| `mode` | `status=true` | Current companion/infra state and radio policy. |
| `mode` | `companion=true\|infra=true save=true` | Switch persisted operating mode. |
| `mode` | `advertise=true window_ms=... adv_ms=...` | Open companion advertising window. |
| `mode` | `active=true ms=...` | Keep active for a bounded window. |
| `mode` | `raw_wifi=true channel=6` | Enable raw Wi-Fi under mode policy. |
| `mode` | `lora_sleep_listen=true save=true` | Persist companion LoRa sleep-listen preference. |
| `mode` | `ping=true` | Send ping across enabled transports. |
| `power` | `status=true` | Current CPU frequency, XTAL, PM min/max, light-sleep flag, internal heap, PSRAM heap, task count, and tick counter. |
| `power` | `profile=dfs\|perf\|low\|auto save=true min_mhz=... max_mhz=... light=true\|false` | Configure ESP-IDF PM. Default boot profile is `dfs`: dynamic frequency scaling enabled, automatic light sleep disabled. |
| `nvs` | `set key=uart.active_ms value=10000` | Configure the debug UART output/input window in milliseconds. Boot, PRG/button/DTR edge, and UART input open the window; firmware UART output is dropped while the window is closed. |
| `sleep` | `status=true` | Sleep/PM/radio state and counters. |
| `sleep` | `test=ble\|raw\|raw_data\|sta\|ap\|nan ms=... restore=true` | Bounded light-sleep experiment with timer recovery. |
| `sleep` | `mode=deep wake_ms=... active_ms=... lora=true|false start=true` | Enter deep sleep with timer and button wake. LoRa deep-sleep listen is opt-in with `lora=true`. |
| `sleep` | `mode=light start=true\|stop=true ...` | Manual light-sleep/PM controls. |

Never use sleep paths without a timer or button recovery path. Infra mode should
not deep sleep.

## Hardware and Probe

| Command | Params | Result |
| --- | --- | --- |
| `battery` | `status=true`, `pin`, `divider`, `ctrl_pin`, `ctrl_level`, `save=true` | Battery ADC reading and saved config. |
| `adcprobe` | `pins=32,33,34,35,36,39 interval_ms=... count=...` | ADC sample table. |
| `button` | `status=true`, `gpio=0`, `enabled=true`, `save=true` | Button config and press count. |
| `gpio` | `pin`, `mode=input\|output`, `level=0\|1` | GPIO diagnostics. |
| `rgbled` | `pin=N off=true`, or `pin=N r=0..255 g=0..255 b=0..255` | Sends one WS2812/SK6812-style GRB LED frame using RMT. Useful for generic ESP32-S3 boards whose addressable status LED is often on GPIO48 or GPIO38. |
| `i2cconfig` | `sda`, `scl`, `freq`, `save=true` | I2C config. |
| `i2cprobe`, `i2cdetect`, `i2cget`, `i2cset`, `i2cdump` | I2C diagnostics. |

On classic ESP32, avoid ADC2 pins while Wi-Fi is active. Use ADC1 pins
`32,33,34,35,36,39` for battery probing.

## NAN

| Command | Params | Result |
| --- | --- | --- |
| `nan` | `start=true\|stop=true`, `backend=official\|raw`, `role=publish\|publisher_solicited\|subscribe\|both`, `service=dmesh`, `channel=6` | Start/stop NAN/raw NAN-like mode. `publisher_solicited` is the low-duty responder mode for lmesh/Android active subscribers. |
| `nan` | `send="status"` | Send a DMesh NAN follow-up to the most recent NAN peer. Official NAN follow-up payloads that validate as text commands are dispatched through the shared command registry and answered with a `resp ...` follow-up. |
| `nan` | `stats=true` | NAN support, counters, role/backend state, beacon timing, queued raw-NAN work, and raw command/response counters. |

Official NAN on classic ESP32 is an explicit comparison mode and uses a
low-power-biased default for power tests:
`scan_time=1`, `warm_up_sec=2`, passive subscribe, low master preference, and
`WIFI_PS_MAX_MODEM` after NAN starts. `sleep ... nan=true` now starts official
NAN instead of recording a skipped request.

Use `role=both` when testing ESP-to-ESP discovery without a host/phone active
subscriber. Use `role=publisher_solicited` when lmesh or Android owns active
subscribe and the ESP should only respond to matching subscribers instead of
broadcasting unsolicited publish frames every discovery window.

Raw/custom NAN command/response is the current reliable ESP-to-ESP validation
path. Example:

```bash
python tools/nan_pair_test.py --backend raw \
  --a uds:///run/mesh/lmesh-radio-build/USB1.sock \
  --a-mac 84:0d:8e:07:41:70 \
  --b uds:///run/mesh/lmesh-radio-build/USB3.sock \
  --b-mac fc:f5:c4:0e:f1:e8 \
  --iterations 5
python tools/nan_stress_test.py --backend raw \
  --a uds:///run/mesh/lmesh-radio-build/USB1.sock \
  --a-mac 84:0d:8e:07:41:70 \
  --b uds:///run/mesh/lmesh-radio-build/USB3.sock \
  --b-mac fc:f5:c4:0e:f1:e8 \
  --iterations 100 --batch 10
```

The pair/stress helpers keep both serial consoles open, include `to=`/`from=`
tokens in each command payload, and validate `raw_cmd_rx`, `raw_resp_tx`, and
`raw_resp_rx`.

For fleet discovery, send a broadcast command such as
`dmesh.ping type=status to=ffffffff from=<host-last4>`. Each awake firmware node
should respond directly to the sender with its compact status/pong. Host
`lmesh` currently exposes `ping`, `send`, `wifi.nan.default`,
`wifi.nan.status`, `wifi.nan.events`, `wifi.nan.transmit`, and
`wifi.nan.ping`; the host queue that holds follow-up traffic for sleepy ESPs
for the next 8 second wake cycle is a host-side TODO, not firmware behavior yet.

Firmware send-test helper:

```text
test cnt=50 wake_ms=4000 active_ms=500 discovery=2
sleep mode=nan_raw channel=6 start=true
```

`test cnt=NN` returns immediately and stores its state in RTC memory. Each
raw-NAN active window sends at most one broadcast `dmesh.ping` with
`to=ffffffff` and this device's `from=<last4>`. The first `discovery` pings are
`type=discover`; the remaining `NN` are `type=status`. `test status=true`
reports `remaining`, `sent`, and received raw-NAN responses seen by the sender.
When a send test is active, `sleep mode=nan_raw start=true` defaults to the
test's `wake_ms` and `active_ms` values, so the short test cadence can be set on
the `test` command.

Official NAN command delivery works into the firmware queue, but directed
response routing is not currently reliable in the full lab cluster with host
lmesh, wpa_supplicant NAN, Android, and multiple ESP boards active. Treat
official NAN response tests as an open item until `nan_pair_test.py
--backend official` passes with response expectations enabled.

Companion mode should not depend on ESP NAN. Android can own NAN in companion
scenarios; ESP raw action frames are an ESP-side Wi-Fi experiment.

## lmesh Proxying

`lmesh` should treat this firmware as a radio adapter:

- list serial/BLE/raw-Wi-Fi firmware adapters in `radios.list`;
- expose curated tools from `resources/tools.json`;
- translate tool calls into firmware commands;
- normalize responses into `lmesh` neighbor/link/message records;
- keep encryption/auth at the mesh layer, not in this text command ABI.

Production callers should prefer `lmesh send radio=...` over direct firmware
commands. For example, `send radio=lora payload=...` may use a local ESP over
UART, a companion ESP reached through Android BLE/JNI, or a remote ESP exposed
by an SSH-forwarded `lmesh` socket.
