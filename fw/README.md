# Local mesh firmware

This is intended for devices that may be used for local communication when 
Internet is not available - using alternative transports.

In particular, current focus is on 'raw' Wifi frames (like ESP-NOW) without ACK and
hardware retry - and LoRA for short messages and discovery on longer range.
Last part is based on and works with MeshTastic low level protocol (packet structure, frequencies - not protobuf or app level), with ideas from MeshCore and Wifi NAN. 

Currently testing on few ESP32 and ESP32S3 I have. 

Like Tasmota, the pins are set at config time - so one binary can be installed
on any device with the right CPU. 

The firmware can be used as 'companion device' - if a battery is used, optimizing
with a lot of sleep, or as 'infrastructure' device if it has a continuous 
power source. Devices do not forward automatically - frames are sent to an Android
or Linux server that may decide how to route.

## Networking

The firmware is setting 'hop count' to 0 - MeshTastic devices should be able to communicate but will not forward. Routing in mesh is using 'infrastructure' like
MeshCore and NAN - but assuming a linux-class machine handling discovery and
picking Gateways - just like a Cloud Mesh.

Network is not trusted - the devices are not involved in security or encription, 
nor in routing decisions. 

Discovery can select local 'egress gateways' - similar to NAN master elections.

The goal is for each device to pick a gateway that can be reached with Wifi frames,
fallback to LoRA only if nothing is in Wifi range or the Wifi paths can't find 
the destination device - or the Internet.

When selecting, signal strength should be used to pick close enough (but not too
close) devices that don't require max transmit power - and adjust the power and speed. Same for LoRA. Using MEDIUM_FAST (Bay Area) - but I expect to use 
discovery and switch to a different channel with higher speed/lower power if 
possible. An interesting question I'm trying to solve is what is the range
of 'raw Wifi' - vs LoRA.

## Changes from MeshTastic

- no UI, web server, AP or Client modes - just packet processing.
- clear separation between battery-powered 'companions' and 'infra'.
- deep sleep and BLE to the paired android in companions - using LoRA and raw Wifi for mesh transport. 
- raw Wifi is going to be used whenever possible, LoRA sparingly.

Not changed:
- packet format (with extensions), radio frequency. 
- a phone may process the meshtastic messages - just not handled on the low end ESP device. 
- forwarding may still be used by a phone using meshtastic text protocols.

Most important for battery operated is the use of deep sleep and optimizing the 
LoRA airtime by using directed circuits on infra nodes, with WiFi (ESP-Now like frames) when possible.

The firmware is generic - LoRA is configured by setting the PINs and chip type.
It uses a text protocol (with an optional CBOR planned), and has many probe and 
debug commands (inspired by old bus pirate)

## Other features

Main feature is 'no features' - no plan for UI on small LCDs, web servers, etc.

Ability to use the pins to read sensors or perform actions is partially available 
and may be extended - but will require some crypto and not a priority.