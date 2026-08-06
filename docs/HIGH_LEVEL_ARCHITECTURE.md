# Tetragon High-Level Architecture

## Overview

This document describes Tetragon's high-level architecture. If it is
incorrect or lacking, please fix it. :D

The sections are ordered to correspond with the order of execution within
Tetragon. This is roughly, in sequence:

* Configuration
* Start user space sensors
* Load BPF programs and maps
* Send messages through ring buffers and maps
* Sensors handle and enrich messages, and access maps
* gRPC handlers enrich sensor events
* Output
  * Events output
  * Metrics update
  * Alerts output
  * Application Model output

## Configuration

### CLI Switches

The CLI switches are defined in `pkg/option/flags*.go`. They are read into the
`pkg/option/config.go:Config` struct on start up.

The Enterprise version of Tetragon inherits all the CLI switches from the OSS
module. These are read into the
`vendor/github.com/cilium/tetragon/pkg/option/config.go:Config` struct on start
up.

### Helm Chart Values

The helm chart values are defined in `install/kubernetes/enterprise/values.yaml`.
These are copied to CLI switches by the rules in
`install/kubernetes/enterprise/templates/_extensions.tpl`.

### Tracing Policies

Tracing policies provide a means of temporary or changeable configuration. The
tracing policy custom resource definitions (CRDs) are specified in
`pkg/k8s/apis/cilium.io/v1alpha1/types.go`.

## Sensors

Sensors in Tetragon are managed by the sensor manager found in
`vendor/github.com/cilium/tetragon/pkg/observer`. The OSS version consists
mainly of the base sensor that detects process execution and exit, plus
tracing sensors that hook arbitrary kernel tracepoints and functions (kprobe
and fentry), and userspace functions (uprobe and usdt). The Enterprise version
extends the OSS base sensor and adds additional sensors, such as for file and
network observability. Sensors are located in `pkg/sensors`.

Sensors may perform initialisation on start up, especially if they are
configured by CLI switches, and should respond to tracing policies being
loaded. Sensors may register handlers for loading certain types of programs
(if they need special handling) and handlers for processing messages from BPF
to user space.

A sensor that starts up automatically can call `AddSensor()` and `EnableSensor()`
on the sensor manager with its sensor definition. A sensor that starts up in
response to a tracing policy, will return a sensor definition from its
`PolicyHandler()` method, which will then be added and enabled by the sensor
manager.

When a sensor has been added and enabled, the sensor manager will load its
maps, pinning those for which it is the owner, followed by its programs. The
sensor manager uses the type of the program to locate its loader; it has a map
of common types, and falls back to types registered by the sensors. If a
program is loaded with a type that was registered by a sensor, the sensor
manager calls its `LoadProbe()` method with the program parameters.

## BPF Programs

The BPF programs loaded by the sensors are located in `bpf`. This directory
has its own `Makefile` that builds all the required objects, which are varied
by macro definitions. Some versions are necessary because changes to kernels
require them; other versions are necessary to make newer functionality
available that would not load on older kernels.

The BPF programs inherit headers from the OSS
`vendor/github.com/cilium/tetragon/bpf` directory. These provide access to the
perf and BPF ring buffers that can be used to send messages to user space.
Messages follow a format that includes an op-code so they can be distinguished
in user space.

BPF programs also store information in BPF maps that are shared with other BPF
programs and also with user space.

## Observer

The observer services the ring buffers in user space and locates a message
handler for the op-code of each received message. These handlers are located
within the sensors.

In order that the messages follow the same formats in user space and BPF, the
definitions are padded for guaranteed alignment. The user space definitions
are located in `pkg/api` and the BPF definitions are usually located in
`bpf/lib`. The alignment checker in `pkg/alignchecker` runs a gotest that
checks all the API structs it knows about to confirm they have matching
layouts.

## Sensor Message Handlers

Typically, the sensor message handlers decode the BPF message to a possible
observer event; some messages are consumed by the sensors; other messages may
be malformed, cached, or only reported in bulk. The sensor can enrich the
message with additional state that it holds. The handlers return the observer
event to the observer.

## Sensor State Observation

Rather than send messages from BPF to user space, some sensors store the
information in BPF maps and extract it in user space as required. These could
be triggered by external events, for example a request to an API requires
information stored in BPF maps. Alternatively, they could be triggered by user
space tickers, regularly servicing the maps.

## gRPC Event Handlers

The observer delivers the event to the appropriate gRPC event handler in
`pkg/gRPC`. These event handlers enrich the events with broader state observed
across the gRPC handlers. For example, process and pod information for both
the process associated with the event, and its parent, can be retrieved from
the process cache. The event handlers also reformat data into more
human-readable formats by, for example, converting IP addresses from a raw
byte format to a string. The event handlers return an event response that
encapsulates the produced event.

## Metrics

The gRPC event handlers also update event metrics, located in
`pkg/metrics`. Other parts of Tetragon, and the sensors in particular, also
update these metrics. Metrics can be enable with a CLI switch and accessed via
HTTP.

## Events Output

Tetragon events can be written to rotating log files in JSON, specified by
CLI switches. They can also be accessed in real-time via the `tetra` tool.

## Alerts

Needs information.

## Application Model

Needs information.
