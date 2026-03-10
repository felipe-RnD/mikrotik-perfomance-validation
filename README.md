# MikroTik Performance Validation Framework

```
mikrotik-perfomance-validation/
│
├── ansible.cfg                                  # Ansible runtime config (roles path, SSH args)
│
├── inventory/
│   ├── hosts.yml                                # ★ Device inventory — set your lab IPs here
│   └── group_vars/
│       ├── all.yml                              # ★ Global vars: result paths, IPs, thresholds
│       ├── trex_server.yml                      # T-Rex binary search defaults & install dir
│       ├── k6_server.yml                        # K6 binary path, VU counts, latency threshold
│       ├── app_server.yml                       # App server interface name (for XDP reflector)
│       └── mikrotik_devices.yml                 # MikroTik SSH connection defaults
│
├── host_vars/
│   ├── dut.yml                                  # ★ DUT identity: platform_name, interfaces, IPs
│   └── fitlet3.yml                              # Platform profile: speed limits, session ceiling
│
├── playbooks/
│   │
│   ├── 01_validate_environment.yml              # ★ Step 1 — Pre-flight: SSH + binary checks
│   ├── 96_validate_k6_control.yml               # Standalone K6 connectivity smoke-test
│   ├── 97_validate_trex_control.yml             # Standalone T-Rex connectivity smoke-test
│   ├── 98_validate_dut_control.yml              # Standalone DUT SSH + monitoring smoke-test
│   ├── 99_run_full_test_suite.yml               # ★ Orchestrator — runs S2 → S3 → S4 → S5
│   ├── 100_enrich_scenario.yml                  # Post-run enrichment helper
│   ├── 100_generate_master_report.yml           # Consolidated report across all scenarios
│   │
│   ├── scenarios/
│   │   ├── 01b_noise_baseline.yml               # ★ Step 2 — Calibrate loss thresholds (once per platform)
│   │   ├── 01b_noise_iteration.yml              # (included by 01b — low-load phase)
│   │   ├── 01b_stress_iteration.yml             # (included by 01b — stress calibration phase)
│   │   ├── 01b_observer_iteration.yml           # (included by 01b — observer-effect phase)
│   │   ├── 02_l3_baseline.yml                   # ★ Step 3 — Max throughput per packet size
│   │   ├── 03_scaling_and_quality.yml           # ★ Step 4 — Throughput + K6 app quality
│   │   ├── 03_scaling_iteration.yml             # (included by 03 — per-iteration logic)
│   │   ├── 04_session_scalability.yml           # ★ Step 5 — Session table ceiling (ASTF)
│   │   └── 05_extended_stability.yml            # ★ Step 6 — Soak test / memory leak detection
│   │
│   └── utils/
│       ├── run_monitoring.yml                   # DUT telemetry subprocess wrapper (async)
│       └── run_trex_load.yml                    # T-Rex background load subprocess wrapper (async)
│
├── roles/
│   ├── 01_validation/tasks/
│   │   ├── main.yml                             # Entry point — includes per-device checks
│   │   ├── trex.yml                             # T-Rex reachability & service checks
│   │   ├── k6.yml                               # K6 binary, route, and gateway checks
│   │   ├── app_server.yml                       # App server XDP reflector checks
│   │   └── mikrotik.yml                         # MikroTik SSH and interface checks
│   │
│   ├── 02_trex_control/
│   │   ├── tasks/
│   │   │   ├── binary_search.yml                # ★ Iterative max-rate discovery
│   │   │   ├── binary_search_iteration.yml      # Single binary search step
│   │   │   ├── start_test.yml                   # ★ Run T-Rex STL or ASTF test
│   │   │   ├── stop_test.yml                    # Graceful T-Rex stop
│   │   │   ├── multi_sample_measure.yml         # Multi-sample measurement (S1b)
│   │   │   └── multi_sample_single.yml          # Single sample helper
│   │   ├── templates/
│   │   │   ├── l3_profile.py.j2                 # T-Rex STL profile: 64b / 512b / 1472b
│   │   │   ├── imix_profile.py.j2               # T-Rex STL profile: IMIX mix
│   │   │   └── session_ramp_profile.py.j2       # T-Rex ASTF profile: TCP session ramp
│   │   └── files/
│   │       ├── xdp_loader.c                     # ★ XDP reflector source (compile on app server)
│   │       ├── l3_reflector.c                   # Alternative L3 reflector source
│   │       ├── app_server_dpdk_reflect.c        # DPDK reflector source
│   │       └── Makefile                         # Build all reflector binaries
│   │
│   ├── 03_dut_control/tasks/
│   │   └── monitor_stats_loop.yml               # ★ Tcl/Expect SSH loop — collects RouterOS telemetry
│   │
│   ├── 04_dut_provision/
│   │   ├── tasks/
│   │   │   └── get_vm_profile.yml               # Auto-detect DUT VM profile (RAM/CPU)
│   │   └── templates/
│   │       └── vm_profiles.yml.j2               # Profile definitions template
│   │
│   └── 05_k6_control/
│       ├── tasks/
│       │   └── run_test.yml                     # ★ Copy script, run K6, fetch results JSON
│       └── files/
│           ├── k6_transaction_test.js           # ★ K6 test script (HTTP + DB profiles)
│           └── mock_backend.py                  # Local mock server for dev/testing
│
├── scripts/analysis/
│   ├── parse_s01b_results.py                    # Parses S1b noise logs → calibration JSON
│   ├── parse_s02_results.py                     # ★ Parses S2 T-Rex logs → s02_summary.json
│   ├── parse_s03_results.py                     # Parses S3 T-Rex + K6 logs → s03_summary.json
│   ├── parse_s04_results.py                     # Parses S4 session logs → s04_summary.json
│   └── parse_s05_results.py                     # Parses S5 stability logs → s05_summary.json
│
└── docs/
    └── parameters_config.md                     # Variable reference and tuning guide
```
> **★** marks the files most commonly edited when adapting the framework to a new lab or DUT.

---

An Ansible-based automation framework for validating the full forwarding capacity of
MikroTik RouterOS devices in standalone (single-path) mode. It drives T-Rex for
wire-rate traffic generation and K6 for application-level quality measurement,
collecting DUT telemetry at every stage and producing structured JSON reports.

---

## Table of Contents

1. [Why T-Rex and K6?](#why-t-rex-and-k6)
2. [Test Architecture](#test-architecture)
3. [Lab Topology](#lab-topology)
4. [Prerequisites](#prerequisites)
5. [Repository Layout](#repository-layout)
6. [Configuration](#configuration)
7. [Playbook Guide](#playbook-guide)
8. [Running the Full Suite](#running-the-full-suite)
9. [Results Structure](#results-structure)
10. [Troubleshooting](#troubleshooting)

---

## Why T-Rex and K6?

### T-Rex — Wire-Rate Packet Generation

MikroTik RouterOS performance is fundamentally limited by **packets per second (PPS)**,
not raw bandwidth. A 1 GbE interface saturates at ~1.49 Mpps with 64-byte frames, but
only ~83 Kpps at 1500 bytes — a 17× difference at the same link speed. Tools like
`iperf3` operate at the application layer and cannot generate traffic at the rates
needed to find real forwarding ceilings.

**T-Rex** is a DPDK-accelerated, stateless (STL) and stateful (ASTF) traffic generator
that bypasses the Linux kernel and drives NICs at true wire speed. This framework uses it to:

- **Binary search** the maximum sustainable forwarding rate per packet size (64b, 512b,
  1472b, IMIX) with a configurable loss threshold (default 0.003%).
- **Sustain a background load** (70% of discovered ceiling) during application tests
  so K6 measures quality *under real forwarding pressure*.
- **Ramp TCP sessions** (ASTF mode) to find the connection table ceiling and measure
  connections-per-second (CPS) capacity for Scenario 4.

Without wire-rate PPS pressure, MikroTik CPU and fastpath bottlenecks remain hidden.

### K6 — Application-Layer Quality Under Load

Forwarding rate alone does not tell the full story. A device that forwards 950 Mbps
but adds 800 ms of latency to HTTP transactions fails in production. **K6** runs
concurrent virtual users against real application endpoints (HTTP, database) *while
T-Rex is holding the background load*, so the framework captures:

- HTTP transaction latency (P95, P99)
- Database query response time
- Error rates under sustained forwarding stress

This combination — T-Rex for wire-rate stress, K6 for application quality — is the
standard methodology for validating SD-WAN and routing platforms.

---

## Test Architecture

```
 ┌──────────────────────────────────────────────────────────────────────────────────┐
 │  Dell XR5610 (Eve-OS)                                                            │
 │  ┌────────────────────────┐   ┌────────────────────────┐                         │
 │  │  Ansible Controller    │   │  Web/App Server        │                         │
 │  │  (Ubuntu VM)           │   │  (Ubuntu VM)           │                         │
 │  │  10.1.1.x/24           │   │  LAN: 10.0.0.2/24      │                         │
 │  └──────────┬─────────────┘   └───────────┬────────────┘                         │
 │             │  eth6 (MGMT)                │  SFP+ 10G                            │
 └─────────────┼─────────────────────────────┼────────────────────────────────────--┘
               │                             │ VLAN202
               │ VLAN201                     ▼
               │                   ┌──────────────────────┐
               │                   │   Cisco 1300 (top)   │
               │◄──── Control ────►│   SFP+: 10.0.0.1/24  │◄── gi12 ── Internet
               │      Plane        │   192.168.100.1/24   │
               │                   └──────────┬───────────┘
               │                              │ VLAN100 Trunk (Path 1 - 1Gb)
               │                              │ WAN: 192.168.100.100/24
               ▼                              ▼
 ┌─────────────────────────┐       ┌──────────────────────────────────┐
 │   MGMT Switch           │       │   MikroTik DUT                   │
 │   VLAN1: 10.1.1.1/24    │◄─────►│   (Lanner-1516A / 1510D / Fitlet)│
 │   Mgmt: 10.130.140.14   │ ether2│   MGMT  ether2:  10.1.1.20/24   │
 └────────┬────────────────┘       │   WAN   ether1:  VLAN100 trunk   │
          │                        │   LAN   ETH3:    172.16.1.1/24   │
          │ Control Plane (MGMT)   │                  172.16.0.1/24   │
          │                        └──────────┬───────────────────────┘
          │                                   │ ETH3 trunk
          │                          ┌────────┴────────┐
          │                          │  Cisco 1300      │
          │                          │  (bottom switch) │
          │                          │  gi3: 10.130.140.20│
          │                          └───┬──────────┬───┘
          │                   VLAN200    │          │ VLAN203
          │                   172.16.1.x │          │ 172.16.0.x
          │                              ▼          ▼
          │           ┌──────────────────────┐  ┌──────────────────────┐
          │           │  T-Rex               │  │  K6 / Grafana        │
          │           │  Lanner-1516A        │  │  1510D (Eve-OS)      │
          │           │  (Baremetal)         │  │                      │
          └──────────►│  MGMT: 10.1.1.10/24  │  │  MGMT: 10.1.1.70/24 │◄──┘
                      │  enp2s0f0            │  │  enp4s0              │
                      │  Test: 172.16.1.2/30 │  │  Test: 172.16.0.2/30 │
                      │  Route→ 10.0.0.0/24  │  │  Route→ 10.0.0.0/24  │
                      │  via 172.16.1.1      │  │  via 172.16.0.1      │
                      └──────────────────────┘  └──────────────────────┘
```

**Control plane:** Ansible Controller → MGMT Switch (10.1.1.x/24) → all devices via SSH.

**Data plane (T-Rex):**
`T-Rex enp2s0f0` → `VLAN200` → `Cisco 1300 gi1` → `MikroTik ETH3 (172.16.1.1)` → MikroTik routing → `ether1 WAN` → `VLAN100 trunk` → `Cisco 1300 gi7` → `VLAN202` → `App Server (XDP reflector)`

**Data plane (K6):**
`K6 enp4s0` → `VLAN203` → `Cisco 1300 gi2` → `MikroTik ETH3 (172.16.0.1)` → MikroTik routing → same WAN path → `App Server`

---

## Lab Topology

| Device | Hardware | Role | Management IP | Test IP |
|---|---|---|---|---|
| `trex-01` | Lanner-1516A (baremetal) | Traffic Generator (T-Rex STL/ASTF) | 10.1.1.10 | 172.16.1.2/30 |
| `k6-01` | 1510D (Eve-OS VM) | App Test Client (K6) + Grafana | 10.1.1.70 | 172.16.0.2/30 |
| `app-01` | Dell XR5610 (Eve-OS VM) | Web/App Server (XDP Reflector) | 10.1.1.60 | 10.0.0.2/24 |
| `dut` | Lanner-1516A / 1510D / Fitlet | MikroTik RouterOS DUT | 10.1.1.118 (ether2) | — |
| `cisco-sw-top` | Cisco 1300 | WAN uplink + VLAN202 to App Server | 192.168.100.1 | 10.0.0.1/24 |
| `cisco-sw-bot` | Cisco 1300 | LAN trunk (VLAN200/203) to T-Rex & K6 | 10.130.140.20 | — |
| `mgmt-sw` | MGMT Switch | Management network (10.1.1.x/24) | 10.130.140.14 | — |

Interface mapping on DUT (configured in `host_vars/dut.yml`):

| Logical Role | RouterOS Interface | Network |
|---|---|---|
| Management | `ether2` | 10.1.1.20/24 |
| LAN to T-Rex | `vlan200` (on ETH3) | 172.16.1.1/30 (gateway) |
| LAN to K6 | `vlan203` (on ETH3) | 172.16.0.1/30 (gateway) |
| WAN trunk | `ether1` | VLAN100 → 192.168.100.100/24 |

---

## Prerequisites

### Control Node (Ansible Controller)

```bash
# Python 3.8+ and pip
pip install ansible ansible-core

# Required Ansible collections
ansible-galaxy collection install community.general ansible.netcommon

# SSH key for lab access (no passphrase)
ssh-keygen -t rsa -f ~/.ssh/lab_key -N ""
# Copy to T-Rex, K6, App Server, and MikroTik DUT
ssh-copy-id -i ~/.ssh/lab_key scadmin@10.1.1.10   # T-Rex
ssh-copy-id -i ~/.ssh/lab_key scadmin@10.1.1.70   # K6
ssh-copy-id -i ~/.ssh/lab_key scadmin@10.1.1.60   # App Server
# For MikroTik, import via: /user ssh-keys import public-key-file=lab_key.pub user=scadmin
```

### T-Rex Server

- T-Rex installed (e.g. `/opt/trex/v3.x/`)
- Running as a service (`trex` for STL, `trex-astf` for ASTF mode)
- DPDK-compatible NICs bound to `dpdk` driver
- Port 4501 (RPC) reachable from Ansible controller

### K6 Server

- K6 binary installed at `/usr/bin/k6`
- Test scripts in `/opt/k6/scripts/`
  - `k6_transaction_test.js` (handles both HTTP and DB profiles)
- Results directory writable: `/opt/k6/results/`

### App Server

- XDP reflector binary compiled at `/opt/scripts/xdp_loader`
- NIC driver supports XDP (e2k, ixgbe, i40e, etc.)

### MikroTik DUT

- RouterOS 7.x with SSH enabled
- User `scadmin` with SSH key imported
- Interfaces configured as per topology (VLANs, routing)

---

## Repository Layout

```
mikrotik-perfomance-validation/
├── inventory/
│   ├── hosts.yml                    # Device inventory (IPs, groups)
│   └── group_vars/
│       ├── all.yml                  # Global vars (IPs, result paths)
│       ├── trex_server.yml          # T-Rex binary search defaults
│       ├── k6_server.yml            # K6 paths, VU counts, thresholds
│       └── app_server.yml           # App server interface name
├── host_vars/
│   ├── dut.yml                      # DUT-specific: interfaces, platform
│   └── fitlet3.yml                  # Platform profile: speed limits
├── playbooks/
│   ├── 01_validate_environment.yml  # Step 1: Pre-flight checks
│   ├── 96_validate_k6_control.yml   # Standalone K6 connectivity test
│   ├── 97_validate_trex_control.yml # Standalone T-Rex connectivity test
│   ├── 98_validate_dut_control.yml  # Standalone DUT SSH/monitoring test
│   ├── 99_run_full_test_suite.yml   # Orchestrator: runs S2→S5 in sequence
│   ├── 100_generate_master_report.yml
│   ├── scenarios/
│   │   ├── 01b_noise_baseline.yml   # Step 2: Calibrate loss thresholds
│   │   ├── 02_l3_baseline.yml       # Step 3: Throughput per packet size
│   │   ├── 03_scaling_and_quality.yml  # Step 4: Throughput + app quality
│   │   ├── 03_scaling_iteration.yml    # (included by S3, per-path logic)
│   │   ├── 04_session_scalability.yml  # Step 5: Session table ceiling
│   │   └── 05_extended_stability.yml   # Step 6: Soak test (memory leaks)
│   └── utils/
│       ├── run_monitoring.yml       # DUT monitoring subprocess wrapper
│       └── run_trex_load.yml        # T-Rex background load wrapper
├── roles/
│   ├── 01_validation/               # Pre-flight checks (SSH, binaries, routes)
│   ├── 02_trex_control/             # Binary search, start/stop T-Rex
│   ├── 03_dut_control/              # MikroTik SSH monitoring (Tcl Expect)
│   ├── 04_dut_provision/            # DUT profile auto-detection
│   └── 05_k6_control/               # K6 test execution and result fetch
├── scripts/
│   └── analysis/
│       ├── parse_s02_results.py     # Parses S2 T-Rex logs → JSON summary
│       ├── parse_s03_results.py     # Parses S3 T-Rex + K6 logs → JSON summary
│       └── parse_s04_results.py     # Parses S4 session logs → JSON summary
└── results/                         # Auto-created; one dir per suite run
```

---

## Configuration

Before running tests, update these files:

### `inventory/hosts.yml`
Set the actual management IPs of your lab devices.

### `inventory/group_vars/all.yml`
```yaml
results_base_dir: "/home/scadmin/mikrotik-perfomance-validation/results"
app_server_ip: "10.0.0.2"
trex_ip: "172.16.1.2"
dut_trex_lan_ip: "172.16.1.1"   # MikroTik LAN IP facing T-Rex
```

### `host_vars/dut.yml`
```yaml
ansible_host: 10.1.1.118
ansible_user: scadmin
platform_name: fitlet3           # Must match a file in host_vars/

dut_interface_map:
  mgmt: "ether4"
  lan_trex: "vlan200"
  lan_k6: "vlan203"
  wan_trunk: "ether1"
```

### `host_vars/fitlet3.yml` (or your platform file)
```yaml
platform_expected_max_gbps: 0.95
platform_expected_max_sessions: 250000
binary_search_max_gbps: 1.0      # Caps binary search for 1GbE platforms
```

---

## Playbook Guide

Run all commands from the repository root:
```bash
cd /home/scadmin/mikrotik-perfomance-validation
```

---

### Step 1 — Validate Environment

**Playbook:** `01_validate_environment.yml`

Checks that all lab components are reachable and correctly configured before
spending time on long test runs. Validates:
- SSH connectivity to T-Rex, K6, App Server, and MikroTik DUT
- T-Rex binary and service status
- K6 binary presence
- XDP reflector binary on App Server
- Network routes between components

```bash
ansible-playbook playbooks/01_validate_environment.yml -i inventory/hosts.yml
```

All tasks must pass before proceeding. If any fail, fix the connectivity or
configuration issue indicated in the error message.

---

### Step 2 — Baseline Noise Characterization (Optional but Recommended)

**Playbook:** `playbooks/scenarios/01b_noise_baseline.yml`

Run this **once per new platform** before executing the main test suite. It
calibrates the platform-specific packet loss floor so that test thresholds are
set to realistic values rather than generic defaults.

**Phases:**
1. **Low-load baseline** — sends 100 Mbps IMIX traffic and measures inherent loss
   from virtualization/driver overhead (the "noise floor").
2. **Hardware ceiling** — binary search for the true maximum PPS rate using 64-byte
   frames (most stressful for the routing engine).
3. **Stress calibration** — runs 8 samples at 80% of ceiling with DUT monitoring ON
   to quantify the "observer effect" (how much telemetry collection impacts performance).
4. **Observer isolation** — optional phase comparing monitoring-on vs monitoring-off.

**Output:** `results/.../s1b_noise_baseline.json` with recommended loss threshold.
Use that threshold value with `--loss-threshold` when running S2 manually.

```bash
ansible-playbook playbooks/scenarios/01b_noise_baseline.yml -i inventory/hosts.yml
```

---

### Step 3 — L3 Baseline Throughput (Standalone)

**Playbook:** `playbooks/scenarios/02_l3_baseline.yml`

Core throughput characterization. Runs a **binary search** to find the maximum
sustainable forwarding rate for four packet sizes, then validates each rate with
a full-duration run while collecting DUT telemetry (CPU, memory, interface stats,
connection table).

| Test | Profile | What it measures |
|---|---|---|
| 64-byte | `l3_64b` | Maximum PPS (CPU/fastpath limit) |
| 512-byte | `l3_512b` | Mid-range throughput |
| 1472-byte | `l3_1472b` | Near-wire-rate large-packet |
| IMIX | `imix` | Realistic mixed-traffic ceiling |

```bash
ansible-playbook playbooks/scenarios/02_l3_baseline.yml -i inventory/hosts.yml
```

Results are parsed by `parse_s02_results.py` and saved as `s02_summary.json` with
PASS/FAIL per packet size against the configured loss threshold.

---

### Step 4 — Scaling & Application Quality

**Playbook:** `playbooks/scenarios/03_scaling_and_quality.yml`

Tests how the DUT handles simultaneous forwarding load and application transactions.

**Flow per iteration:**
1. Binary search for IMIX ceiling.
2. Start DUT monitoring (async background process).
3. Start T-Rex at **70% of discovered ceiling** (async background process).
4. Wait 10 seconds for T-Rex to stabilize.
5. Run K6 HTTP test (concurrent virtual users against `http://app_server_ip/`).
6. Run K6 DB test (concurrent virtual users against database endpoint).
7. Wait for T-Rex and monitoring to complete.
8. Save per-iteration summary JSON.

```bash
ansible-playbook playbooks/scenarios/03_scaling_and_quality.yml -i inventory/hosts.yml
```

Results parsed by `parse_s03_results.py` → `s03_summary.json` with throughput,
K6 latency (P95), CPU usage, and PASS/FAIL per iteration.

---

### Step 5 — Session Scalability

**Playbook:** `playbooks/scenarios/04_session_scalability.yml`

Finds the connection table ceiling using **T-Rex ASTF mode** (stateful TCP sessions).
Ramps TCP connections at a configured CPS rate for 10 minutes while DUT monitoring
tracks peak concurrent sessions, peak CPU, and memory at peak.

Key configuration in `host_vars/dut.yml`:
```yaml
platform_expected_max_sessions: 250000
session_target_cps: 2000
```

```bash
ansible-playbook playbooks/scenarios/04_session_scalability.yml -i inventory/hosts.yml
```

Results parsed by `parse_s04_results.py` → `s04_summary.json`. PASS if connection
success rate ≥ 95%.

---

### Step 6 — Extended Stability (Soak Test)

**Playbook:** `playbooks/scenarios/05_extended_stability.yml`

Long-duration test at sustained load to detect memory leaks, CPU drift, and
performance degradation over time. Runs for a configurable duration (default:
several hours) with periodic DUT telemetry collection at 60-second intervals.

```bash
ansible-playbook playbooks/scenarios/05_extended_stability.yml -i inventory/hosts.yml
```

---

## Running the Full Suite

The `99_run_full_test_suite.yml` playbook orchestrates Scenarios 2 through 5 in a
single automated run. It:
1. Creates an isolated timestamped results directory (e.g. `results/Suite_Run_20260310T143414/`).
2. Auto-detects the DUT VM profile.
3. Runs S2 → S3 → S4 → S5 in sequence.

```bash
cd /home/scadmin/mikrotik-perfomance-validation
ansible-playbook playbooks/99_run_full_test_suite.yml -i inventory/hosts.yml
```

> **Important:** Always run from the repository root (`/home/scadmin/mikrotik-perfomance-validation`).
> Running from another directory (e.g. `/opt/...`) will cause `playbook_dir` to resolve
> incorrectly and results will be written to a root-owned path, causing permission errors.

### Recommended Full Workflow

```bash
cd /home/scadmin/mikrotik-perfomance-validation

# 1. Validate lab connectivity
ansible-playbook playbooks/01_validate_environment.yml -i inventory/hosts.yml

# 2. Calibrate thresholds (once per new platform)
ansible-playbook playbooks/scenarios/01b_noise_baseline.yml -i inventory/hosts.yml

# 3. Run full automated suite
ansible-playbook playbooks/99_run_full_test_suite.yml -i inventory/hosts.yml
```

---

## Results Structure

Each suite run creates an isolated directory:

```
results/
└── Suite_Run_20260310T143414/
    ├── l3_baseline_mikrotik_20260310T143415/
    │   ├── s2_64b_dut_monitor.log       # Raw DUT telemetry (Tcl Expect output)
    │   ├── s2_64b_validation.log        # T-Rex result for 64b validation run
    │   ├── s2_512b_dut_monitor.log
    │   ├── s2_512b_validation.log
    │   ├── s2_imix_dut_monitor.log
    │   ├── s2_imix_validation.log
    │   └── s02_summary.json             # Parsed summary with PASS/FAIL
    ├── scaling_quality_standalone_*/
    │   ├── s3_scale_1path_dut_monitor.log
    │   ├── s3_scale_1path_trex_70pct.log
    │   ├── s3_scale_1path_k6_http.json
    │   ├── s3_scale_1path_k6_db.json
    │   ├── s3_scale_1path_summary.json
    │   └── s03_summary.json
    ├── session_scalability_standalone_*/
    │   ├── s4_session_dut_monitor.log
    │   ├── s4_session_ramp_trex.log
    │   └── s04_summary.json
    └── extended_stability_standalone_*/
        └── s5_stability_dut_monitor.log
```

### DUT Monitor Log

The `*_dut_monitor.log` files contain raw MikroTik RouterOS CLI output captured
via SSH (Tcl Expect). Each iteration is delimited by a header:
```
================================================================================
Iteration N/M - "TIMESTAMP"
================================================================================
```
The `parse_s0X_results.py` scripts extract CPU%, memory used%, interface
byte/packet counters, and active connection count from these logs.

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `Permission denied` creating Suite dir | Running from wrong directory | `cd /home/scadmin/mikrotik-perfomance-validation` first |
| Monitor log is empty (only SSH banner) | SSH key not used / expect timeout | Verify `~/.ssh/lab_key` is imported on MikroTik DUT |
| Interface stats empty in monitor log | Wrong interface names in `host_vars/dut.yml` | Check with `ssh dut "/interface print terse"` |
| `No valid iterations found` in parser | Monitor log has no recognized CLI output | Check `dut_interface_map` and `monitor_start_delay_sec` |
| T-Rex binary search stuck at 0 Gbps | T-Rex service not running or RPC unreachable | `systemctl status trex` on trex-01; check port 4501 |
| K6 thresholds failed | App server not reachable from K6 | Run `96_validate_k6_control.yml` to diagnose |
| IMIX FAIL at low loss threshold | Platform genuinely at ceiling (expected) | Run `01b_noise_baseline.yml` to calibrate threshold |
| `ansible_job_id` undefined | Async task failed to launch | Check shell task output; verify `become: false` on async tasks |
