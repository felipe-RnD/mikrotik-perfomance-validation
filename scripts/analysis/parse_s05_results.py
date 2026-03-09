#!/usr/bin/env python3
"""
Scenario 05 (Extended Stability) Results Parser

Parses T-Rex long-duration stability logs and DUT monitor logs to create
enriched JSON results with stability analysis over time.

Usage:
    python parse_s05_results.py <results_directory>

Example:
    python parse_s05_results.py /opt/versa-sdwan-performance-test/results/stability_sdwan_20251126

The script will:
1. Find s5_stability_summary.json
2. Parse T-Rex stability test log for packet loss
3. Parse DUT monitor log for stability metrics over time
4. Calculate drift/variance metrics
5. Generate enriched s5_stability_enriched.json and s05_summary.json
"""

import os
import re
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from statistics import mean, stdev
from datetime import datetime


# -----------------------------------------------------------------------------
# Data Classes
# -----------------------------------------------------------------------------

@dataclass
class TrexStabilityStats:
    """Metrics extracted from T-Rex stability test log"""
    duration_sec: int = 0
    tx_packets: int = 0
    rx_packets: int = 0
    packet_loss: int = 0
    packet_loss_pct: float = 0.0
    tx_bps_l2: float = 0.0
    rx_bps: float = 0.0
    tx_pps: float = 0.0
    rx_pps: float = 0.0
    tx_bytes: int = 0
    rx_bytes: int = 0
    line_util_pct: float = 0.0
    cpu_util_pct: float = 0.0


@dataclass
class StabilityPoint:
    """Single monitoring point during stability test"""
    iteration: int
    timestamp: str
    cpu_load: int
    mem_load: int
    session_count: int
    wan_rx_bps: int
    wan_tx_bps: int


@dataclass
class DutStabilityStats:
    """Aggregated DUT statistics during stability test"""
    samples: int = 0
    test_duration_minutes: float = 0.0
    # CPU metrics
    cpu_load_avg: float = 0.0
    cpu_load_max: int = 0
    cpu_load_min: int = 0
    cpu_load_stdev: float = 0.0
    # Memory metrics
    mem_load_avg: float = 0.0
    mem_load_max: int = 0
    mem_load_min: int = 0
    mem_load_stdev: float = 0.0
    # Session metrics
    session_count_avg: float = 0.0
    session_count_max: int = 0
    session_count_min: int = 0
    # Drift analysis (compare first vs last third of samples)
    cpu_drift: float = 0.0  # Positive = increasing over time
    mem_drift: float = 0.0
    # Timeline for visualization
    timeline: List[Dict] = field(default_factory=list)


# -----------------------------------------------------------------------------
# Parsing Functions
# -----------------------------------------------------------------------------

def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text"""
    ansi_pattern = re.compile(r'\x1b\[[0-9;]*[mK]|\[\d+m|\[0m|\[1m|\[22m|\[32m|\[39m|\[36m|\[4m|\[24m')
    return ansi_pattern.sub('', text)


def _convert_to_bps(value: float, unit: str) -> float:
    """Convert bandwidth value to bps"""
    multipliers = {'': 1, 'K': 1e3, 'M': 1e6, 'G': 1e9}
    return value * multipliers.get(unit, 1)


def _convert_to_pps(value: float, unit: str) -> float:
    """Convert packet rate to pps"""
    multipliers = {'': 1, 'K': 1e3, 'M': 1e6}
    return value * multipliers.get(unit, 1)


def parse_stability_trex_log(filepath: Path) -> Optional[TrexStabilityStats]:
    """
    Parse T-Rex stability test log to extract traffic statistics.
    """
    if not filepath.exists():
        print(f"  Warning: Stability T-Rex log not found: {filepath}")
        return None
    
    try:
        content = strip_ansi(filepath.read_text())
    except Exception as e:
        print(f"  Error reading {filepath}: {e}")
        return None
    
    stats = TrexStabilityStats()
    
    # Parse test duration from "Running test for X seconds..."
    match = re.search(r'Running test for (\d+) seconds', content)
    if match:
        stats.duration_sec = int(match.group(1))
    
    # Parse opackets (transmitted)
    match = re.search(r'opackets\s+\|\s+(\d+)', content)
    if match:
        stats.tx_packets = int(match.group(1))
    
    # Parse ipackets (received)
    match = re.search(r'ipackets\s+\|\s+(\d+)', content)
    if match:
        stats.rx_packets = int(match.group(1))
    
    # Calculate packet loss
    stats.packet_loss = stats.tx_packets - stats.rx_packets
    if stats.tx_packets > 0:
        stats.packet_loss_pct = round(
            (stats.packet_loss / stats.tx_packets) * 100, 4
        )
    
    # Parse obytes/ibytes
    match = re.search(r'obytes\s+\|\s+(\d+)', content)
    if match:
        stats.tx_bytes = int(match.group(1))
    
    match = re.search(r'ibytes\s+\|\s+(\d+)', content)
    if match:
        stats.rx_bytes = int(match.group(1))
    
    # Parse Tx bps L2
    match = re.search(r'Tx bps L2\s+\|\s+([\d.]+)\s*([KMG]?)bps', content)
    if match:
        stats.tx_bps_l2 = _convert_to_bps(float(match.group(1)), match.group(2))
    
    # Parse Rx bps
    match = re.search(r'Rx bps\s+\|\s+([\d.]+)\s*([KMG]?)bps', content)
    if match:
        stats.rx_bps = _convert_to_bps(float(match.group(1)), match.group(2))
    
    # Parse Tx pps
    match = re.search(r'Tx pps\s+\|\s+([\d.]+)\s*([KMG]?)pps', content)
    if match:
        stats.tx_pps = _convert_to_pps(float(match.group(1)), match.group(2))
    
    # Parse Rx pps
    match = re.search(r'Rx pps\s+\|\s+([\d.]+)\s*([KMG]?)pps', content)
    if match:
        stats.rx_pps = _convert_to_pps(float(match.group(1)), match.group(2))
    
    # Parse Line Utilization
    match = re.search(r'Line Util\.\s+\|\s+([\d.]+)\s*%', content)
    if match:
        stats.line_util_pct = float(match.group(1))
    
    # Parse CPU utilization
    match = re.search(r'cpu_util\.\s*:\s*([\d.]+)%', content)
    if match:
        stats.cpu_util_pct = float(match.group(1))
    
    return stats


def parse_stability_dut_monitor(filepath: Path) -> Optional[DutStabilityStats]:
    """
    Parse DUT monitor log during stability test.
    Tracks stability metrics over time and calculates drift.
    """
    if not filepath.exists():
        print(f"  Warning: DUT monitor log not found: {filepath}")
        return None
    
    try:
        content = filepath.read_text()
    except Exception as e:
        print(f"  Error reading {filepath}: {e}")
        return None
    
    # Split into iterations
    iterations = re.split(r'={80}\nIteration (\d+)/(\d+) - "([^"]+)"', content)
    
    # Parse iteration data
    points = []
    cpu_loads = []
    mem_loads = []
    session_counts = []
    timestamps = []
    
    i = 1
    while i < len(iterations) - 1:
        iter_num = int(iterations[i])
        total_iters = int(iterations[i + 1])
        timestamp = iterations[i + 2]
        iter_content = iterations[i + 3] if i + 3 < len(iterations) else ""
        
        point = StabilityPoint(
            iteration=iter_num,
            timestamp=timestamp,
            cpu_load=0,
            mem_load=0,
            session_count=0,
            wan_rx_bps=0,
            wan_tx_bps=0,
        )
        
        # Parse CPU/memory from system load stats
        load_match = re.search(r'0\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)', iter_content)
        if load_match:
            point.cpu_load = int(load_match.group(1))
            point.mem_load = int(load_match.group(4))
            cpu_loads.append(point.cpu_load)
            mem_loads.append(point.mem_load)
        
        # Parse session count
        session_match = re.search(r'session-count\s+(\d+)', iter_content)
        if session_match:
            point.session_count = int(session_match.group(1))
            session_counts.append(point.session_count)
        
        # Parse WAN interface stats (vni-0/4)
        wan_match = re.search(
            r'vni-0/4\s+\w+\s+up\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)',
            iter_content
        )
        if wan_match:
            point.wan_rx_bps = int(wan_match.group(1))
            point.wan_tx_bps = int(wan_match.group(2))
        
        timestamps.append(timestamp)
        points.append(point)
        i += 4
    
    if not points:
        print(f"  Warning: No valid iterations found in {filepath}")
        return None
    
    # Calculate test duration from timestamps
    try:
        first_ts = datetime.fromisoformat(timestamps[0].replace('T', ' ').replace('"', ''))
        last_ts = datetime.fromisoformat(timestamps[-1].replace('T', ' ').replace('"', ''))
        duration_minutes = (last_ts - first_ts).total_seconds() / 60
    except:
        duration_minutes = 0
    
    # Calculate drift (compare first third vs last third)
    n = len(cpu_loads)
    third = max(1, n // 3)
    
    if n >= 3:
        first_third_cpu = mean(cpu_loads[:third])
        last_third_cpu = mean(cpu_loads[-third:])
        cpu_drift = round(last_third_cpu - first_third_cpu, 2)
        
        first_third_mem = mean(mem_loads[:third])
        last_third_mem = mean(mem_loads[-third:])
        mem_drift = round(last_third_mem - first_third_mem, 2)
    else:
        cpu_drift = 0
        mem_drift = 0
    
    # Build stats
    stats = DutStabilityStats(
        samples=len(points),
        test_duration_minutes=round(duration_minutes, 1),
        cpu_load_avg=round(mean(cpu_loads), 1) if cpu_loads else 0,
        cpu_load_max=max(cpu_loads) if cpu_loads else 0,
        cpu_load_min=min(cpu_loads) if cpu_loads else 0,
        cpu_load_stdev=round(stdev(cpu_loads), 2) if len(cpu_loads) > 1 else 0,
        mem_load_avg=round(mean(mem_loads), 1) if mem_loads else 0,
        mem_load_max=max(mem_loads) if mem_loads else 0,
        mem_load_min=min(mem_loads) if mem_loads else 0,
        mem_load_stdev=round(stdev(mem_loads), 2) if len(mem_loads) > 1 else 0,
        session_count_avg=round(mean(session_counts), 1) if session_counts else 0,
        session_count_max=max(session_counts) if session_counts else 0,
        session_count_min=min(session_counts) if session_counts else 0,
        cpu_drift=cpu_drift,
        mem_drift=mem_drift,
        timeline=[{
            'iteration': p.iteration,
            'timestamp': p.timestamp,
            'cpu_load': p.cpu_load,
            'mem_load': p.mem_load,
            'session_count': p.session_count,
        } for p in points],
    )
    
    return stats


def dataclass_to_dict(obj) -> dict:
    """Convert dataclass to dict, handling nested dataclasses and None values"""
    if obj is None:
        return None
    if hasattr(obj, '__dataclass_fields__'):
        result = {}
        for field_name in obj.__dataclass_fields__:
            value = getattr(obj, field_name)
            result[field_name] = dataclass_to_dict(value)
        return result
    if isinstance(obj, list):
        return [dataclass_to_dict(item) for item in obj]
    return obj


# -----------------------------------------------------------------------------
# Main Processing
# -----------------------------------------------------------------------------

def process_scenario_05(results_dir: Path,
                        max_loss_pct: float = 0.5,
                        max_cpu_drift: float = 10.0,
                        max_mem_drift: float = 5.0) -> dict:
    """
    Process Scenario 05 (Extended Stability) results.
    
    Args:
        results_dir: Directory containing S05 result files
        max_loss_pct: Maximum acceptable packet loss percentage
        max_cpu_drift: Maximum acceptable CPU drift (increase) over test
        max_mem_drift: Maximum acceptable memory drift over test
    """
    results_dir = Path(results_dir)
    
    if not results_dir.exists():
        raise FileNotFoundError(f"Results directory not found: {results_dir}")
    
    print(f"Processing Scenario 05 results from: {results_dir}")
    
    # Load base JSON
    json_path = results_dir / "s5_stability_summary.json"
    if not json_path.exists():
        raise FileNotFoundError(f"Summary JSON not found: {json_path}")
    
    with open(json_path) as f:
        base_result = json.load(f)
    
    # Parse T-Rex stability log
    trex_stats = parse_stability_trex_log(results_dir / "s5_stability_trex.log")
    
    # Parse DUT monitor log
    dut_stats = parse_stability_dut_monitor(results_dir / "s5_stability_dut_monitor.log")
    
    # Build enriched result
    enriched = {
        'scenario': base_result.get('scenario', '05_extended_stability'),
        'test_mode': base_result.get('test_mode', 'unknown'),
        'config': {
            'wan_paths_enabled': base_result.get('wan_paths_enabled', 0),
            'max_14path_rate_gbps': base_result.get('max_14path_rate_gbps', 0),
            'stability_load_gbps': base_result.get('stability_load_gbps', 0),
            'load_factor': 0.8,  # 80% as per test plan
        },
        'trex_stats': dataclass_to_dict(trex_stats) if trex_stats else None,
        'dut_stats': dataclass_to_dict(dut_stats) if dut_stats else None,
        'timestamp': base_result.get('timestamp'),
    }
    
    # Determine pass/fail
    pass_criteria = {
        'packet_loss': True,
        'cpu_stable': True,
        'mem_stable': True,
    }
    
    if trex_stats:
        pass_criteria['packet_loss'] = trex_stats.packet_loss_pct <= max_loss_pct
    
    if dut_stats:
        pass_criteria['cpu_stable'] = abs(dut_stats.cpu_drift) <= max_cpu_drift
        pass_criteria['mem_stable'] = abs(dut_stats.mem_drift) <= max_mem_drift
    
    enriched['pass_criteria'] = pass_criteria
    enriched['pass'] = all(pass_criteria.values())
    
    # Build summary
    summary = {
        'scenario': '05_extended_stability',
        'results_dir': str(results_dir),
        'test_mode': enriched.get('test_mode', 'unknown'),
        'thresholds': {
            'max_packet_loss_pct': max_loss_pct,
            'max_cpu_drift': max_cpu_drift,
            'max_mem_drift': max_mem_drift,
        },
        'enriched_result': enriched,
        'summary': {
            'test_duration_minutes': dut_stats.test_duration_minutes if dut_stats else 0,
            'samples': dut_stats.samples if dut_stats else 0,
            'tx_packets': trex_stats.tx_packets if trex_stats else 0,
            'rx_packets': trex_stats.rx_packets if trex_stats else 0,
            'packet_loss': trex_stats.packet_loss if trex_stats else 0,
            'packet_loss_pct': trex_stats.packet_loss_pct if trex_stats else 0,
            'cpu_avg': dut_stats.cpu_load_avg if dut_stats else 0,
            'cpu_max': dut_stats.cpu_load_max if dut_stats else 0,
            'cpu_drift': dut_stats.cpu_drift if dut_stats else 0,
            'mem_avg': dut_stats.mem_load_avg if dut_stats else 0,
            'mem_max': dut_stats.mem_load_max if dut_stats else 0,
            'mem_drift': dut_stats.mem_drift if dut_stats else 0,
            'pass': enriched.get('pass', False),
        },
    }
    
    return summary


def save_enriched_results(results_dir: Path, summary: dict):
    """Save enriched results back to files"""
    results_dir = Path(results_dir)
    
    # Save enriched result
    enriched_path = results_dir / 's5_stability_enriched.json'
    with open(enriched_path, 'w') as f:
        json.dump(summary.get('enriched_result', {}), f, indent=2)
    print(f"  Saved: {enriched_path}")
    
    # Save summary
    summary_path = results_dir / 's05_summary.json'
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"  Saved: {summary_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Parse Scenario 05 (Extended Stability) results and enrich JSON files'
    )
    parser.add_argument(
        'results_dir',
        type=Path,
        help='Directory containing S05 result files'
    )
    parser.add_argument(
        '--max-loss',
        type=float,
        default=0.5,
        help='Maximum packet loss percentage for pass (default: 0.5%%)'
    )
    parser.add_argument(
        '--max-cpu-drift',
        type=float,
        default=10.0,
        help='Maximum CPU drift for pass (default: 10%%)'
    )
    parser.add_argument(
        '--max-mem-drift',
        type=float,
        default=5.0,
        help='Maximum memory drift for pass (default: 5%%)'
    )
    parser.add_argument(
        '--no-save',
        action='store_true',
        help='Parse only, do not save enriched files'
    )
    
    args = parser.parse_args()
    
    try:
        summary = process_scenario_05(
            args.results_dir,
            args.max_loss,
            args.max_cpu_drift,
            args.max_mem_drift
        )
        
        print("\n" + "=" * 70)
        print("SCENARIO 05 - EXTENDED STABILITY SUMMARY")
        print("=" * 70)
        print(f"Test Mode: {summary.get('test_mode', 'unknown')}")
        
        s = summary.get('summary', {})
        print(f"\nTest Duration: {s.get('test_duration_minutes', 0):.1f} minutes ({s.get('samples', 0)} samples)")
        
        print(f"\nTraffic Statistics:")
        print(f"  TX Packets:   {s.get('tx_packets', 0):,}")
        print(f"  RX Packets:   {s.get('rx_packets', 0):,}")
        print(f"  Packet Loss:  {s.get('packet_loss', 0):,} ({s.get('packet_loss_pct', 0):.4f}%)")
        
        print(f"\nStability Metrics:")
        print(f"  CPU Load:     avg={s.get('cpu_avg', 0):.1f}%, max={s.get('cpu_max', 0)}%")
        print(f"  CPU Drift:    {s.get('cpu_drift', 0):+.1f}%")
        print(f"  Memory Load:  avg={s.get('mem_avg', 0):.1f}%, max={s.get('mem_max', 0)}%")
        print(f"  Memory Drift: {s.get('mem_drift', 0):+.1f}%")
        
        print(f"\nResult: {'PASS' if s.get('pass') else 'FAIL'}")
        print("-" * 70)
        
        if not args.no_save:
            print("\nSaving enriched results...")
            save_enriched_results(args.results_dir, summary)
            print("\nDone!")
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    exit(main())
