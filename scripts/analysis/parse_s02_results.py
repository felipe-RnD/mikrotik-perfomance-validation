#!/usr/bin/env python3
"""
Scenario 02 (L3 Baseline) Results Parser

Parses T-Rex validation logs and DUT monitor logs to enrich the basic JSON
results with detailed performance metrics.

Usage:
    python parse_s02_results.py <results_directory>

Example:
    python parse_s02_results.py /opt/versa-sdwan-performance-test/results/l3_baseline_sdwan_20251126T094842

The script will:
1. Find all s2_l3_*.json files in the directory
2. Parse corresponding validation and monitor logs
3. Update JSON files with enriched data
4. Generate a consolidated s02_summary.json
"""

import os
import re
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any
from statistics import mean


# -----------------------------------------------------------------------------
# Data Classes
# -----------------------------------------------------------------------------

@dataclass
class ValidationStats:
    """Metrics extracted from T-Rex validation log"""
    tx_packets: int = 0
    rx_packets: int = 0
    packet_loss_pct: float = 0.0
    tx_bps_l2: float = 0.0
    rx_bps: float = 0.0
    tx_pps: float = 0.0
    rx_pps: float = 0.0
    tx_bps_l1: float = 0.0
    line_util_pct: float = 0.0


@dataclass
class InterfaceStats:
    """Per-interface statistics from DUT monitor"""
    name: str
    rx_pps_avg: float = 0.0
    tx_pps_avg: float = 0.0
    rx_bps_avg: float = 0.0
    tx_bps_avg: float = 0.0
    rx_packets_total: int = 0
    tx_packets_total: int = 0


@dataclass
class SessionStats:
    """Session statistics from DUT monitor"""
    active: int = 0
    created: int = 0
    closed: int = 0
    failed: int = 0
    max_allowed: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    icmp_count: int = 0


@dataclass
class DutStats:
    """Aggregated DUT statistics from monitor log"""
    samples: int = 0
    cpu_load_avg: float = 0.0
    cpu_load_max: float = 0.0
    cpu_load_min: float = 0.0
    mem_load_avg: float = 0.0
    poller_cpu_avg: float = 0.0
    ctrl_cpu_avg: float = 0.0
    load_factor_avg: float = 0.0
    lan_interface: Optional[InterfaceStats] = None
    wan_interface: Optional[InterfaceStats] = None
    sessions: Optional[SessionStats] = None


# -----------------------------------------------------------------------------
# Parsing Functions
# -----------------------------------------------------------------------------

def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text"""
    ansi_pattern = re.compile(r'\x1b\[[0-9;]*[mK]|\[\d+m|\[0m|\[1m|\[22m|\[32m|\[39m|\[36m|\[4m|\[24m')
    return ansi_pattern.sub('', text)


def parse_validation_log(filepath: Path) -> Optional[ValidationStats]:
    """
    Parse T-Rex validation log to extract traffic statistics.
    
    Extracts: opackets, ipackets, Tx/Rx bps, Tx/Rx pps, line utilization
    """
    if not filepath.exists():
        print(f"  Warning: Validation log not found: {filepath}")
        return None
    
    try:
        content = strip_ansi(filepath.read_text())
    except Exception as e:
        print(f"  Error reading {filepath}: {e}")
        return None
    
    stats = ValidationStats()
    
    # Parse opackets (transmitted)
    match = re.search(r'opackets\s+\|\s+(\d+)', content)
    if match:
        stats.tx_packets = int(match.group(1))
    
    # Parse ipackets (received)
    match = re.search(r'ipackets\s+\|\s+(\d+)', content)
    if match:
        stats.rx_packets = int(match.group(1))
    
    # Calculate packet loss
    if stats.tx_packets > 0:
        stats.packet_loss_pct = round(
            ((stats.tx_packets - stats.rx_packets) / stats.tx_packets) * 100, 4
        )
    
    # Parse Tx bps L2 (e.g., "341.43 Mbps")
    match = re.search(r'Tx bps L2\s+\|\s+([\d.]+)\s*([KMG]?)bps', content)
    if match:
        value = float(match.group(1))
        unit = match.group(2)
        stats.tx_bps_l2 = _convert_to_bps(value, unit)
    
    # Parse Tx bps L1
    match = re.search(r'Tx bps L1\s+\|\s+([\d.]+)\s*([KMG]?)bps', content)
    if match:
        value = float(match.group(1))
        unit = match.group(2)
        stats.tx_bps_l1 = _convert_to_bps(value, unit)
    
    # Parse Rx bps
    match = re.search(r'Rx bps\s+\|\s+([\d.]+)\s*([KMG]?)bps', content)
    if match:
        value = float(match.group(1))
        unit = match.group(2)
        stats.rx_bps = _convert_to_bps(value, unit)
    
    # Parse Tx pps (e.g., "31.29 Kpps")
    match = re.search(r'Tx pps\s+\|\s+([\d.]+)\s*([KMG]?)pps', content)
    if match:
        value = float(match.group(1))
        unit = match.group(2)
        stats.tx_pps = _convert_to_pps(value, unit)
    
    # Parse Rx pps
    match = re.search(r'Rx pps\s+\|\s+([\d.]+)\s*([KMG]?)pps', content)
    if match:
        value = float(match.group(1))
        unit = match.group(2)
        stats.rx_pps = _convert_to_pps(value, unit)
    
    # Parse Line Utilization
    match = re.search(r'Line Util\.\s+\|\s+([\d.]+)\s*%', content)
    if match:
        stats.line_util_pct = float(match.group(1))
    
    return stats


def _convert_to_bps(value: float, unit: str) -> float:
    """Convert bandwidth value to bps"""
    multipliers = {'': 1, 'K': 1e3, 'M': 1e6, 'G': 1e9}
    return value * multipliers.get(unit, 1)


def _convert_to_pps(value: float, unit: str) -> float:
    """Convert packet rate to pps"""
    multipliers = {'': 1, 'K': 1e3, 'M': 1e6}
    return value * multipliers.get(unit, 1)


def parse_dut_monitor_log(filepath: Path) -> Optional[DutStats]:
    """
    Parse DUT monitor log to extract system and interface statistics.
    
    Handles multiple iterations and averages the values.
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
    iterations = re.split(r'={80}\nIteration \d+/\d+', content)
    iterations = [it for it in iterations if it.strip() and 'show system load-stats' in it]
    
    if not iterations:
        print(f"  Warning: No valid iterations found in {filepath}")
        return None
    
    # Collect metrics across iterations
    cpu_loads = []
    mem_loads = []
    poller_cpus = []
    ctrl_cpus = []
    load_factors = []
    
    # Interface stats per iteration (keyed by interface name)
    interface_samples: Dict[str, List[Dict]] = {}
    
    # Session stats (take from last iteration)
    session_stats = None
    failed_sessions = 0
    
    for iteration in iterations:
        # Parse system load stats
        # Format: VSN ID, CPU LOAD, POLLER CPU, CTRL CPU, MEM LOAD, LOAD FACTOR
        load_match = re.search(
            r'0\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)',
            iteration
        )
        if load_match:
            cpu_loads.append(int(load_match.group(1)))
            poller_cpus.append(int(load_match.group(2)))
            ctrl_cpus.append(int(load_match.group(3)))
            mem_loads.append(int(load_match.group(4)))
            load_factors.append(int(load_match.group(5)))
        
        # Parse interface statistics table
        # Find the interface stats block
        if_block_match = re.search(
            r'NAME\s+INF\s+STATUS.*?(?=\[ok\]|\Z)',
            iteration,
            re.DOTALL
        )
        if if_block_match:
            if_block = if_block_match.group(0)
            # Parse each interface line
            # Format: NAME HOST INF OPER STATUS RX_PACKETS RX_PPS RX_BYTES RX_ERRORS RX_BPS TX_PACKETS TX_PPS TX_BYTES TX_ERRORS TX_BPS RX_USAGE TX_USAGE
            if_pattern = re.compile(
                r'(vni-\d+/\d+)\s+\w+\s+(up|down)\s+'
                r'(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+'  # RX: packets, pps, bytes, errors, bps
                r'(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)',    # TX: packets, pps, bytes, errors, bps
                re.MULTILINE
            )
            for match in if_pattern.finditer(if_block):
                iface_name = match.group(1)
                if iface_name not in interface_samples:
                    interface_samples[iface_name] = []
                
                interface_samples[iface_name].append({
                    'status': match.group(2),
                    'rx_packets': int(match.group(3)),
                    'rx_pps': int(match.group(4)),
                    'rx_bytes': int(match.group(5)),
                    'rx_bps': int(match.group(7)),
                    'tx_packets': int(match.group(8)),
                    'tx_pps': int(match.group(9)),
                    'tx_bytes': int(match.group(10)),
                    'tx_bps': int(match.group(12)),
                })
        
        # Parse session summary
        session_match = re.search(
            r'session-count\s+(\d+).*?'
            r'session-created\s+(\d+).*?'
            r'session-closed\s+(\d+).*?'
            r'session-count-max\s+(\d+).*?'
            r'tcp-session-count\s+(\d+).*?'
            r'udp-session-count\s+(\d+).*?'
            r'icmp-session-count\s+(\d+)',
            iteration,
            re.DOTALL
        )
        if session_match:
            session_stats = SessionStats(
                active=int(session_match.group(1)),
                created=int(session_match.group(2)),
                closed=int(session_match.group(3)),
                max_allowed=int(session_match.group(4)),
                tcp_count=int(session_match.group(5)),
                udp_count=int(session_match.group(6)),
                icmp_count=int(session_match.group(7)),
            )
        
        # Parse failed sessions from device clients
        failed_match = re.search(r'16\s+0\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)', iteration)
        if failed_match:
            failed_sessions = int(failed_match.group(1))
    
    if session_stats:
        session_stats.failed = failed_sessions
    
    # Build DUT stats with averages
    dut_stats = DutStats(
        samples=len(iterations),
        cpu_load_avg=round(mean(cpu_loads), 1) if cpu_loads else 0,
        cpu_load_max=max(cpu_loads) if cpu_loads else 0,
        cpu_load_min=min(cpu_loads) if cpu_loads else 0,
        mem_load_avg=round(mean(mem_loads), 1) if mem_loads else 0,
        poller_cpu_avg=round(mean(poller_cpus), 1) if poller_cpus else 0,
        ctrl_cpu_avg=round(mean(ctrl_cpus), 1) if ctrl_cpus else 0,
        load_factor_avg=round(mean(load_factors), 1) if load_factors else 0,
        sessions=session_stats,
    )
    
    # Calculate interface averages
    # vni-0/3 is typically LAN (T-Rex facing), vni-0/4 is typically WAN
    for iface_name, samples in interface_samples.items():
        if not samples or samples[0]['status'] == 'down':
            continue
        
        iface_stats = InterfaceStats(
            name=iface_name,
            rx_pps_avg=round(mean(s['rx_pps'] for s in samples), 1),
            tx_pps_avg=round(mean(s['tx_pps'] for s in samples), 1),
            rx_bps_avg=round(mean(s['rx_bps'] for s in samples), 1),
            tx_bps_avg=round(mean(s['tx_bps'] for s in samples), 1),
            rx_packets_total=samples[-1]['rx_packets'],  # Last sample has cumulative
            tx_packets_total=samples[-1]['tx_packets'],
        )
        
        if iface_name == 'vni-0/3':
            dut_stats.lan_interface = iface_stats
        elif iface_name == 'vni-0/4':
            dut_stats.wan_interface = iface_stats
    
    return dut_stats


def dataclass_to_dict(obj) -> dict:
    """Convert dataclass to dict, handling nested dataclasses and None values"""
    if obj is None:
        return None
    if hasattr(obj, '__dataclass_fields__'):
        result = {}
        for field in obj.__dataclass_fields__:
            value = getattr(obj, field)
            result[field] = dataclass_to_dict(value)
        return result
    return obj


# -----------------------------------------------------------------------------
# Main Processing
# -----------------------------------------------------------------------------

# File pattern mapping for each packet size label
# Format: label -> (json_file, validation_log, monitor_log)
FILE_PATTERNS = {
    '64b': ('s2_l3_64b.json', 's2_64b_validation.log', 's2_64b_dut_monitor.log'),
    '512b': ('s2_l3_512b.json', 's2_512b_validation.log', 's2_512b_dut_monitor.log'),
    'large': ('s2_l3_large.json', 's2_large_validation.log', 's2_large_dut_monitor.log'),
    'imix': ('s2_l3_imix.json', 's2_imix_validation.log', 's2_imix_dut_monitor.log'),
}


def process_packet_size(results_dir: Path, packet_size_label: str, loss_threshold: float = 0.2) -> Optional[dict]:
    """
    Process all logs for a single packet size test.
    
    Args:
        results_dir: Directory containing log files
        packet_size_label: One of '64b', '512b', 'large', 'imix'
        loss_threshold: Packet loss threshold for pass/fail determination
    
    Returns:
        Enriched result dictionary or None if JSON not found
    """
    if packet_size_label not in FILE_PATTERNS:
        print(f"  Unknown packet size label: {packet_size_label}")
        return None
    
    json_file, validation_file, monitor_file = FILE_PATTERNS[packet_size_label]
    json_path = results_dir / json_file
    
    if not json_path.exists():
        print(f"  JSON file not found: {json_path}")
        return None
    
    # Load existing JSON
    with open(json_path) as f:
        result = json.load(f)
    
    # Get actual packet size from JSON metadata (1360 for SD-WAN, 1472 for DIA)
    # Fall back to label-derived size for backwards compatibility
    actual_packet_size = result.get('packet_size')
    if actual_packet_size is None:
        # Backwards compatibility: derive from label
        if packet_size_label == 'large':
            actual_packet_size = 1360  # Legacy default
        elif packet_size_label == 'imix':
            actual_packet_size = 'imix'
        else:
            actual_packet_size = int(packet_size_label.replace('b', ''))
    
    # Create display label for output (e.g., "1360b" or "1472b" for large)
    if packet_size_label == 'large':
        display_label = f"{actual_packet_size}b"
    elif packet_size_label == 'imix':
        display_label = 'IMIX'
    else:
        display_label = packet_size_label
    
    print(f"  Processing {display_label}...")
    
    # Parse validation log
    validation_stats = parse_validation_log(results_dir / validation_file)
    
    # Parse DUT monitor log
    dut_stats = parse_dut_monitor_log(results_dir / monitor_file)
    
    # Build enriched result
    enriched = {
        'scenario': result.get('scenario', '02_l3_baseline'),
        'test_mode': result.get('test_mode', 'unknown'),
        'packet_size': actual_packet_size,
        'packet_size_label': packet_size_label,      # Internal label ('large', '64b', etc.)
        'packet_size_display': display_label,        # For reports ('1360b', '64b', 'IMIX')
        'binary_search': {
            'max_rate_gbps': result.get('max_rate_gbps', 0),
            'target_loss_pct': loss_threshold,
        },
        'validation': dataclass_to_dict(validation_stats) if validation_stats else None,
        'dut_stats': dataclass_to_dict(dut_stats) if dut_stats else None,
        'timestamp': result.get('timestamp'),
        'monitoring_log': result.get('monitoring_log'),
    }
    
    # Determine pass/fail based on validation packet loss
    if validation_stats:
        enriched['pass'] = validation_stats.packet_loss_pct <= loss_threshold
    else:
        enriched['pass'] = None  # Unknown if no validation data
    
    return enriched


def process_scenario_02(results_dir: Path, loss_threshold: float = 0.2) -> dict:
    """
    Process all Scenario 02 results in a directory.
    
    Args:
        results_dir: Directory containing all S02 log files
        loss_threshold: Packet loss threshold for pass/fail
    
    Returns:
        Summary dictionary with all packet size results
    """
    results_dir = Path(results_dir)
    
    if not results_dir.exists():
        raise FileNotFoundError(f"Results directory not found: {results_dir}")
    
    print(f"Processing Scenario 02 results from: {results_dir}")
    
    # Process each packet size
    packet_sizes = ['64b', '512b', 'large', 'imix']
    results = {}
    
    for size in packet_sizes:
        enriched = process_packet_size(results_dir, size, loss_threshold)
        if enriched:
            results[size] = enriched
    
    # Build summary
    summary = {
        'scenario': '02_l3_baseline',
        'results_dir': str(results_dir),
        'test_mode': results.get('64b', {}).get('test_mode', 'unknown'),
        'loss_threshold_pct': loss_threshold,
        'packet_size_results': results,
        'summary': {
            'total_tests': len(results),
            'passed': sum(1 for r in results.values() if r.get('pass') is True),
            'failed': sum(1 for r in results.values() if r.get('pass') is False),
            'unknown': sum(1 for r in results.values() if r.get('pass') is None),
        }
    }
    
    # Add performance summary
    perf_summary = []
    for size, data in results.items():
        entry = {
            'packet_size': data.get('packet_size'),
            'packet_size_label': data.get('packet_size_label', size),
            'packet_size_display': data.get('packet_size_display', size),
            'max_rate_gbps': data.get('binary_search', {}).get('max_rate_gbps', 0),
            'validation_loss_pct': data.get('validation', {}).get('packet_loss_pct') if data.get('validation') else None,
            'pass': data.get('pass'),
        }
        if data.get('dut_stats'):
            entry['cpu_load_avg'] = data['dut_stats'].get('cpu_load_avg')
        perf_summary.append(entry)
    
    summary['performance_summary'] = perf_summary
    
    return summary


def save_enriched_results(results_dir: Path, summary: dict):
    """Save enriched results back to files"""
    results_dir = Path(results_dir)
    
    # Map packet size labels to enriched output file names
    enriched_files = {
        '64b': 's2_l3_64b_enriched.json',
        '512b': 's2_l3_512b_enriched.json',
        'large': 's2_l3_large_enriched.json',
        'imix': 's2_l3_imix_enriched.json',
    }
    
    # Save individual enriched JSON files
    for size, data in summary.get('packet_size_results', {}).items():
        if size in enriched_files:
            output_path = results_dir / enriched_files[size]
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"  Saved: {output_path}")
    
    # Save consolidated summary
    summary_path = results_dir / 's02_summary.json'
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"  Saved: {summary_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Parse Scenario 02 (L3 Baseline) results and enrich JSON files'
    )
    parser.add_argument(
        'results_dir',
        type=Path,
        help='Directory containing S02 result files'
    )
    parser.add_argument(
        '--loss-threshold',
        type=float,
        default=0.2,
        help='Packet loss threshold for pass/fail (default: 0.2%%)'
    )
    parser.add_argument(
        '--no-save',
        action='store_true',
        help='Parse only, do not save enriched files'
    )
    
    args = parser.parse_args()
    
    try:
        summary = process_scenario_02(args.results_dir, args.loss_threshold)
        
        print("\n" + "=" * 60)
        print("SCENARIO 02 SUMMARY")
        print("=" * 60)
        print(f"Test Mode: {summary['test_mode']}")
        print(f"Tests: {summary['summary']['total_tests']} total, "
              f"{summary['summary']['passed']} passed, "
              f"{summary['summary']['failed']} failed")
        print("\nPerformance Results:")
        print("-" * 60)
        print(f"{'Packet Size':<12} {'Max Rate':<12} {'Loss %':<10} {'CPU %':<8} {'Pass':<6}")
        print("-" * 60)
        
        for entry in summary['performance_summary']:
            # Use display label for output (shows actual size like "1360b" or "1472b")
            pkt_display = entry.get('packet_size_display', str(entry.get('packet_size', 'N/A')))
            max_rate = f"{entry.get('max_rate_gbps', 0):.3f} Gbps"
            loss = entry.get('validation_loss_pct')
            loss_str = f"{loss:.2f}%" if loss is not None else "N/A"
            cpu = entry.get('cpu_load_avg')
            cpu_str = f"{cpu:.1f}" if cpu is not None else "N/A"
            pass_str = "PASS" if entry.get('pass') else "FAIL" if entry.get('pass') is False else "N/A"
            print(f"{pkt_display:<12} {max_rate:<12} {loss_str:<10} {cpu_str:<8} {pass_str:<6}")
        
        print("-" * 60)
        
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
