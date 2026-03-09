#!/usr/bin/env python3
"""
Scenario 03 (Scaling and Quality) Results Parser

Parses T-Rex 70% load logs, K6 HTTP/DB results, and DUT monitor logs
for each path count iteration to create enriched JSON results.

Usage:
    python parse_s03_results.py <results_directory>

Example:
    python parse_s03_results.py /opt/versa-sdwan-performance-test/results/scaling_sdwan_20251126

The script will:
1. Find all s3_scale_*path_summary.json files
2. Parse corresponding T-Rex, K6, and DUT monitor logs for each path count
3. Update JSON files with enriched data
4. Generate a consolidated s03_summary.json with scaling analysis
"""

import os
import re
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from statistics import mean, stdev


# -----------------------------------------------------------------------------
# Data Classes
# -----------------------------------------------------------------------------

@dataclass
class TrexLoadStats:
    """Metrics extracted from T-Rex 70% load test log"""
    duration_sec: int = 0
    tx_packets: int = 0
    rx_packets: int = 0
    packet_loss_pct: float = 0.0
    tx_bps_l2: float = 0.0
    rx_bps: float = 0.0
    tx_pps: float = 0.0
    rx_pps: float = 0.0
    tx_bps_l1: float = 0.0
    line_util_pct: float = 0.0
    cpu_util_pct: float = 0.0


@dataclass
class K6Stats:
    """Metrics extracted from K6 JSON results"""
    test_type: str = ""  # "http" or "db"
    total_requests: int = 0
    requests_per_sec: float = 0.0
    vus: int = 0
    vus_max: int = 0
    latency_avg_ms: float = 0.0
    latency_med_ms: float = 0.0
    latency_p90_ms: float = 0.0
    latency_p95_ms: float = 0.0
    latency_max_ms: float = 0.0
    checks_passed: int = 0
    checks_failed: int = 0
    error_rate: float = 0.0
    data_received_bytes: int = 0
    data_sent_bytes: int = 0


@dataclass
class InterfaceStats:
    """Per-interface statistics from DUT monitor"""
    name: str
    rx_pps_avg: float = 0.0
    tx_pps_avg: float = 0.0
    rx_bps_avg: float = 0.0
    tx_bps_avg: float = 0.0
    rx_pps_max: float = 0.0
    tx_pps_max: float = 0.0


@dataclass
class SessionStats:
    """Session statistics from DUT monitor"""
    active_avg: float = 0.0
    active_max: int = 0
    created: int = 0
    closed: int = 0
    failed: int = 0
    max_allowed: int = 0
    tcp_count_max: int = 0
    udp_count_max: int = 0


@dataclass
class DutStats:
    """Aggregated DUT statistics from monitor log"""
    samples: int = 0
    cpu_load_avg: float = 0.0
    cpu_load_max: float = 0.0
    cpu_load_min: float = 0.0
    cpu_load_stdev: float = 0.0
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


def _convert_to_bps(value: float, unit: str) -> float:
    """Convert bandwidth value to bps"""
    multipliers = {'': 1, 'K': 1e3, 'M': 1e6, 'G': 1e9}
    return value * multipliers.get(unit, 1)


def _convert_to_pps(value: float, unit: str) -> float:
    """Convert packet rate to pps"""
    multipliers = {'': 1, 'K': 1e3, 'M': 1e6}
    return value * multipliers.get(unit, 1)


def parse_trex_load_log(filepath: Path, expected_duration: int = 190) -> Optional[TrexLoadStats]:
    """
    Parse T-Rex 70% load test log to extract traffic statistics.
    """
    if not filepath.exists():
        print(f"    Warning: T-Rex load log not found: {filepath}")
        return None
    
    try:
        content = strip_ansi(filepath.read_text())
    except Exception as e:
        print(f"    Error reading {filepath}: {e}")
        return None
    
    stats = TrexLoadStats(duration_sec=expected_duration)
    
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
    
    # Parse Tx bps L2
    match = re.search(r'Tx bps L2\s+\|\s+([\d.]+)\s*([KMG]?)bps', content)
    if match:
        stats.tx_bps_l2 = _convert_to_bps(float(match.group(1)), match.group(2))
    
    # Parse Tx bps L1
    match = re.search(r'Tx bps L1\s+\|\s+([\d.]+)\s*([KMG]?)bps', content)
    if match:
        stats.tx_bps_l1 = _convert_to_bps(float(match.group(1)), match.group(2))
    
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


def parse_k6_json(filepath: Path, test_type: str) -> Optional[K6Stats]:
    """
    Parse K6 JSON results to extract performance metrics.
    
    Args:
        filepath: Path to K6 JSON file
        test_type: "http" or "db"
    """
    if not filepath.exists():
        print(f"    Warning: K6 {test_type} results not found: {filepath}")
        return None
    
    try:
        with open(filepath) as f:
            data = json.load(f)
    except Exception as e:
        print(f"    Error reading {filepath}: {e}")
        return None
    
    metrics = data.get('metrics', {})
    root_group = data.get('root_group', {})
    checks = root_group.get('checks', {})
    
    stats = K6Stats(test_type=test_type)
    
    # Request counts and rate
    http_reqs = metrics.get('http_reqs', {})
    stats.total_requests = http_reqs.get('count', 0)
    stats.requests_per_sec = round(http_reqs.get('rate', 0), 2)
    
    # Virtual users
    vus = metrics.get('vus', {})
    stats.vus = vus.get('value', vus.get('max', 0))
    stats.vus_max = metrics.get('vus_max', {}).get('value', 0)
    
    # Latency metrics (http_req_duration is in milliseconds)
    duration = metrics.get('http_req_duration', {})
    stats.latency_avg_ms = round(duration.get('avg', 0), 3)
    stats.latency_med_ms = round(duration.get('med', 0), 3)
    stats.latency_p90_ms = round(duration.get('p(90)', 0), 3)
    stats.latency_p95_ms = round(duration.get('p(95)', 0), 3)
    stats.latency_max_ms = round(duration.get('max', 0), 3)
    
    # Check results
    status_check = checks.get('status is 200', {})
    stats.checks_passed = status_check.get('passes', 0)
    stats.checks_failed = status_check.get('fails', 0)
    
    # Error rate (http_req_failed.value is 0 when no failures)
    http_failed = metrics.get('http_req_failed', {})
    stats.error_rate = http_failed.get('value', 0)
    
    # Data transfer
    stats.data_received_bytes = metrics.get('data_received', {}).get('count', 0)
    stats.data_sent_bytes = metrics.get('data_sent', {}).get('count', 0)
    
    return stats


def parse_dut_monitor_log(filepath: Path) -> Optional[DutStats]:
    """
    Parse DUT monitor log to extract system and interface statistics.
    Handles multiple iterations and calculates averages/max/stdev.
    """
    if not filepath.exists():
        print(f"    Warning: DUT monitor log not found: {filepath}")
        return None
    
    try:
        content = filepath.read_text()
    except Exception as e:
        print(f"    Error reading {filepath}: {e}")
        return None
    
    # Split into iterations
    iterations = re.split(r'={80}\nIteration \d+/\d+', content)
    iterations = [it for it in iterations if it.strip() and 'show system load-stats' in it]
    
    if not iterations:
        print(f"    Warning: No valid iterations found in {filepath}")
        return None
    
    # Collect metrics across iterations
    cpu_loads = []
    mem_loads = []
    poller_cpus = []
    ctrl_cpus = []
    load_factors = []
    
    # Interface stats per iteration
    interface_samples: Dict[str, List[Dict]] = {}
    
    # Session stats
    session_actives = []
    session_tcp_counts = []
    session_udp_counts = []
    last_session_data = {}
    failed_sessions = 0
    
    for iteration in iterations:
        # Parse system load stats
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
        
        # Parse interface statistics
        if_block_match = re.search(
            r'NAME\s+INF\s+STATUS.*?(?=\[ok\]|\Z)',
            iteration,
            re.DOTALL
        )
        if if_block_match:
            if_block = if_block_match.group(0)
            # Parse interface lines - handle variable column widths
            if_pattern = re.compile(
                r'(vni-\d+/\d+)\s+\w+\s+(up|down)\s+'
                r'(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+'
                r'(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)',
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
            r'udp-session-count\s+(\d+)',
            iteration,
            re.DOTALL
        )
        if session_match:
            session_actives.append(int(session_match.group(1)))
            session_tcp_counts.append(int(session_match.group(5)))
            session_udp_counts.append(int(session_match.group(6)))
            last_session_data = {
                'created': int(session_match.group(2)),
                'closed': int(session_match.group(3)),
                'max_allowed': int(session_match.group(4)),
            }
        
        # Parse failed sessions
        failed_match = re.search(r'16\s+0\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)', iteration)
        if failed_match:
            failed_sessions = int(failed_match.group(1))
    
    # Build DUT stats with calculations
    dut_stats = DutStats(
        samples=len(iterations),
        cpu_load_avg=round(mean(cpu_loads), 1) if cpu_loads else 0,
        cpu_load_max=max(cpu_loads) if cpu_loads else 0,
        cpu_load_min=min(cpu_loads) if cpu_loads else 0,
        cpu_load_stdev=round(stdev(cpu_loads), 2) if len(cpu_loads) > 1 else 0,
        mem_load_avg=round(mean(mem_loads), 1) if mem_loads else 0,
        poller_cpu_avg=round(mean(poller_cpus), 1) if poller_cpus else 0,
        ctrl_cpu_avg=round(mean(ctrl_cpus), 1) if ctrl_cpus else 0,
        load_factor_avg=round(mean(load_factors), 1) if load_factors else 0,
    )
    
    # Session stats
    if session_actives:
        dut_stats.sessions = SessionStats(
            active_avg=round(mean(session_actives), 1),
            active_max=max(session_actives),
            created=last_session_data.get('created', 0),
            closed=last_session_data.get('closed', 0),
            failed=failed_sessions,
            max_allowed=last_session_data.get('max_allowed', 0),
            tcp_count_max=max(session_tcp_counts) if session_tcp_counts else 0,
            udp_count_max=max(session_udp_counts) if session_udp_counts else 0,
        )
    
    # Interface stats
    for iface_name, samples in interface_samples.items():
        if not samples or samples[0]['status'] == 'down':
            continue
        
        # Filter out zero-pps samples (idle periods)
        active_samples = [s for s in samples if s['rx_pps'] > 0 or s['tx_pps'] > 0]
        if not active_samples:
            active_samples = samples
        
        iface_stats = InterfaceStats(
            name=iface_name,
            rx_pps_avg=round(mean(s['rx_pps'] for s in active_samples), 1),
            tx_pps_avg=round(mean(s['tx_pps'] for s in active_samples), 1),
            rx_bps_avg=round(mean(s['rx_bps'] for s in active_samples), 1),
            tx_bps_avg=round(mean(s['tx_bps'] for s in active_samples), 1),
            rx_pps_max=max(s['rx_pps'] for s in samples),
            tx_pps_max=max(s['tx_pps'] for s in samples),
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
        for field_name in obj.__dataclass_fields__:
            value = getattr(obj, field_name)
            result[field_name] = dataclass_to_dict(value)
        return result
    return obj


# -----------------------------------------------------------------------------
# Path Count Processing
# -----------------------------------------------------------------------------

def process_path_count(results_dir: Path, path_count: int, 
                       loss_threshold: float = 0.5,
                       latency_threshold_ms: float = 200.0) -> Optional[dict]:
    """
    Process all logs for a single path count iteration.
    
    Args:
        results_dir: Directory containing log files
        path_count: Number of WAN paths (1, 2, 4, 8, 14)
        loss_threshold: Packet loss threshold for pass/fail
        latency_threshold_ms: P95 latency threshold for K6 tests
    """
    prefix = f"s3_scale_{path_count}path"
    json_path = results_dir / f"{prefix}_summary.json"
    
    if not json_path.exists():
        return None
    
    # Load existing JSON
    with open(json_path) as f:
        result = json.load(f)
    
    print(f"  Processing {path_count} path(s)...")
    
    # Parse T-Rex 70% load test
    trex_stats = parse_trex_load_log(
        results_dir / f"{prefix}_trex_70pct.log",
        expected_duration=result.get('test_duration_sec', 190)
    )
    
    # Parse K6 HTTP results
    k6_http = parse_k6_json(results_dir / f"{prefix}_k6_http.json", "http")
    
    # Parse K6 DB results
    k6_db = parse_k6_json(results_dir / f"{prefix}_k6_db.json", "db")
    
    # Parse DUT monitor log
    dut_stats = parse_dut_monitor_log(results_dir / f"{prefix}_dut_monitor.log")
    
    # Build enriched result
    enriched = {
        'scenario': result.get('scenario', '03_scaling_and_quality'),
        'test_mode': result.get('test_mode', 'unknown'),
        'path_count': path_count,
        'binary_search': {
            'max_rate_gbps': result.get('max_rate_gbps', 0),
            'background_load_gbps': result.get('background_load_gbps', 0),
            'load_factor': 0.7,
        },
        'trex_70pct': dataclass_to_dict(trex_stats) if trex_stats else None,
        'k6_http': dataclass_to_dict(k6_http) if k6_http else None,
        'k6_db': dataclass_to_dict(k6_db) if k6_db else None,
        'dut_stats': dataclass_to_dict(dut_stats) if dut_stats else None,
        'timestamp': result.get('timestamp'),
    }
    
    # Determine pass/fail
    pass_criteria = {
        'trex_loss': True,
        'k6_http_latency': True,
        'k6_db_latency': True,
        'k6_http_errors': True,
        'k6_db_errors': True,
    }
    
    if trex_stats:
        pass_criteria['trex_loss'] = trex_stats.packet_loss_pct <= loss_threshold
    
    if k6_http:
        pass_criteria['k6_http_latency'] = k6_http.latency_p95_ms <= latency_threshold_ms
        pass_criteria['k6_http_errors'] = k6_http.checks_failed == 0
    
    if k6_db:
        pass_criteria['k6_db_latency'] = k6_db.latency_p95_ms <= latency_threshold_ms
        pass_criteria['k6_db_errors'] = k6_db.checks_failed == 0
    
    enriched['pass_criteria'] = pass_criteria
    enriched['pass'] = all(pass_criteria.values())
    
    return enriched


# -----------------------------------------------------------------------------
# Main Processing
# -----------------------------------------------------------------------------

def process_scenario_03(results_dir: Path, 
                        loss_threshold: float = 0.5,
                        latency_threshold_ms: float = 200.0) -> dict:
    """
    Process all Scenario 03 results for all path counts.
    
    Args:
        results_dir: Directory containing all S03 log files
        loss_threshold: Packet loss threshold for pass/fail
        latency_threshold_ms: P95 latency threshold for K6 tests
    """
    results_dir = Path(results_dir)
    
    if not results_dir.exists():
        raise FileNotFoundError(f"Results directory not found: {results_dir}")
    
    print(f"Processing Scenario 03 results from: {results_dir}")
    
    # Standard path counts
    path_counts = [1, 2, 4, 8, 14]
    results = {}
    
    for pc in path_counts:
        enriched = process_path_count(results_dir, pc, loss_threshold, latency_threshold_ms)
        if enriched:
            results[pc] = enriched
    
    if not results:
        print("  Warning: No path count results found!")
        return {'error': 'No results found'}
    
    # Build scaling analysis
    scaling_analysis = []
    for pc in sorted(results.keys()):
        data = results[pc]
        entry = {
            'path_count': pc,
            'max_rate_gbps': data.get('binary_search', {}).get('max_rate_gbps', 0),
            'background_load_gbps': data.get('binary_search', {}).get('background_load_gbps', 0),
        }
        
        if data.get('trex_70pct'):
            entry['trex_loss_pct'] = data['trex_70pct'].get('packet_loss_pct', 0)
            entry['trex_tx_pps'] = data['trex_70pct'].get('tx_pps', 0)
        
        if data.get('k6_http'):
            entry['http_p95_ms'] = data['k6_http'].get('latency_p95_ms', 0)
            entry['http_rps'] = data['k6_http'].get('requests_per_sec', 0)
        
        if data.get('k6_db'):
            entry['db_p95_ms'] = data['k6_db'].get('latency_p95_ms', 0)
            entry['db_rps'] = data['k6_db'].get('requests_per_sec', 0)
        
        if data.get('dut_stats'):
            entry['cpu_avg'] = data['dut_stats'].get('cpu_load_avg', 0)
            entry['cpu_max'] = data['dut_stats'].get('cpu_load_max', 0)
        
        entry['pass'] = data.get('pass', False)
        scaling_analysis.append(entry)
    
    # Calculate scaling efficiency
    if len(scaling_analysis) >= 2:
        base_rate = scaling_analysis[0].get('max_rate_gbps', 0)
        for entry in scaling_analysis:
            if base_rate > 0:
                entry['scaling_factor'] = round(entry.get('max_rate_gbps', 0) / base_rate, 2)
    
    # Build summary
    summary = {
        'scenario': '03_scaling_and_quality',
        'results_dir': str(results_dir),
        'test_mode': results.get(list(results.keys())[0], {}).get('test_mode', 'unknown'),
        'thresholds': {
            'packet_loss_pct': loss_threshold,
            'latency_p95_ms': latency_threshold_ms,
        },
        'path_count_results': {str(k): v for k, v in results.items()},
        'scaling_analysis': scaling_analysis,
        'summary': {
            'path_counts_tested': len(results),
            'passed': sum(1 for r in results.values() if r.get('pass') is True),
            'failed': sum(1 for r in results.values() if r.get('pass') is False),
        }
    }
    
    return summary


def save_enriched_results(results_dir: Path, summary: dict):
    """Save enriched results back to files"""
    results_dir = Path(results_dir)
    
    # Save individual enriched JSON files per path count
    for pc_str, data in summary.get('path_count_results', {}).items():
        output_path = results_dir / f"s3_scale_{pc_str}path_enriched.json"
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"  Saved: {output_path}")
    
    # Save consolidated summary
    summary_path = results_dir / 's03_summary.json'
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"  Saved: {summary_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Parse Scenario 03 (Scaling and Quality) results and enrich JSON files'
    )
    parser.add_argument(
        'results_dir',
        type=Path,
        help='Directory containing S03 result files'
    )
    parser.add_argument(
        '--loss-threshold',
        type=float,
        default=0.5,
        help='Packet loss threshold for pass/fail (default: 0.5%%)'
    )
    parser.add_argument(
        '--latency-threshold',
        type=float,
        default=200.0,
        help='P95 latency threshold in ms for K6 tests (default: 200ms)'
    )
    parser.add_argument(
        '--no-save',
        action='store_true',
        help='Parse only, do not save enriched files'
    )
    
    args = parser.parse_args()
    
    try:
        summary = process_scenario_03(
            args.results_dir, 
            args.loss_threshold,
            args.latency_threshold
        )
        
        print("\n" + "=" * 80)
        print("SCENARIO 03 - SCALING AND QUALITY SUMMARY")
        print("=" * 80)
        print(f"Test Mode: {summary.get('test_mode', 'unknown')}")
        print(f"Path Counts Tested: {summary['summary']['path_counts_tested']}")
        print(f"Passed: {summary['summary']['passed']}, Failed: {summary['summary']['failed']}")
        
        print("\nScaling Analysis:")
        print("-" * 80)
        header = f"{'Paths':<6} {'MaxRate':<10} {'Load':<8} {'Loss%':<8} {'HTTP P95':<10} {'DB P95':<10} {'CPU%':<8} {'Pass':<6}"
        print(header)
        print("-" * 80)
        
        for entry in summary.get('scaling_analysis', []):
            paths = str(entry.get('path_count', 'N/A'))
            max_rate = f"{entry.get('max_rate_gbps', 0):.3f}"
            load = f"{entry.get('background_load_gbps', 0):.3f}"
            loss = f"{entry.get('trex_loss_pct', 0):.2f}"
            http_p95 = f"{entry.get('http_p95_ms', 0):.1f}ms"
            db_p95 = f"{entry.get('db_p95_ms', 0):.1f}ms"
            cpu = f"{entry.get('cpu_avg', 0):.1f}"
            pass_str = "PASS" if entry.get('pass') else "FAIL"
            print(f"{paths:<6} {max_rate:<10} {load:<8} {loss:<8} {http_p95:<10} {db_p95:<10} {cpu:<8} {pass_str:<6}")
        
        print("-" * 80)
        
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
