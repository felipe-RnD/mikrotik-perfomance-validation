#!/usr/bin/env python3
"""
Scenario 04 (Session Scalability) Results Parser

Parses T-Rex ASTF session ramp logs and DUT monitor logs to create
enriched JSON results with session establishment metrics.

Usage:
    python parse_s04_results.py <results_directory>

Example:
    python parse_s04_results.py /opt/versa-sdwan-performance-test/results/session_sdwan_20251126

The script will:
1. Find s4_session_summary.json
2. Parse T-Rex ASTF session ramp log for TCP connection stats
3. Parse DUT monitor log for session ramp progression
4. Generate enriched s4_session_enriched.json and s04_summary.json
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
class AstfSessionStats:
    """Metrics extracted from T-Rex ASTF session ramp log"""
    # Connection metrics
    conn_attempted: int = 0
    conn_established: int = 0
    conn_closed: int = 0
    conn_drops: int = 0
    conn_embryonic_drops: int = 0
    conn_timeout_drops: int = 0
    # Success rates
    conn_success_rate: float = 0.0
    conn_drop_rate: float = 0.0
    # Retransmits
    rexmit_timeouts: int = 0
    rexmit_syn_timeouts: int = 0
    rexmit_packets: int = 0
    rexmit_bytes: int = 0
    # Traffic stats
    tx_packets: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    rx_bytes: int = 0
    # Errors
    dup_packets: int = 0
    ooo_packets: int = 0
    bad_syn: int = 0
    paws_drops: int = 0
    client_pkt_without_flow: int = 0


@dataclass
class SessionRampPoint:
    """Single point in the session ramp timeline"""
    iteration: int
    timestamp: str
    session_count: int
    tcp_sessions: int
    udp_sessions: int
    active_sessions: int
    cpu_load: int
    mem_load: int
    failed_sessions: int


@dataclass
class DutSessionStats:
    """Aggregated DUT statistics during session ramp"""
    samples: int = 0
    # Session metrics
    peak_session_count: int = 0
    peak_tcp_sessions: int = 0
    peak_active_sessions: int = 0
    final_session_count: int = 0
    sessions_created_total: int = 0
    sessions_closed_total: int = 0
    sessions_failed_total: int = 0
    # CPU/Memory at peak
    cpu_at_peak: int = 0
    mem_at_peak: int = 0
    # Averages during test
    cpu_load_avg: float = 0.0
    cpu_load_max: int = 0
    mem_load_avg: float = 0.0
    mem_load_max: int = 0
    # Session ramp timeline
    ramp_timeline: List[Dict] = field(default_factory=list)


# -----------------------------------------------------------------------------
# Parsing Functions
# -----------------------------------------------------------------------------

def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text"""
    ansi_pattern = re.compile(r'\x1b\[[0-9;]*[mK]|\[\d+m|\[0m|\[1m|\[22m|\[32m|\[39m|\[31m|\[36m|\[4m|\[24m')
    return ansi_pattern.sub('', text)


def parse_astf_session_log(filepath: Path) -> Optional[AstfSessionStats]:
    """
    Parse T-Rex ASTF session ramp log to extract TCP connection statistics.
    """
    if not filepath.exists():
        print(f"  Warning: ASTF session log not found: {filepath}")
        return None
    
    try:
        content = strip_ansi(filepath.read_text())
    except Exception as e:
        print(f"  Error reading {filepath}: {e}")
        return None
    
    stats = AstfSessionStats()
    
    # Connection metrics
    match = re.search(r'tcps_connattempt\s+\|\s+(\d+)', content)
    if match:
        stats.conn_attempted = int(match.group(1))
    
    match = re.search(r'tcps_connects\s+\|\s+(\d+)', content)
    if match:
        stats.conn_established = int(match.group(1))
    
    match = re.search(r'tcps_closed\s+\|\s+(\d+)', content)
    if match:
        stats.conn_closed = int(match.group(1))
    
    match = re.search(r'tcps_drops\s+\|\s+(\d+)', content)
    if match:
        stats.conn_drops = int(match.group(1))
    
    match = re.search(r'tcps_conndrops\s+\|\s+(\d+)', content)
    if match:
        stats.conn_embryonic_drops = int(match.group(1))
    
    match = re.search(r'tcps_timeoutdrop\s+\|\s+(\d+)', content)
    if match:
        stats.conn_timeout_drops = int(match.group(1))
    
    # Calculate success/drop rates
    if stats.conn_attempted > 0:
        stats.conn_success_rate = round(
            (stats.conn_established / stats.conn_attempted) * 100, 2
        )
        stats.conn_drop_rate = round(
            (stats.conn_drops / stats.conn_attempted) * 100, 2
        )
    
    # Retransmit stats
    match = re.search(r'tcps_rexmttimeo\s+\|\s+(\d+)', content)
    if match:
        stats.rexmit_timeouts = int(match.group(1))
    
    match = re.search(r'tcps_rexmttimeo_syn\s+\|\s+(\d+)', content)
    if match:
        stats.rexmit_syn_timeouts = int(match.group(1))
    
    match = re.search(r'tcps_sndrexmitpack\s+\|\s+(\d+)', content)
    if match:
        stats.rexmit_packets = int(match.group(1))
    
    match = re.search(r'tcps_sndrexmitbyte\s+\|\s+(\d+)', content)
    if match:
        stats.rexmit_bytes = int(match.group(1))
    
    # Traffic stats
    match = re.search(r'tcps_sndtotal\s+\|\s+(\d+)', content)
    if match:
        stats.tx_packets = int(match.group(1))
    
    match = re.search(r'tcps_sndbyte\s+\|\s+(\d+)', content)
    if match:
        stats.tx_bytes = int(match.group(1))
    
    match = re.search(r'tcps_rcvtotal\s+\|\s+(\d+)', content)
    if match:
        stats.rx_packets = int(match.group(1))
    
    match = re.search(r'tcps_rcvbyte\s+\|\s+(\d+)', content)
    if match:
        stats.rx_bytes = int(match.group(1))
    
    # Error stats
    match = re.search(r'tcps_rcvduppack\s+\|\s+(\d+)', content)
    if match:
        stats.dup_packets = int(match.group(1))
    
    match = re.search(r'tcps_rcvoopack\s+\|\s+(\d+)', content)
    if match:
        stats.ooo_packets = int(match.group(1))
    
    match = re.search(r'tcps_badsyn\s+\|\s+(\d+)', content)
    if match:
        stats.bad_syn = int(match.group(1))
    
    match = re.search(r'tcps_pawsdrop\s+\|\s+(\d+)', content)
    if match:
        stats.paws_drops = int(match.group(1))
    
    match = re.search(r'err_cwf\s+\|\s+(\d+)', content)
    if match:
        stats.client_pkt_without_flow = int(match.group(1))
    
    return stats


def parse_session_dut_monitor(filepath: Path) -> Optional[DutSessionStats]:
    """
    Parse DUT monitor log during session ramp test.
    Tracks session count progression over time.
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
    ramp_points = []
    cpu_loads = []
    mem_loads = []
    
    i = 1  # Skip first split element (before first iteration)
    while i < len(iterations) - 1:
        iter_num = int(iterations[i])
        total_iters = int(iterations[i + 1])
        timestamp = iterations[i + 2]
        iter_content = iterations[i + 3] if i + 3 < len(iterations) else ""
        
        point = SessionRampPoint(
            iteration=iter_num,
            timestamp=timestamp,
            session_count=0,
            tcp_sessions=0,
            udp_sessions=0,
            active_sessions=0,
            cpu_load=0,
            mem_load=0,
            failed_sessions=0,
        )
        
        # Parse CPU/memory from system load stats
        # Format: VSN_ID CPU_LOAD POLLER_CPU CTRL_CPU MEM_LOAD LOAD_FACTOR
        load_match = re.search(r'0\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)', iter_content)
        system_cpu = 0
        system_mem = 0
        if load_match:
            system_cpu = int(load_match.group(1))
            system_mem = int(load_match.group(4))
        
        # Parse session summary
        session_match = re.search(
            r'session-count\s+(\d+).*?'
            r'tcp-session-count\s+(\d+).*?'
            r'udp-session-count\s+(\d+)',
            iter_content,
            re.DOTALL
        )
        if session_match:
            point.session_count = int(session_match.group(1))
            point.tcp_sessions = int(session_match.group(2))
            point.udp_sessions = int(session_match.group(3))
        
        # Parse device clients for CPU, MEM, active sessions, and failed sessions
        # Format: CLIENT_ID VSN_ID CPU_LOAD MEM_LOAD MAX_SESSIONS ACTIVE_SESSIONS FAILED_SESSIONS
        # Example: 16      0    65    53    500000    194133    993609
        client_match = re.search(
            r'(?:^|\n)\s*16\s+0\s+(\d{1,3})\s+(\d{1,3})\s+\d+\s+(\d+)\s+(\d+)',
            iter_content
        )
        client_cpu = 0
        client_mem = 0
        if client_match:
            client_cpu = int(client_match.group(1))
            client_mem = int(client_match.group(2))
            point.active_sessions = int(client_match.group(3))
            point.failed_sessions = int(client_match.group(4))
        
        # Use max of system load-stats and device clients for CPU/MEM
        # Device clients often shows higher (more accurate) per-client load
        point.cpu_load = max(system_cpu, client_cpu)
        point.mem_load = max(system_mem, client_mem)
        
        if point.cpu_load > 0:
            cpu_loads.append(point.cpu_load)
        if point.mem_load > 0:
            mem_loads.append(point.mem_load)
        
        ramp_points.append(point)
        i += 4
    
    if not ramp_points:
        print(f"  Warning: No valid iterations found in {filepath}")
        return None
    
    # Find peak session point
    peak_point = max(ramp_points, key=lambda p: p.session_count)
    final_point = ramp_points[-1]
    
    # Parse session created/closed from last iteration
    last_iter_content = iterations[-1] if iterations else ""
    created_match = re.search(r'session-created\s+(\d+)', last_iter_content)
    closed_match = re.search(r'session-closed\s+(\d+)', last_iter_content)
    
    # Build stats
    stats = DutSessionStats(
        samples=len(ramp_points),
        peak_session_count=peak_point.session_count,
        peak_tcp_sessions=peak_point.tcp_sessions,
        peak_active_sessions=max(p.active_sessions for p in ramp_points),
        final_session_count=final_point.session_count,
        sessions_created_total=int(created_match.group(1)) if created_match else 0,
        sessions_closed_total=int(closed_match.group(1)) if closed_match else 0,
        sessions_failed_total=final_point.failed_sessions,
        cpu_at_peak=peak_point.cpu_load,
        mem_at_peak=peak_point.mem_load,
        cpu_load_avg=round(mean(cpu_loads), 1) if cpu_loads else 0,
        cpu_load_max=max(cpu_loads) if cpu_loads else 0,
        mem_load_avg=round(mean(mem_loads), 1) if mem_loads else 0,
        mem_load_max=max(mem_loads) if mem_loads else 0,
        ramp_timeline=[{
            'iteration': p.iteration,
            'timestamp': p.timestamp,
            'session_count': p.session_count,
            'tcp_sessions': p.tcp_sessions,
            'active_sessions': p.active_sessions,
            'cpu_load': p.cpu_load,
            'mem_load': p.mem_load,
        } for p in ramp_points],
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

def process_scenario_04(results_dir: Path,
                        min_success_rate: float = 95.0) -> dict:
    """
    Process Scenario 04 (Session Scalability) results.
    
    Args:
        results_dir: Directory containing S04 result files
        min_success_rate: Minimum connection success rate for pass (default: 95%)
    """
    results_dir = Path(results_dir)
    
    if not results_dir.exists():
        raise FileNotFoundError(f"Results directory not found: {results_dir}")
    
    print(f"Processing Scenario 04 results from: {results_dir}")
    
    # Load base JSON
    json_path = results_dir / "s4_session_summary.json"
    if not json_path.exists():
        raise FileNotFoundError(f"Summary JSON not found: {json_path}")
    
    with open(json_path) as f:
        base_result = json.load(f)
    
    # Parse ASTF session log
    astf_stats = parse_astf_session_log(results_dir / "s4_session_ramp_trex.log")
    
    # Parse DUT monitor log
    dut_stats = parse_session_dut_monitor(results_dir / "s4_session_dut_monitor.log")
    
    # Build enriched result
    enriched = {
        'scenario': base_result.get('scenario', '04_session_scalability'),
        'test_mode': base_result.get('test_mode', 'unknown'),
        'config': {
            'wan_paths_enabled': base_result.get('wan_paths_enabled', 0),
            'test_duration_sec': base_result.get('test_duration_sec', 0),
            'multiplier': base_result.get('multiplier', 0),
            'target_cps': base_result.get('target_cps', 0),
            'trex_profile': base_result.get('trex_profile', ''),
        },
        'astf_stats': dataclass_to_dict(astf_stats) if astf_stats else None,
        'dut_stats': dataclass_to_dict(dut_stats) if dut_stats else None,
        'timestamp': base_result.get('timestamp'),
    }
    
    # Determine pass/fail
    pass_criteria = {
        'conn_success_rate': True,
        'no_timeout_drops': True,
    }
    
    if astf_stats:
        pass_criteria['conn_success_rate'] = astf_stats.conn_success_rate >= min_success_rate
        pass_criteria['no_timeout_drops'] = astf_stats.conn_timeout_drops < 100  # Allow some
    
    enriched['pass_criteria'] = pass_criteria
    enriched['pass'] = all(pass_criteria.values())
    
    # Build summary
    summary = {
        'scenario': '04_session_scalability',
        'results_dir': str(results_dir),
        'test_mode': enriched.get('test_mode', 'unknown'),
        'thresholds': {
            'min_conn_success_rate': min_success_rate,
        },
        'enriched_result': enriched,
        'summary': {
            'conn_attempted': astf_stats.conn_attempted if astf_stats else 0,
            'conn_established': astf_stats.conn_established if astf_stats else 0,
            'conn_success_rate': astf_stats.conn_success_rate if astf_stats else 0,
            'conn_drops': astf_stats.conn_drops if astf_stats else 0,
            'peak_sessions': dut_stats.peak_session_count if dut_stats else 0,
            'peak_tcp_sessions': dut_stats.peak_tcp_sessions if dut_stats else 0,
            'cpu_at_peak': dut_stats.cpu_at_peak if dut_stats else 0,
            'cpu_max': dut_stats.cpu_load_max if dut_stats else 0,
            'mem_at_peak': dut_stats.mem_at_peak if dut_stats else 0,
            'mem_max': dut_stats.mem_load_max if dut_stats else 0,
            'pass': enriched.get('pass', False),
        },
    }
    
    return summary


def save_enriched_results(results_dir: Path, summary: dict):
    """Save enriched results back to files"""
    results_dir = Path(results_dir)
    
    # Save enriched result
    enriched_path = results_dir / 's4_session_enriched.json'
    with open(enriched_path, 'w') as f:
        json.dump(summary.get('enriched_result', {}), f, indent=2)
    print(f"  Saved: {enriched_path}")
    
    # Save summary
    summary_path = results_dir / 's04_summary.json'
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"  Saved: {summary_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Parse Scenario 04 (Session Scalability) results and enrich JSON files'
    )
    parser.add_argument(
        'results_dir',
        type=Path,
        help='Directory containing S04 result files'
    )
    parser.add_argument(
        '--min-success-rate',
        type=float,
        default=95.0,
        help='Minimum connection success rate for pass (default: 95%%)'
    )
    parser.add_argument(
        '--no-save',
        action='store_true',
        help='Parse only, do not save enriched files'
    )
    
    args = parser.parse_args()
    
    try:
        summary = process_scenario_04(args.results_dir, args.min_success_rate)
        
        print("\n" + "=" * 70)
        print("SCENARIO 04 - SESSION SCALABILITY SUMMARY")
        print("=" * 70)
        print(f"Test Mode: {summary.get('test_mode', 'unknown')}")
        
        s = summary.get('summary', {})
        print(f"\nConnection Statistics:")
        print(f"  Attempted:    {s.get('conn_attempted', 0):,}")
        print(f"  Established:  {s.get('conn_established', 0):,}")
        print(f"  Success Rate: {s.get('conn_success_rate', 0):.2f}%")
        print(f"  Drops:        {s.get('conn_drops', 0):,}")
        
        print(f"\nDUT Session Metrics:")
        print(f"  Peak Sessions:     {s.get('peak_sessions', 0):,}")
        print(f"  Peak TCP Sessions: {s.get('peak_tcp_sessions', 0):,}")
        print(f"  CPU at Peak:       {s.get('cpu_at_peak', 0)}%")
        print(f"  CPU Max:           {s.get('cpu_max', 0)}%")
        print(f"  Memory at Peak:    {s.get('mem_at_peak', 0)}%")
        print(f"  Memory Max:        {s.get('mem_max', 0)}%")
        
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
