#!/usr/bin/env python3
"""
Parser for Scenario 01B - Noise Baseline Characterization (v3.0)

Implements "Strict Search / Lenient Validation" logic:
  1. Binary Search Threshold: Fixed near 0.1% to find the true hardware knee.
  2. Validation Threshold: Calculated based on measured Noise + Observer Effect + Variance.
  3. Safe Load Factor: Calculated based on stress stability.

Usage:
    python parse_s01b_results.py /path/to/noise_baseline_directory
    python parse_s01b_results.py /path/to/noise_baseline_directory --update-config
    python parse_s01b_results.py /path/to/noise_baseline_directory --json
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any

def parse_noise_baseline(results_dir: Path) -> Optional[dict]:
    json_file = results_dir / 's1b_noise_baseline.json'
    if not json_file.exists():
        print(f"Error: Noise baseline file not found: {json_file}")
        return None
    try:
        with open(json_file) as f:
            return json.load(f)
    except Exception as e:
        print(f"Error parsing JSON: {e}")
        return None

def get_stats(data: dict, phase_key: str) -> Dict[str, float]:
    """Generic stats extractor"""
    phase_data = data.get(phase_key, {})
    # Handle direct dict or nested 'statistics' dict
    stats = phase_data.get('statistics', phase_data)
    
    # Fallback for Observer Phase which is flat
    if 'monitor_overhead_pct' in phase_data: 
        return {'overhead': phase_data.get('monitoring_overhead_pct', 0.0)}
        
    return {
        'avg': stats.get('avg_loss_pct', 0.0),
        'max': stats.get('max_loss_pct', 0.0),
        'stddev': stats.get('stddev', 0.0)
    }

def calculate_recommendations(data: dict) -> Dict[str, Any]:
    """
    Core Logic for Threshold Calculation
    """
    p1 = get_stats(data, 'phase1_low_load')
    p3 = get_stats(data, 'phase3_stress_calibration')
    p4 = data.get('phase4_observer_isolation', {})
    
    # --- 1. Binary Search Threshold (Strict) ---
    # We use the ITU-T Y.1564 baseline (0.1%).
    # We do NOT add the noise floor here. If noise is 0.27%, we WANT the search
    # to fail at that rate and back off until it finds a clean(er) rate.
    # We add a tiny epsilon (0.01%) for rounding safety.
    rec_binary_search = 0.11

    # --- 2. Validation Threshold (Lenient / Calculated) ---
    # This must account for the reality of the environment so valid runs don't fail.
    # Formula: Noise Floor + Observer Overhead + Variance Padding + ITU Base
    
    noise_floor = p1['avg']  # Wire/Virtio noise found in Phase 1
    
    # Observer Overhead (Cost of monitoring)
    observer_overhead = p4.get('monitoring_overhead_pct', 0.0) if p4.get('enabled') else 0.0
    
    # Variance Padding (Stability)
    # If P3 (Stress) had high variance, we need more room.
    # We take 2 standard deviations from the stress test.
    variance_padding = 2 * p3['stddev']
    
    # Safety Margin (Fixed)
    safety_buffer = 0.1
    
    rec_validation = noise_floor + observer_overhead + variance_padding + safety_buffer
    
    # Ensure it never goes below 0.3% (practical floor for virtualized SD-WAN)
    rec_validation = max(rec_validation, 0.3)

    # --- 3. Safe Load Factor (Capacity De-rating) ---
    # Start at 90% (aggressive but safe)
    base_factor = 0.90
    
    # Penalize for high variance in Phase 3
    # If stddev is high (e.g. > 0.05%), reduce capacity
    variance_penalty = max(0.0, (p3['stddev'] - 0.02) * 2) 
    
    # Penalize for high monitoring overhead
    observer_penalty = max(0.0, observer_overhead)
    
    rec_safe_factor = base_factor - variance_penalty - observer_penalty
    
    # Clamp between 0.70 and 0.95
    rec_safe_factor = max(0.70, min(0.95, rec_safe_factor))

    return {
        'binary_search_loss_pct': round(rec_binary_search, 5),
        'validation_loss_pct': round(rec_validation, 3),
        'safe_validation_factor': round(rec_safe_factor, 2),
        'debug': {
            'noise_floor': noise_floor,
            'observer_overhead': observer_overhead,
            'variance_padding': variance_padding
        }
    }

def display_results(data: dict) -> None:
    rec = calculate_recommendations(data)
    d = rec['debug']
    
    print("\n" + "="*80)
    print(f"  NOISE BASELINE ANALYSIS (v{data.get('version', '2.0')})")
    print("="*80)
    print(f"  Timestamp: {data.get('timestamp')}")
    print("\n  MEASUREMENTS:")
    print(f"    1. Noise Floor (Phase 1):      {d['noise_floor']:.4f}%")
    print(f"    2. Observer Cost (Phase 4):    {d['observer_overhead']:.4f}%")
    print(f"    3. Stress Variance (Phase 3):  {d['variance_padding']/2:.4f}% (StdDev)")
    print("-" * 80)
    print("  RECOMMENDATIONS:")
    print("-" * 80)
    
    print(f"  1. Binary Search Threshold: {rec['binary_search_loss_pct']:.4f}%  (STRICT)")
    print(f"     -> Forces T-Rex to find the true stable knee-of-curve.")
    
    print(f"  2. Validation Threshold:    {rec['validation_loss_pct']:.3f}%   (CALCULATED)")
    print(f"     -> {d['noise_floor']:.3f}% (Noise) + {d['observer_overhead']:.3f}% (Obs) + {d['variance_padding']:.3f}% (Var) + 0.1% (Safe)")
    
    print(f"  3. Safe Validation Factor:  {rec['safe_validation_factor']}")
    print(f"     -> Multiplier to apply to Ceiling Rate for validation.")
    print("="*80 + "\n")

def generate_config_snippet(data: dict) -> str:
    rec = calculate_recommendations(data)
    return f"""
# =============================================================================
# Recommended Thresholds (Auto-Calculated from S01b)
# =============================================================================
# host_vars/dut.yml

# 1. Search Strictness: Keep low (0.1%) to find true hardware limits
binary_search_loss_pct: {rec['binary_search_loss_pct']}

# 2. Validation Gate: Calculated from measured environment noise
validation_loss_pct: {rec['validation_loss_pct']}

# 3. Capacity De-rating: Based on stability variance
safe_validation_factor: {rec['safe_validation_factor']}
"""

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('results_dir', type=Path)
    parser.add_argument('--update-config', action='store_true')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    
    data = parse_noise_baseline(args.results_dir)
    if not data: return 1
    
    if args.json:
        rec = calculate_recommendations(data)
        print(json.dumps(rec, indent=2))
    elif args.update_config:
        print(generate_config_snippet(data))
    else:
        display_results(data)
    return 0

if __name__ == '__main__':
    sys.exit(main())
