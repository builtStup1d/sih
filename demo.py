#!/usr/bin/env python3
"""
FlowGuard AI — end-to-end demo.

Mirrors the "Demo Plan and Impact" slide:
  1. Train the hybrid model on labeled synthetic traffic.
  2. Replay a synthetic traffic stream through the live pipeline.
  3. Show detections (alerts) appearing as flows are processed.
  4. Filter alerts by threat class.
  5. Report throughput achieved.

Run:
    python demo.py                 # fast replay, prints throughput
    python demo.py --realtime      # paced replay, mimics live timing
"""

from __future__ import annotations

import argparse
import time

from flowguard.dashboard import print_alert, print_summary
from flowguard.pipeline import FlowGuardPipeline
from flowguard.traffic_simulator import build_demo_stream, build_training_set


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the FlowGuard AI demo.")
    parser.add_argument(
        "--realtime", action="store_true",
        help="Pace the replay to mimic live traffic timing (slower, for a live demo).",
    )
    parser.add_argument(
        "--filter", type=str, default=None,
        help="After the run, show only alerts of this threat class "
             "(e.g. port_scan, botnet_beaconing, exfiltration).",
    )
    parser.add_argument(
        "--export-json", type=str, default=None, help="Path to write alerts as JSON.",
    )
    parser.add_argument(
        "--export-csv", type=str, default=None, help="Path to write alerts as CSV.",
    )
    args = parser.parse_args()

    print("FlowGuard AI — passive threat detection for unidirectional IP traffic")
    print("No probes are sent. No traffic goes back to the source network.\n")

    print("[1/4] Training hybrid model on labeled synthetic traffic...")
    pipeline = FlowGuardPipeline()
    training_data = build_training_set()
    t0 = time.perf_counter()
    pipeline.train(training_data)
    print(f"      trained on {len(training_data)} labeled flows "
          f"in {time.perf_counter() - t0:.2f}s\n")

    print("[2/4] Replaying demo traffic stream (benign + scan + beacon + "
          "exfil + DGA)...\n")
    demo_flows = [f for f, _label in build_demo_stream()]

    def on_alert(alert):
        print_alert(alert)

    alerts = pipeline.run_stream(demo_flows, on_alert=on_alert, realtime_replay=args.realtime)

    print("\n[3/4] Detection complete.")
    print_summary(alerts, pipeline.flows_processed, pipeline.last_run_throughput_fps)

    if args.filter:
        filtered = pipeline.alert_engine.by_class(args.filter)
        print(f"\n[4/4] Filtered view — threat_class == '{args.filter}' "
              f"({len(filtered)} alerts):")
        for a in filtered:
            print_alert(a)
    else:
        print("\n[4/4] Tip: rerun with --filter port_scan (or botnet_beaconing, "
              "exfiltration, dga_dns_tunneling, ddos, encrypted_malware) "
              "to see the dashboard's filter view.")

    if args.export_json:
        pipeline.alert_engine.export_json(args.export_json)
        print(f"\nAlerts exported to {args.export_json}")
    if args.export_csv:
        pipeline.alert_engine.export_csv(args.export_csv)
        print(f"Alerts exported to {args.export_csv}")


if __name__ == "__main__":
    main()
