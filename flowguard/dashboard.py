"""
Minimal console dashboard. Prints each alert as a formatted row
(timestamp, flow ID, threat class, confidence, evidence) matching the
"Alert Format" slide, plus a summary table by threat class at the end.
This is the text-mode stand-in for the visual dashboard; export_json /
export_csv in alert_engine.py can feed a real web/GUI dashboard.
"""

from __future__ import annotations

from collections import Counter
from typing import List

from .alert_engine import Alert

SEVERITY_COLOR = {
    "critical": "\033[91m",  # red
    "high": "\033[93m",      # yellow
    "medium": "\033[94m",    # blue
    "info": "\033[90m",      # grey
}
RESET = "\033[0m"


def print_alert(alert: Alert) -> None:
    color = SEVERITY_COLOR.get(alert.severity, "")
    print(
        f"{color}[{alert.severity.upper():8}] {alert.timestamp}  "
        f"{alert.flow_id:12}  {alert.src_ip:>15} -> {alert.dst_ip:<15}  "
        f"class={alert.threat_class:<20} conf={alert.confidence:.2f}  "
        f"evidence=({'; '.join(alert.evidence)}){RESET}"
    )


def print_summary(alerts: List[Alert], flows_processed: int, throughput_fps: float) -> None:
    counts = Counter(a.threat_class for a in alerts)
    print("\n" + "=" * 70)
    print("FlowGuard AI — Detection Summary")
    print("=" * 70)
    print(f"Flows processed : {flows_processed}")
    print(f"Alerts raised   : {len(alerts)}")
    print(f"Throughput      : {throughput_fps:,.0f} flows/sec")
    print("-" * 70)
    for cls, n in counts.most_common():
        print(f"  {cls:<22} {n}")
    print("=" * 70)
