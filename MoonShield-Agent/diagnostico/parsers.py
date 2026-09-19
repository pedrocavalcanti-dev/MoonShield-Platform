import re
import json
from typing import Any

def parse_ping_output(stdout: str) -> dict[str, Any]:
    """Parse ping output robustly tolerating some locale differences."""
    result = {
        "sent": 0,
        "received": 0,
        "loss_percent": 0.0,
        "min_ms": None,
        "avg_ms": None,
        "max_ms": None,
        "mdev_ms": None,
    }

    # 4 packets transmitted, 4 received, 0% packet loss, time 3004ms
    # 4 packets transmitted, 0 received, 100% packet loss, time 3065ms
    # 4 packets transmitted, 4 received, +1 duplicates, 0% packet loss, time 3003ms
    loss_match = re.search(r"(\d+)\s+packets?\s+transmitted,\s+(\d+)\s+received.*?(?:([0-9.]+)\s*%?\s*packet\s*loss)", stdout, re.IGNORECASE)
    if loss_match:
        result["sent"] = int(loss_match.group(1))
        result["received"] = int(loss_match.group(2))
        try:
            result["loss_percent"] = float(loss_match.group(3))
        except ValueError:
            pass

    # rtt min/avg/max/mdev = 0.536/0.596/0.631/0.038 ms
    # round-trip min/avg/max/stddev = 0.536/0.596/0.631/0.038 ms
    rtt_match = re.search(r"(?:rtt|round-trip).*?=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)\s*ms", stdout, re.IGNORECASE)
    if rtt_match:
        try:
            result["min_ms"] = float(rtt_match.group(1))
            result["avg_ms"] = float(rtt_match.group(2))
            result["max_ms"] = float(rtt_match.group(3))
            result["mdev_ms"] = float(rtt_match.group(4))
        except ValueError:
            pass

    return result

def parse_mtr_json(stdout: str) -> dict[str, Any]:
    """Parse MTR --json output."""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return {}

    report = data.get("report", {})
    hubs = report.get("hubs", [])

    parsed_hops = []
    for hub in hubs:
        parsed_hops.append({
            "hop": hub.get("count"),
            "host": hub.get("host"),
            "ip": hub.get("ip") or hub.get("host"),
            "loss_percent": hub.get("Loss%"),
            "sent": hub.get("Snt"),
            "last_ms": hub.get("Last"),
            "avg_ms": hub.get("Avg"),
            "best_ms": hub.get("Best"),
            "worst_ms": hub.get("Wrst"),
            "stdev_ms": hub.get("StDev"),
        })

    return {"hops": parsed_hops}

def parse_ip_j(stdout: str) -> Any:
    """Parse JSON output from ip -j ..."""
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return []
