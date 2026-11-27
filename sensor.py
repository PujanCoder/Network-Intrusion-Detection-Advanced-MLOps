"""Optional live-capture sensor for the legacy CIC-flow API.

Requires the third-party ``netflower`` package (not a dependency of this
repository) and the legacy serving app on port 8000. The real-time NDR
platform uses Zeek instead - see ``scripts/zeek_live.sh``.
"""

import sys

import httpx

try:
    from netflower import capture_live
except ImportError:  # optional dependency, only needed for this legacy path
    capture_live = None

API = "http://127.0.0.1:8000/api/v1/ingest/cic"

def on_flow(flow: dict):
    # flow is a dict with 82 CIC-compatible keys
    httpx.post(API, json=flow, timeout=5.0)

if capture_live is None:
    print(
        "netflower is not installed; this legacy sensor is optional.\n"
        "Use Zeek for the real-time platform: ./scripts/zeek_live.sh -i eth0",
        file=sys.stderr,
    )
    raise SystemExit(1)

handle = capture_live(
    "eth0",
    on_flow=on_flow,
    idle_timeout=15.0,   # UDP / long-lived TCP emit after 15s silence
    flow_timeout=120.0,  # absolute cap
)
handle.start()
input("Press Enter to stop...\n")
handle.stop()