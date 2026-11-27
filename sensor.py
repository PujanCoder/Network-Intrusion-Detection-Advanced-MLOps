import httpx
from netflower import capture_live

API = "http://127.0.0.1:8000/api/v1/ingest/cic"

def on_flow(flow: dict):
    # flow is a dict with 82 CIC-compatible keys
    httpx.post(API, json=flow, timeout=5.0)

handle = capture_live(
    "eth0",
    on_flow=on_flow,
    idle_timeout=15.0,   # UDP / long-lived TCP emit after 15s silence
    flow_timeout=120.0,  # absolute cap
)
handle.start()
input("Press Enter to stop...\n")
handle.stop()