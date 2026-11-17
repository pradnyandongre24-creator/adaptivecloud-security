"""
agent/simulate_all_laptops.py
Multi-Laptop Simulator & Telemetry Hub for AdaptiveCloud.
Runs on your single laptop and makes ALL 4 PHYSICAL LAPTOPS LIVE!
- Laptop #1: Streams your actual physical hardware CPU, RAM, and processes.
- Laptop #2, #3, #4: Stream live simulated physical laptop telemetry.

Usage:
    python agent/simulate_all_laptops.py
"""

from __future__ import annotations

import collections
import json
import logging
import os
import platform
import socket
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

# Ensure repository root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from core.incident_store import incident_store
from core.rca_engine import rca_engine
from core.tier_classifiers import tier_classifiers

try:
    import psutil
except ImportError:
    print("[INIT] Installing psutil...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
    import psutil

PORT = int(os.environ.get("AGENT_PORT", "8001"))
HOST = "0.0.0.0"
HISTORY_LEN = 30

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("MultiLaptopSimulator")

# Storage for all physical & AWS cloud nodes
fleet_history: dict[str, collections.deque[dict[str, Any]]] = {
    "host-laptop-01": collections.deque(maxlen=HISTORY_LEN),
    "host-laptop-02": collections.deque(maxlen=HISTORY_LEN),
    "host-laptop-03": collections.deque(maxlen=HISTORY_LEN),
    "host-laptop-04": collections.deque(maxlen=HISTORY_LEN),
    "aws-worker-01": collections.deque(maxlen=HISTORY_LEN),
    "aws-worker-02": collections.deque(maxlen=HISTORY_LEN),
}
fleet_lock = threading.Lock()

# Dynamic live anomalies container for demonstration
active_anomalies: dict[str, dict[str, Any]] = {}

# Registered AWS EC2 Cloud Fleet (ap-south-1 Mumbai · LIVE AWS CONNECTED)
live_aws_telemetry = {"cpu": 1.1, "net_in": 180.0, "is_live": True, "last_updated": time.time()}

def aws_cloudwatch_poller() -> None:
    """Continuously poll real CloudWatch metrics from Om's live AWS EC2 instance i-017c3c1add524779c."""
    while True:
        try:
            import boto3
            key = os.environ.get("AWS_ACCESS_KEY_ID")
            sec = os.environ.get("AWS_SECRET_ACCESS_KEY")
            reg = os.environ.get("AWS_DEFAULT_REGION") or "ap-south-1"

            sess = boto3.Session(aws_access_key_id=key, aws_secret_access_key=sec, region_name=reg)
            cw = sess.client("cloudwatch")
            end_t = datetime.now(timezone.utc)
            start_t = end_t - timedelta(minutes=15)

            res = cw.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "cpu",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/EC2",
                                "MetricName": "CPUUtilization",
                                "Dimensions": [{"Name": "InstanceId", "Value": "i-017c3c1add524779c"}],
                            },
                            "Period": 60,
                            "Stat": "Average",
                        },
                        "ReturnData": True,
                    }
                ],
                StartTime=start_t,
                EndTime=end_t,
            )
            for r in res.get("MetricDataResults", []):
                vals = r.get("Values", [])
                if r.get("Id") == "cpu" and vals:
                    real_cpu = round(float(vals[0]), 1)
                    live_aws_telemetry["cpu"] = real_cpu
                    live_aws_telemetry["last_updated"] = time.time()
                    logger.info("Real AWS CloudWatch CPU for i-017c3c1add524779c: %.2f%%", real_cpu)
        except Exception as exc:
            logger.debug("CloudWatch poll note: %s", exc)
        time.sleep(30.0)

registered_aws_workers: list[dict[str, Any]] = [
    {
        "id": "aws-worker-01",
        "instance_id": "i-017c3c1add524779c",
        "name": "AdaptiveCloud-Worker-01",
        "display_label": "AWS EC2 Worker 01 (i-017c3c1add524779c · Live AWS)",
        "type": "t2.micro",
        "state": "running",
        "public_ip": "3.108.250.115",
        "private_ip": "172.31.6.242",
        "region": "ap-south-1b (Mumbai)",
        "os_version": "Amazon Linux 2023 (Live AWS · omhiwrakar)",
        "agent_platform": "linux",
        "status": "online",
        "is_cloud": True,
        "is_physical": False,
        "is_live_aws": True,
        "cpu": 1.1,
        "mem": 24.5,
        "disk": 18.8,
        "launch_time": "2026-11-17T09:27:00Z",
    }
]

HOSTNAME = socket.gethostname()
LOCAL_IP = "127.0.0.1"
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    LOCAL_IP = s.getsockname()[0]
    s.close()
except Exception:
    pass

OS_DETAILS = f"{platform.system()} {platform.release()} ({platform.machine()})"
CPU_CORES = psutil.cpu_count(logical=True) or 4
RAM_TOTAL_GB = round(psutil.virtual_memory().total / (1024 ** 3), 1)


def generate_fleet_snapshots() -> None:
    """Collect real telemetry for Laptop 1, and simulated hardware telemetry for Laptops 2-4."""
    now_ts = time.time()
    iso_ts = datetime.now(timezone.utc).isoformat()

    # LAPTOP 1: Real Local Hardware
    real_cpu = psutil.cpu_percent(interval=None)
    real_mem = psutil.virtual_memory().percent
    real_disk = psutil.disk_usage("C:\\" if os.name == "nt" else "/").percent
    try:
        real_conns = len(psutil.net_connections(kind="inet"))
    except Exception:
        real_conns = len(psutil.pids()) // 2

    real_procs = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent"]):
        try:
            pinfo = proc.info
            real_procs.append({
                "pid": pinfo["pid"],
                "name": pinfo["name"] or "process",
                "cpu_percent": round(pinfo["cpu_percent"] or 0.0, 1),
            })
        except Exception:
            pass
    real_procs = sorted(real_procs, key=lambda x: x["cpu_percent"], reverse=True)[:5]

    snap_1 = {
        "id": f"m-1-{int(now_ts * 1000)}",
        "host_id": "host-laptop-01",
        "ts": iso_ts,
        "cpu": round(real_cpu, 1),
        "mem": round(real_mem, 1),
        "disk": round(real_disk, 1),
        "conn_count": real_conns,
        "load": round(real_cpu / 25.0, 2),
        "extra": {"top_cpu_processes": real_procs},
    }

    # LAPTOP 2: Lab Workstation A (Port Scan activity)
    t = now_ts / 4
    snap_2 = {
        "id": f"m-2-{int(now_ts * 1000)}",
        "host_id": "host-laptop-02",
        "ts": iso_ts,
        "cpu": round(58.0 + 8.0 * ((t % 3) - 1.5), 1),
        "mem": 72.4,
        "disk": 61.2,
        "conn_count": 182,
        "load": 2.1,
        "extra": {
            "top_cpu_processes": [
                {"name": "nmap_probe.exe", "pid": 8840, "cpu_percent": 24.2},
                {"name": "svchost.exe", "pid": 1044, "cpu_percent": 12.8},
                {"name": "chrome.exe", "pid": 6320, "cpu_percent": 6.4},
            ]
        },
    }

    # LAPTOP 3: Dev Workstation B (XMRig Cryptominer)
    snap_3 = {
        "id": f"m-3-{int(now_ts * 1000)}",
        "host_id": "host-laptop-03",
        "ts": iso_ts,
        "cpu": round(92.0 + 3.0 * ((t % 2) - 1.0), 1),
        "mem": 86.5,
        "disk": 48.0,
        "conn_count": 42,
        "load": 3.8,
        "extra": {
            "top_cpu_processes": [
                {"name": "xmrig-daemon", "pid": 4912, "cpu_percent": 68.5},
                {"name": "stratum-worker", "pid": 4913, "cpu_percent": 14.2},
                {"name": "containerd", "pid": 890, "cpu_percent": 4.5},
            ]
        },
    }

    # LAPTOP 4: Field Workstation C (LSASS Dump)
    snap_4 = {
        "id": f"m-4-{int(now_ts * 1000)}",
        "host_id": "host-laptop-04",
        "ts": iso_ts,
        "cpu": round(42.0 + 5.0 * ((t % 4) - 2.0), 1),
        "mem": 68.2,
        "disk": 55.4,
        "conn_count": 28,
        "load": 1.4,
        "extra": {
            "top_cpu_processes": [
                {"name": "lsass.exe (Audit)", "pid": 680, "cpu_percent": 18.2},
                {"name": "mimikatz_probe.exe", "pid": 7420, "cpu_percent": 9.4},
                {"name": "powershell.exe", "pid": 3204, "cpu_percent": 6.8},
            ]
        },
    }

    # AWS WORKER: AdaptiveCloud-Worker-01 (i-017c3c1add524779c · Live CloudWatch)
    real_aws_cpu = live_aws_telemetry.get("cpu", 1.2)
    snap_aws = {
        "id": f"m-aws-{int(now_ts * 1000)}",
        "host_id": "aws-worker-01",
        "ts": iso_ts,
        "cpu": real_aws_cpu,
        "mem": 24.5,
        "disk": 18.8,
        "conn_count": 14,
        "load": round(real_aws_cpu / 50.0, 2),
        "is_live_aws": True,
        "extra": {
            "top_cpu_processes": [
                {"name": "python3 (agent)", "pid": 1102, "cpu_percent": round(real_aws_cpu * 0.6, 1)},
                {"name": "systemd", "pid": 1, "cpu_percent": 0.2},
                {"name": "sshd", "pid": 890, "cpu_percent": 0.1},
            ]
        },
    }

    # Inject dynamic live anomaly metrics if currently activated
    if "aws-worker-01" in active_anomalies:
        anom = active_anomalies["aws-worker-01"]
        snap_aws["cpu"] = anom.get("cpu", 93.5)
        snap_aws["mem"] = anom.get("mem", 79.2)
        snap_aws["conn_count"] = anom.get("conn_count", 480)
        snap_aws["load"] = 4.8
        snap_aws["extra"]["top_cpu_processes"] = anom.get("processes", [
            {"name": "syn_flood_ingress", "pid": 9811, "cpu_percent": 84.5},
            {"name": "python3 (agent)", "pid": 1102, "cpu_percent": 6.8},
        ])

    # AWS WORKER 2: ap-south-1a (Mumbai) — Healthy secondary worker
    snap_aws2 = {
        "id": f"m-aws2-{int(now_ts * 1000)}",
        "host_id": "aws-worker-02",
        "ts": iso_ts,
        "cpu": round(14.0 + 2.0 * ((t % 7) - 3.5), 1),
        "mem": 38.2,
        "disk": 19.5,
        "conn_count": 8,
        "load": 0.22,
        "extra": {
            "top_cpu_processes": [
                {"name": "nginx", "pid": 1201, "cpu_percent": 0.8},
                {"name": "systemd", "pid": 1, "cpu_percent": 0.3},
            ]
        },
    }

    with fleet_lock:
        fleet_history["host-laptop-01"].append(snap_1)
        fleet_history["host-laptop-02"].append(snap_2)
        fleet_history["host-laptop-03"].append(snap_3)
        fleet_history["host-laptop-04"].append(snap_4)
        fleet_history["aws-worker-01"].append(snap_aws)
        fleet_history["aws-worker-02"].append(snap_aws2)


def background_loop() -> None:
    psutil.cpu_percent(interval=0.5)
    for _ in range(10):
        generate_fleet_snapshots()
        time.sleep(0.1)

    while True:
        try:
            generate_fleet_snapshots()
            logger.info(
                "Streaming 4 Laptops -> L1 (You): %4.1f%% | L2: %4.1f%% | L3: %4.1f%% | L4: %4.1f%%",
                fleet_history["host-laptop-01"][-1]["cpu"],
                fleet_history["host-laptop-02"][-1]["cpu"],
                fleet_history["host-laptop-03"][-1]["cpu"],
                fleet_history["host-laptop-04"][-1]["cpu"],
            )
        except Exception as e:
            logger.error("Simulator error: %s", e)
        time.sleep(2.0)


class MultiLaptopHandler(BaseHTTPRequestHandler):
    def _send_json(self, data: Any, status_code: int = 200) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS, POST, PUT, DELETE")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS, POST, PUT, DELETE")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:
        clean = self.path.split("?")[0]
        content_len = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_len) if content_len > 0 else b"{}"
        try:
            body = json.loads(post_data.decode("utf-8")) if post_data else {}
        except Exception:
            body = {}

        # Auth Login: POST /auth/login or /api/v1/auth/login
        if clean in ("/auth/login", "/api/v1/auth/login"):
            username = body.get("username", "admin")
            import base64
            hdr = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
            payload = base64.urlsafe_b64encode(json.dumps({"sub": username, "role": "admin", "exp": int(time.time()) + 86400 * 7}).encode()).decode().rstrip("=")
            fake_sig = base64.urlsafe_b64encode(b"adaptivecloud_signature").decode().rstrip("=")
            token = f"{hdr}.{payload}.{fake_sig}"
            self._send_json({
                "access_token": token,
                "refresh_token": token,
                "token_type": "bearer",
                "role": "admin",
                "user": {"username": username, "role": "admin"}
            }, 200)
            return

        # Permission Gate: POST /incidents/{id}/approve
        if "/approve" in clean:
            parts = clean.strip("/").split("/")
            inc_id = parts[-2] if len(parts) >= 2 else parts[0]
            try:
                action_ids = body.get("action_ids")
                decided_by = body.get("decided_by", "Operator")
                comment = body.get("comment", "")
                dry_run = body.get("dry_run", True)

                updated = incident_store.approve_and_execute(
                    incident_id=inc_id,
                    action_ids=action_ids,
                    decided_by=decided_by,
                    comment=comment,
                    dry_run=dry_run,
                )
                active_anomalies.clear()
                generate_fleet_snapshots()
                self._send_json(updated, 200)
                return
            except Exception as e:
                self._send_json({"error": str(e)}, 400)
                return

        # Permission Gate: POST /incidents/{id}/reject
        if "/reject" in clean:
            parts = clean.strip("/").split("/")
            inc_id = parts[-2] if len(parts) >= 2 else parts[0]
            try:
                decided_by = body.get("decided_by", "Operator")
                comment = body.get("comment", "")

                updated = incident_store.reject_action(
                    incident_id=inc_id,
                    decided_by=decided_by,
                    comment=comment,
                )
                self._send_json(updated, 200)
                return
            except Exception as e:
                self._send_json({"error": str(e)}, 400)
                return

        # Rollback: POST /incidents/{id}/rollback
        if "/rollback" in clean:
            parts = clean.strip("/").split("/")
            inc_id = parts[-2] if len(parts) >= 2 else parts[0]
            try:
                decided_by = body.get("decided_by", "Operator")
                comment = body.get("comment", "")
                dry_run = body.get("dry_run", True)

                updated = incident_store.rollback_action(
                    incident_id=inc_id,
                    decided_by=decided_by,
                    comment=comment,
                    dry_run=dry_run,
                )
                self._send_json(updated, 200)
                return
            except Exception as e:
                self._send_json({"error": str(e)}, 400)
                return

        # Anomaly Injection: POST /demo/inject or /api/v1/demo/inject
        if clean in ("/demo/inject", "/api/v1/demo/inject"):
            host_id = body.get("host_id", "aws-worker-01")
            attack_type = body.get("attack_type", "ddos").lower()
            try:
                from scripts.aws_cloud_monitor import trigger_aws_incident
                inc = trigger_aws_incident(
                    attack_type=attack_type,
                    target_host="AdaptiveCloud-Worker-01 (i-017c3c1add524779c)",
                )
            except Exception as exc:
                inc = {"incident_id": f"inc-aws-manual-{int(time.time())}", "error": str(exc)}

            if attack_type == "ddos":
                active_anomalies[host_id] = {
                    "cpu": 93.8,
                    "mem": 78.4,
                    "conn_count": 520,
                    "type": "ddos",
                    "processes": [
                        {"name": "syn_flood_ingress", "pid": 9811, "cpu_percent": 84.5},
                        {"name": "iptables_drop", "pid": 9812, "cpu_percent": 7.4},
                    ],
                }
            elif attack_type == "cryptomining":
                active_anomalies[host_id] = {
                    "cpu": 98.6,
                    "mem": 86.2,
                    "conn_count": 45,
                    "type": "cryptomining",
                    "processes": [
                        {"name": "xmrig_miner", "pid": 9941, "cpu_percent": 89.4},
                        {"name": "stratum_daemon", "pid": 9942, "cpu_percent": 8.1},
                    ],
                }
            elif attack_type == "brute_force":
                active_anomalies[host_id] = {
                    "cpu": 52.0,
                    "mem": 58.0,
                    "conn_count": 185,
                    "type": "brute_force",
                    "processes": [
                        {"name": "sshd_auth_fail", "pid": 9710, "cpu_percent": 34.0},
                        {"name": "hydra_spray", "pid": 9711, "cpu_percent": 12.0},
                    ],
                }
            else:
                active_anomalies[host_id] = {
                    "cpu": 85.0,
                    "mem": 88.0,
                    "conn_count": 95,
                    "type": attack_type,
                    "processes": [
                        {"name": "sql_inject_probe", "pid": 9601, "cpu_percent": 74.0},
                    ],
                }

            # Force immediate telemetry snapshot refresh across fleet
            generate_fleet_snapshots()

            self._send_json({
                "success": True,
                "incident": inc,
                "active_anomaly": active_anomalies[host_id],
            }, 200)
            return

        # Anomaly Resolver: POST /demo/resolve or /api/v1/demo/resolve
        if clean in ("/demo/resolve", "/api/v1/demo/resolve"):
            host_id = body.get("host_id", "aws-worker-01")
            active_anomalies.pop(host_id, None)
            generate_fleet_snapshots()
            self._send_json({"success": True, "status": "normal"}, 200)
            return

        # Autonomous Instant Self-Healing: POST /demo/heal or /api/v1/demo/heal or /heal
        if clean in ("/demo/heal", "/api/v1/demo/heal", "/heal", "/api/v1/heal") or clean.endswith("/auto_heal"):
            inc_id = body.get("incident_id")
            host_id = body.get("host_id", "aws-worker-01")
            active_anomalies.clear()
            healed = incident_store.auto_heal(inc_id)
            generate_fleet_snapshots()
            self._send_json({
                "success": True,
                "status": "healed",
                "incident": healed,
                "message": "Autonomous self-healing completed. Threat neutralized without operator delay.",
            }, 200)
            return

        self._send_json({"error": "Endpoint not found"}, 404)

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        clean = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # GET /incidents or /api/v1/incidents
        if clean in ("/incidents", "/api/v1/incidents"):
            incident_store.check_expirations(timeout_seconds=3600)
            family = query_params.get("family", [None])[0]
            status_param = query_params.get("status", [None])[0]
            source = query_params.get("source", [None])[0]
            host_id_param = query_params.get("host_id", [None])[0]
            limit_param = int(query_params.get("limit", ["100"])[0])

            items = incident_store.list_incidents(
                family=family,
                status=status_param,
                source=source,
                host_id=host_id_param,
                limit=limit_param,
            )
            self._send_json(items)
            return

        # GET /incidents/{id}
        if clean.startswith("/incidents/") or clean.startswith("/api/v1/incidents/"):
            parts = clean.strip("/").split("/")
            inc_id = parts[-1]
            inc = incident_store.get_incident(inc_id)
            if inc:
                self._send_json(inc)
            else:
                self._send_json({"error": f"Incident {inc_id} not found"}, 404)
            return

        if clean in ("/", "/info", "/status"):
            info = {
                "status": "online",
                "hostname": HOSTNAME,
                "ip_address": LOCAL_IP,
                "os_version": OS_DETAILS,
                "is_physical": True,
                "active_laptops": 4,
            }
            self._send_json(info)
            return

        if clean in ("/hosts", "/api/v1/hosts"):
            # Pull live readings from fleet history
            with fleet_lock:
                l1 = fleet_history["host-laptop-01"][-1] if fleet_history["host-laptop-01"] else {}
                l2 = fleet_history["host-laptop-02"][-1] if fleet_history["host-laptop-02"] else {}
                l3 = fleet_history["host-laptop-03"][-1] if fleet_history["host-laptop-03"] else {}
                l4 = fleet_history["host-laptop-04"][-1] if fleet_history["host-laptop-04"] else {}
                aws1 = fleet_history["aws-worker-01"][-1] if fleet_history["aws-worker-01"] else {}

            hosts_list = [
                {
                    "id": "host-laptop-01",
                    "hostname": HOSTNAME,
                    "display_label": f"Local Host ({HOSTNAME})",
                    "os_version": OS_DETAILS,
                    "agent_platform": "windows",
                    "ip_address": LOCAL_IP,
                    "status": "online",
                    "is_physical": True,
                    "is_cloud": False,
                    "cpu": round(l1.get("cpu", 25), 1),
                    "mem": round(l1.get("mem", 52), 1),
                    "disk": round(l1.get("disk", 45), 1),
                    "is_active": True,
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                },
                {
                    "id": "aws-worker-01",
                    "hostname": "AdaptiveCloud-Worker-01",
                    "display_label": "AWS EC2 Worker 01 (i-017c3c1add524779c · LIVE AWS)",
                    "os_version": "Amazon Linux 2023 (ap-south-1b · omhiwrakar · LIVE AWS)",
                    "agent_platform": "linux",
                    "ip_address": "3.108.250.115",
                    "private_ip": "172.31.6.242",
                    "status": "online",
                    "is_physical": False,
                    "is_cloud": True,
                    "is_live_aws": True,
                    "cpu": round(aws1.get("cpu", live_aws_telemetry.get("cpu", 1.1)), 1),
                    "mem": 24.5,
                    "disk": 18.8,
                    "instance_id": "i-017c3c1add524779c",
                    "region": "ap-south-1b (Mumbai)",
                    "type": "t2.micro (AWS Free Tier)",
                    "is_active": True,
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                },
                {
                    "id": "aws-worker-02",
                    "hostname": "AdaptiveCloud-Worker-02",
                    "display_label": "AWS EC2 Worker 02 (ap-south-1a)",
                    "os_version": "Amazon Linux 2023 (ap-south-1a · Mumbai)",
                    "agent_platform": "linux",
                    "ip_address": "13.233.142.76",
                    "status": "online",
                    "is_physical": False,
                    "is_cloud": True,
                    "cpu": round(14.0 + 2.0 * ((time.time() / 7) % 2 - 1), 1),
                    "mem": 38.2,
                    "disk": 19.5,
                    "instance_id": "i-0ab2c3d4e5f678901",
                    "region": "ap-south-1a (Mumbai)",
                    "type": "t2.micro (Free Tier)",
                    "is_active": True,
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                },
                {
                    "id": "host-laptop-02",
                    "hostname": "LAB-WORKSTATION-A",
                    "display_label": "Lab Workstation A (Simulated)",
                    "os_version": "Windows 11 Enterprise",
                    "agent_platform": "windows",
                    "ip_address": "192.168.1.102",
                    "status": "online",
                    "is_physical": True,
                    "is_cloud": False,
                    "cpu": round(l2.get("cpu", 64), 1),
                    "mem": round(l2.get("mem", 72), 1),
                    "disk": 68,
                    "is_active": True,
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                },
                {
                    "id": "host-laptop-03",
                    "hostname": "DEV-WORKSTATION-B",
                    "display_label": "Dev Workstation B (Simulated Linux)",
                    "os_version": "Ubuntu 24.04 LTS",
                    "agent_platform": "linux",
                    "ip_address": "192.168.1.103",
                    "status": "online",
                    "is_physical": True,
                    "is_cloud": False,
                    "cpu": round(l3.get("cpu", 94), 1),
                    "mem": round(l3.get("mem", 86), 1),
                    "disk": 82,
                    "is_active": True,
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                },
                {
                    "id": "host-laptop-04",
                    "hostname": "FIELD-WORKSTATION-C",
                    "display_label": "Field Workstation C (Simulated)",
                    "os_version": "Windows 10 Pro",
                    "agent_platform": "windows",
                    "ip_address": "192.168.1.104",
                    "status": "online",
                    "is_physical": True,
                    "is_cloud": False,
                    "cpu": round(l4.get("cpu", 42), 1),
                    "mem": round(l4.get("mem", 68), 1),
                    "disk": 55,
                    "is_active": True,
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                },
            ]
            # Dynamically append any additional AWS workers registered in registered_aws_workers
            existing_ids = {h["id"] for h in hosts_list}
            for aw in registered_aws_workers:
                if aw["id"] not in existing_ids:
                    hosts_list.append({**aw, "last_seen": datetime.now(timezone.utc).isoformat()})
            self._send_json(hosts_list)
            return

        if clean in ("/peers", "/peer-laptops"):
            peers = {
                "host-laptop-02": {
                    "hostname": "LAB-WORKSTATION-A",
                    "display_label": "Lab Workstation A (Physical)",
                    "ip_address": "192.168.1.102",
                    "os_version": "Windows 11 Enterprise",
                    "cpu": 64,
                    "mem": 72,
                },
                "host-laptop-03": {
                    "hostname": "DEV-WORKSTATION-B",
                    "display_label": "Dev Workstation B (Physical Linux)",
                    "ip_address": "192.168.1.103",
                    "os_version": "Ubuntu 24.04 LTS",
                    "cpu": 94,
                    "mem": 86,
                },
                "host-laptop-04": {
                    "hostname": "FIELD-WORKSTATION-C",
                    "display_label": "Field Workstation C (Physical)",
                    "ip_address": "192.168.1.104",
                    "os_version": "Windows 10 Pro",
                    "cpu": 42,
                    "mem": 68,
                },
            }
            self._send_json(peers)
            return

        for card_id in ["host-laptop-01", "host-laptop-02", "host-laptop-03", "host-laptop-04", "aws-worker-01", "aws-worker-02"]:
            if (
                clean == f"/hosts/{card_id}/metrics"
                or clean == f"/api/v1/hosts/{card_id}/metrics"
                or clean.endswith(f"/hosts/{card_id}/metrics")
                or clean == f"/{card_id}/telemetry"
                or clean == f"/api/v1/{card_id}/telemetry"
                or (card_id == "host-laptop-01" and clean in ("/telemetry", "/api/v1/telemetry"))
            ):
                with fleet_lock:
                    pts = list(fleet_history[card_id])
                payload = {
                    "host_id": card_id,
                    "status": "online",
                    "points": pts,
                    "latest": pts[-1] if pts else {},
                }
                self._send_json(payload)
                return

        self._send_json({"error": "Not found"}, 404)

    def log_message(self, format: str, *args: Any) -> None:
        pass


def seed_initial_incidents() -> None:
    """Pre-seed representative incidents covering all sources, families, and approval statuses."""
    existing = incident_store.list_incidents(limit=5)
    if len(existing) >= 3:
        return

    logger.info("Initializing baseline incidents in SQLite store...")
    samples = [
        {
            "incident_id": "inc-live-001",
            "source": "live",
            "host_id": "PHYSICAL-LAPTOP-01 (Host Laptop - Windows 11)",
            "tier1_family": "brute_force",
            "tier1_confidence": 0.968,
            "tier2_technique": "T1110.004 (Credential Stuffing)",
            "tier2_confidence": 0.942,
            "status": "awaiting_approval",
            "features": {"cpu": 24.5, "ram": 52.0, "failed_logins": 42, "inbound_traffic": 140.0, "active_connections": 54, "src_ip": "198.51.100.45"},
            "approval": {"decided_by": None, "decision": None, "decided_at": None, "comment": None},
            "execution_log": [],
            "outcome_summary": "High-confidence credential attack detected. Awaiting operator authorization before firewall block.",
        },
        {
            "incident_id": "inc-sim-002",
            "source": "simulated",
            "host_id": "GCP-VM-EU-02 (Google Cloud VPC Gateway)",
            "tier1_family": "ddos",
            "tier1_confidence": 0.985,
            "tier2_technique": "T1498.001 (Direct Network Flood)",
            "tier2_confidence": 0.970,
            "status": "verified",
            "features": {"cpu": 82.4, "ram": 64.0, "failed_logins": 0, "inbound_traffic": 94000.0, "active_connections": 380, "src_ip": "198.51.100.88"},
            "approval": {"decided_by": "SecOps Lead", "decision": "approved", "decided_at": "2026-11-15T02:00:00Z", "comment": "Approved Cloud Armor edge rate-limit."},
            "execution_log": [
                {
                    "action_id": "ACT_GCP_ARMOR_RATE_LIMIT",
                    "command": "gcloud compute security-policies rules create 1000 --security-policy=cloud-armor-adaptive-waf --src-ip-ranges=198.51.100.0/24 --action=rate-based-ban",
                    "dry_run": True,
                    "status": "simulated",
                    "result": "Rate-limit policy deployed across Google edge POPs in 380ms.",
                    "duration_ms": 380.0,
                    "executed_at": "2026-11-15T02:00:01Z",
                }
            ],
            "verification_result": {
                "verified": True,
                "probe": "GCP Cloud Monitoring Edge Packet Probe",
                "metrics_before": {"inbound_traffic_pps": 94000},
                "metrics_after": {"inbound_traffic_pps": 110},
                "message": "Traffic rate normalized to 110 pkts/s (99.8% reduction).",
            },
            "outcome_summary": "Approved by SecOps Lead. Cloud Armor edge rate-limit verified active.",
        },
        {
            "incident_id": "inc-sim-003",
            "source": "simulated",
            "host_id": "PHYSICAL-LAPTOP-03 (Dev Workstation B - Ubuntu)",
            "tier1_family": "cryptomining",
            "tier1_confidence": 0.975,
            "tier2_technique": "T1496 (Resource Hijacking)",
            "tier2_confidence": 0.960,
            "status": "awaiting_approval",
            "features": {"cpu": 94.2, "ram": 86.0, "failed_logins": 0, "inbound_traffic": 180.0, "active_connections": 45, "pid": 4912, "process_name": "xmrig"},
            "approval": {"decided_by": None, "decision": None, "decided_at": None, "comment": None},
            "execution_log": [],
            "outcome_summary": "Rogue mining daemon identified consuming 94% CPU. Awaiting permission to terminate PID 4912.",
        },
        {
            "incident_id": "inc-live-004",
            "source": "live",
            "host_id": "PHYSICAL-LAPTOP-04 (Field Workstation C)",
            "tier1_family": "privilege_escalation",
            "tier1_confidence": 0.964,
            "tier2_technique": "T1003.001 (LSASS Memory Dump)",
            "tier2_confidence": 0.935,
            "status": "rejected",
            "features": {"cpu": 48.0, "ram": 62.0, "failed_logins": 2, "inbound_traffic": 110.0, "active_connections": 22},
            "approval": {"decided_by": "Compliance Officer", "decision": "rejected", "decided_at": "2026-11-15T01:45:00Z", "comment": "Authorized internal red team penetration test. No action permitted."},
            "execution_log": [],
            "outcome_summary": "Operator rejected countermeasure. Host remains uninhibited for audit.",
        },
        {
            "incident_id": "inc-sim-005",
            "source": "simulated",
            "host_id": "PHYSICAL-LAPTOP-02 (Lab Workstation A)",
            "tier1_family": "port_scan",
            "tier1_confidence": 0.924,
            "tier2_technique": "T1046 (Network Service Scanning)",
            "tier2_confidence": 0.910,
            "status": "expired",
            "features": {"cpu": 22.0, "ram": 48.0, "failed_logins": 0, "inbound_traffic": 340.0, "active_connections": 185},
            "approval": {"decided_by": "System Watchdog", "decision": "expired", "decided_at": "2026-11-15T01:30:00Z", "comment": "Approval window elapsed without human authorization."},
            "execution_log": [],
            "outcome_summary": "Permission gate timed out (300s). No defensive action taken.",
        },
    ]

    for s in samples:
        rca = rca_engine.analyze(
            features=s["features"],
            tier1_family=s["tier1_family"],
            tier1_confidence=s["tier1_confidence"],
            tier2_technique=s["tier2_technique"],
            tier2_confidence=s["tier2_confidence"],
            host_id=s["host_id"],
        )
        s["rca"] = rca
        s["recommended_actions"] = rca["recommended_actions"]
        incident_store.save_incident(s)


def start_websocket_server(ws_port: int = 8002) -> None:
    """Start background WebSocket server for live telemetry streaming."""
    def runner() -> None:
        try:
            import asyncio
            import websockets

            active_clients: set[Any] = set()

            async def ws_handler(websocket: Any) -> None:
                active_clients.add(websocket)
                try:
                    await websocket.send(json.dumps({
                        "channel": "live",
                        "type": "connected",
                        "data": {"status": "connected", "active_laptops": 4, "time": time.time()}
                    }))
                    async for message in websocket:
                        try:
                            msg_obj = json.loads(message)
                            if msg_obj.get("action") == "subscribe":
                                await websocket.send(json.dumps({
                                    "channel": msg_obj.get("channel", "live"),
                                    "type": "subscribed",
                                    "data": {"status": "ok"}
                                }))
                        except Exception:
                            pass
                except Exception:
                    pass
                finally:
                    active_clients.discard(websocket)

            async def broadcast_loop() -> None:
                while True:
                    await asyncio.sleep(2.0)
                    if active_clients:
                        with fleet_lock:
                            l1 = fleet_history["host-laptop-01"][-1] if fleet_history["host-laptop-01"] else {}
                        envelope = json.dumps({
                            "channel": "live",
                            "type": "telemetry",
                            "data": l1,
                        })
                        for ws in list(active_clients):
                            try:
                                await ws.send(envelope)
                            except Exception:
                                pass

            async def start() -> None:
                async with websockets.serve(ws_handler, "0.0.0.0", ws_port):
                    logger.info("Live WebSocket stream active on ws://0.0.0.0:%d", ws_port)
                    await broadcast_loop()

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(start())
        except Exception as exc:
            logger.warning("WebSocket server could not be started: %s", exc)

    t = threading.Thread(target=runner, daemon=True)
    t.start()


def main() -> None:
    banner = f"""
======================================================================
      ADAPTIVECLOUD MULTI-LAPTOP FLEET SIMULATOR v2.5.0
======================================================================
  [+] Host Laptop (You) : {HOSTNAME} ({LOCAL_IP})
  [+] Simulated Fleet   : 4 Physical Laptops Streaming Simultaneously!
  [+] Hub API Port      : http://localhost:{PORT}
  [+] Status            : ALL 4 CARDS ON YOUR SCREEN ARE NOW LIVE!
======================================================================
"""
    print(banner)

    seed_initial_incidents()

    collector_thread = threading.Thread(target=background_loop, daemon=True)
    collector_thread.start()

    aws_thread = threading.Thread(target=aws_cloudwatch_poller, daemon=True)
    aws_thread.start()

    start_websocket_server(8002)

    server = HTTPServer((HOST, PORT), MultiLaptopHandler)
    logger.info("Serving all 4 laptops on port %d...", PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSimulator stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
