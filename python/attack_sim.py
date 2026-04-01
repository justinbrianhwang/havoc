"""
HAVOC - Python Client Library

Connects to the HAVOC C++ server to control attacks programmatically
(Carla-style client-server architecture).

Usage:
    import attack_sim

    sim = attack_sim.Simulator('localhost', 7777)

    # List attacks
    for a in sim.list_attacks():
        print(f"[{a['category']}] {a['name']}: {a['description']}")

    # Start attack
    sim.start_attack('syn_flooding', intensity=100)

    # Monitor
    import time
    for _ in range(10):
        m = sim.get_victim_metrics()
        print(f"Status: {m['status']}, CPU: {m['cpu_usage']}%, PPS: {m['packets_per_sec']}")
        time.sleep(1)

    # Stop
    sim.stop_attack()
"""

import json
import urllib.request
import urllib.error
from typing import Any


class SimulatorError(Exception):
    """Simulator error"""
    pass


class Simulator:
    """HAVOC client"""

    def __init__(self, host: str = "localhost", port: int = 7777):
        self.base_url = f"http://{host}:{port}"
        self._verify_connection()

    def _verify_connection(self):
        """Verify server connection"""
        try:
            info = self._get("/api/info")
            print(f"[Connected] {info['name']} v{info['version']} "
                  f"(port: {info['port']}, attacks: {info['attacks']})")
        except Exception as e:
            raise SimulatorError(
                f"Cannot connect to HAVOC server ({self.base_url}). "
                f"Start the server with start.sh first. Error: {e}"
            )

    def _get(self, path: str) -> Any:
        """GET request"""
        url = self.base_url + path
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())

    def _post(self, path: str, data: dict = None) -> Any:
        """POST request"""
        url = self.base_url + path
        body = json.dumps(data or {}).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())

    # ===== Attack control =====

    def list_attacks(self) -> list[dict]:
        """Return list of available attacks"""
        return self._get("/api/attacks")

    def start_attack(self, attack_type: str, intensity: int = 50,
                     num_bots: int = 10, packet_size: int = 1024) -> dict:
        """
        Start attack

        Args:
            attack_type: Attack type key (e.g. 'syn_flooding', 'trinoo')
            intensity: Attack intensity (packets/cycle, 10~200)
            num_bots: DDoS bot count (DDoS attacks only, 2~50)
            packet_size: Packet size (bytes, 64~65535)

        Attack type keys:
            DoS:  ping_of_death, syn_flooding, boink, bonk, teardrop, land_attack, layer7_dos
            DDoS: trinoo, tfn, tfn_2k, stacheldraht, ddos_malware
        """
        return self._post("/api/attack/start", {
            "attack_type": attack_type,
            "intensity": intensity,
            "num_bots": num_bots,
            "packet_size": packet_size,
        })

    def stop_attack(self) -> dict:
        """Stop current attack"""
        return self._post("/api/attack/stop")

    def get_attack_status(self) -> dict:
        """Get current attack status"""
        return self._get("/api/attack/status")

    # ===== Victim server monitoring =====

    def get_victim_metrics(self) -> dict:
        """
        Get victim server metrics

        Returns:
            status: Server status (Normal/Load Increasing/Delay/Severe/Down)
            cpu_usage: CPU usage (%)
            memory_usage: Memory usage (%)
            bandwidth_mbps: Bandwidth (Mbps)
            total_packets: Total packets received
            packets_per_sec: Packets per second
            active_connections: Active connections
            half_open: Half-open connections
            dropped_packets: Dropped packets
            attack_types: Attack type counts
            top_sources: Top attack source IPs
        """
        return self._get("/api/victim/metrics")

    def reset_victim(self) -> dict:
        """Reset victim server metrics"""
        return self._post("/api/victim/reset")

    # ===== Convenience methods =====

    def print_attacks(self):
        """Pretty-print attack list"""
        attacks = self.list_attacks()
        print("\n=== Available Attacks ===\n")

        current_cat = ""
        for a in attacks:
            if a["category"] != current_cat:
                current_cat = a["category"]
                print(f"\n--- {current_cat} Attacks ---")
            print(f"  [{a['key']}] {a['name']}")
            print(f"    {a['description'][:80]}...")
        print()

    def print_victim_status(self):
        """Pretty-print victim server status"""
        m = self.get_victim_metrics()
        print(f"\n=== Victim Server Status ===")
        print(f"  Status:       {m['status']}")
        print(f"  CPU:        {m['cpu_usage']:.1f}%")
        print(f"  Memory:     {m['memory_usage']:.1f}%")
        print(f"  PPS:        {m['packets_per_sec']:.0f}")
        print(f"  Bandwidth:     {m['bandwidth_mbps']:.2f} Mbps")
        print(f"  Total Pkts:    {m['total_packets']}")
        print(f"  Active Conn:  {m['active_connections']}")
        print(f"  Half-Open:     {m['half_open']}")
        print(f"  Dropped:  {m['dropped_packets']}")

        if m.get("attack_types"):
            print(f"  Attack Detection:")
            for at in m["attack_types"]:
                print(f"    - {at['type']}: {at['count']}")
        print()


# ===== Direct execution demo =====
if __name__ == "__main__":
    import time
    import sys

    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 7777

    sim = Simulator(host, port)
    sim.print_attacks()

    # Interactive mode
    print("=== Interactive Mode ===")
    print("Commands: list, start <type> [intensity] [bots], stop, status, victim, reset, quit\n")

    while True:
        try:
            cmd = input("sim> ").strip().split()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not cmd:
            continue

        try:
            if cmd[0] == "quit":
                break
            elif cmd[0] == "list":
                sim.print_attacks()
            elif cmd[0] == "start" and len(cmd) >= 2:
                intensity = int(cmd[2]) if len(cmd) > 2 else 50
                bots = int(cmd[3]) if len(cmd) > 3 else 10
                result = sim.start_attack(cmd[1], intensity=intensity, num_bots=bots)
                print(f"  → {result}")
            elif cmd[0] == "stop":
                result = sim.stop_attack()
                print(f"  → {result}")
            elif cmd[0] == "status":
                s = sim.get_attack_status()
                print(f"  Attack: {s['attack_type']}, Running: {s['running']}, "
                      f"Packets: {s['packets_sent']}, PPS: {s['packets_per_sec']:.0f}")
            elif cmd[0] == "victim":
                sim.print_victim_status()
            elif cmd[0] == "reset":
                sim.reset_victim()
                print("  → Reset complete")
            elif cmd[0] == "monitor" and len(cmd) >= 2:
                # Auto monitoring mode
                duration = int(cmd[1])
                print(f"  {duration}s monitoring...")
                for i in range(duration):
                    m = sim.get_victim_metrics()
                    bar = "█" * int(m["cpu_usage"] / 5) + "░" * (20 - int(m["cpu_usage"] / 5))
                    print(f"\r  [{bar}] CPU:{m['cpu_usage']:5.1f}% "
                          f"PPS:{m['packets_per_sec']:6.0f} "
                          f"Status:{m['status']}", end="", flush=True)
                    time.sleep(1)
                print()
            else:
                print("  Unknown command. list/start/stop/status/victim/reset/monitor/quit")
        except Exception as e:
            print(f"  Error: {e}")
