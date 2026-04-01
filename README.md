# HAVOC - Network Attack Simulation Engine

HAVOC is an educational network attack simulation engine built with C++17 and OpenGL (Dear ImGui). Simulates 12 types of DoS/DDoS attacks internally with real-time monitoring — no actual network traffic is generated.

<img width="1391" height="849" alt="image" src="https://github.com/user-attachments/assets/1a1278fd-9040-4fbc-9f09-f0e6e3c7ecb7" />

<img width="1391" height="849" alt="image" src="https://github.com/user-attachments/assets/d22be834-25b0-4d3a-addb-5bbc6d448ba6" />


## Features

- **12 Attack Types** simulated with realistic packet generation
  - **DoS (7):** Ping of Death, SYN Flooding, Boink, Bonk, Teardrop, Land Attack, 7-Layer DoS
  - **DDoS (5):** Trinoo, TFN, TFN 2K, Stacheldraht, DDoS Using Malicious Code
- **OpenGL GUI** with attacker control panel and victim monitoring dashboard
- **Real-time Monitoring** — CPU, memory, bandwidth, PPS graphs, attack detection, source IP tracking
- **Multilingual UI** — English, Korean, Spanish
- **Python API** — Control attacks programmatically (Carla-style client-server architecture)
- **Headless Mode** — Run as API-only server without GUI
- **Educational Detail** — Each attack includes description, step-by-step principle, and defense methods

## Screenshots

| Start Screen | Attack Simulation |
|:---:|:---:|
| Language selection, usage guide, creator info | Real-time attacker/victim split-panel dashboard |

## Requirements

- Linux (Ubuntu 20.04+ recommended)
- C++17 compiler (g++ 9+)
- GLFW3 and OpenGL development libraries
- Python 3.8+ (optional, for API client)

### Install Dependencies (Ubuntu/Debian)

```bash
sudo apt install build-essential libglfw3-dev libgl1-mesa-dev pkg-config fonts-nanum
```

## Quick Start

```bash
# Clone and run (auto-downloads ImGui, auto-builds)
./start.sh

# Custom API port
./start.sh 9999

# Headless mode (API server only, no GUI)
./start.sh 7777 --headless
```

## Python API

Control the simulator programmatically while it's running:

```python
import attack_sim

# Connect to running simulator
sim = attack_sim.Simulator('localhost', 7777)

# List available attacks
sim.print_attacks()

# Start an attack
sim.start_attack('syn_flooding', intensity=100)
sim.start_attack('trinoo', intensity=50, num_bots=20)

# Monitor victim
sim.print_victim_status()
metrics = sim.get_victim_metrics()
print(f"CPU: {metrics['cpu_usage']}%, Status: {metrics['status']}")

# Stop
sim.stop_attack()

# Interactive mode
python3 python/attack_sim.py
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/info` | Server info |
| GET | `/api/attacks` | List all attack types |
| POST | `/api/attack/start` | Start attack (`attack_type`, `intensity`, `num_bots`, `packet_size`) |
| POST | `/api/attack/stop` | Stop current attack |
| GET | `/api/attack/status` | Current attack metrics |
| GET | `/api/victim/metrics` | Victim server metrics |
| POST | `/api/victim/reset` | Reset victim metrics |

## Project Structure

```
havoc/
├── src/
│   ├── common.h            # Shared types, packet queue, JSON builder
│   ├── attack_engine.h/cpp # 12 attack simulations (multilingual)
│   ├── victim_engine.h/cpp # Victim server simulation
│   ├── http_server.h/cpp   # REST API server (Python client)
│   ├── gui.h/cpp           # OpenGL GUI (ImGui)
│   └── main.cpp            # Entry point
├── python/
│   └── attack_sim.py       # Python API client library
├── Makefile
├── start.sh                # Build & run script
└── README.md
```

## Attack Types Reference

### DoS Attacks

| Attack | Description |
|--------|-------------|
| **Ping of Death** | Oversized ICMP packets cause buffer overflow on reassembly |
| **SYN Flooding** | Half-open TCP connections exhaust server backlog queue |
| **Boink** | Overlapping UDP fragments trigger reassembly errors |
| **Bonk** | DNS-targeted fragment overlap variant (Windows NT/95) |
| **Teardrop** | Negative-length fragments crash TCP/IP stack |
| **Land Attack** | Self-referencing SYN packets create infinite loop |
| **7-Layer DoS** | Application-layer HTTP flood bypasses network firewalls |

### DDoS Attacks

| Attack | Description |
|--------|-------------|
| **Trinoo** | Master-agent UDP flood via known ports (27665/27444/31335) |
| **TFN** | Multi-protocol attacks via ICMP covert channel |
| **TFN 2K** | Encrypted communication with random protocol switching |
| **Stacheldraht** | Blowfish-encrypted with auto-updating agents |
| **DDoS Malware** | Modern botnet simulation (Mirai/Meris-style) |

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## Author

**Sunjun Hwang**
AI & Quantum Computing Researcher
Building Robust AI Systems that Work in the Real World
[https://www.sjhwang.com/](https://www.sjhwang.com/)

## Disclaimer

This simulator is designed **exclusively for educational and research purposes**. All attacks are simulated internally — no real network traffic is generated. Do not use the knowledge gained from this tool for malicious purposes.
