#include "attack_engine.h"
#include <iostream>

// ============================================================
//  Attack catalog (12 types x 3 languages)
// ============================================================
const std::map<Language, std::vector<AttackInfo>> AttackEngine::attack_catalogs_ = {

// ---- ENGLISH ----
{Language::ENGLISH, {
    // DoS attacks
    {"ping_of_death", "Ping of Death", "DoS",
     "Sends ICMP Echo Request packets crafted to exceed the maximum IP size (65,535 bytes). "
     "When the victim system reassembles the fragmented packets, a buffer overflow occurs, crashing the system.",
     "1. Attacker generates ICMP packets exceeding 65,535 bytes\n"
     "2. Packets are split into multiple fragments by IP protocol\n"
     "3. Victim system reassembles fragments, exceeding buffer size\n"
     "4. Memory overflow -> system crash (Blue Screen / Kernel Panic)",
     "Apply latest OS patches, limit ICMP packet size, block oversized ICMP at firewall"},
    {"syn_flooding", "SYN Flooding", "DoS",
     "Exploits the TCP 3-way handshake by sending mass SYN packets without completing with ACK. "
     "The server's backlog queue fills with half-open connections, refusing legitimate connections.",
     "1. Attacker sends mass SYN packets with spoofed source IPs\n"
     "2. Server responds with SYN-ACK and records in backlog\n"
     "3. Spoofed IPs never return ACK\n"
     "4. Backlog queue saturated -> new TCP connections refused",
     "Enable SYN Cookies, increase backlog queue size, reduce timeout, firewall SYN rate limiting"},
    {"boink", "Boink", "DoS",
     "Manipulates UDP fragment offsets to create overlapping fragments. "
     "Triggers errors in the victim's IP reassembly code, crashing the system.",
     "1. Attacker sends UDP fragments with identical IP IDs\n"
     "2. Fragment offsets are intentionally set to overlap\n"
     "3. Victim's reassembly encounters overlap handling errors\n"
     "4. Kernel panic or system freeze",
     "Apply OS patches (fix fragment reassembly code), block malformed fragments"},
    {"bonk", "Bonk", "DoS",
     "A variant of Boink targeting UDP port 53 (DNS) with crafted overlapping fragments. "
     "Exploits fragment handling vulnerabilities in Windows NT/95 systems.",
     "1. Attacker sends two UDP fragments to DNS port (53)\n"
     "2. First fragment: offset 0, normal size\n"
     "3. Second fragment: offset overlaps with the first\n"
     "4. Reassembly failure -> Blue Screen of Death (BSOD)",
     "Apply OS updates, harden DNS service fragment handling"},
    {"teardrop", "Teardrop", "DoS",
     "Manipulates IP datagram fragment offset fields to produce negative length values. "
     "This causes memory access errors in the victim's TCP/IP stack.",
     "1. Attacker sends two or more IP fragments\n"
     "2. Second fragment's offset is set inside the first fragment\n"
     "3. Reassembly calculates negative or invalid value from (offset + size)\n"
     "4. Invalid length passed to memcpy -> kernel crash",
     "Kernel patches, strengthen fragment validation, set IDS/IPS detection rules"},
    {"land_attack", "Land Attack", "DoS",
     "Sends SYN packets with source IP identical to destination IP. "
     "The victim sends SYN-ACK to itself, entering an infinite loop.",
     "1. Attacker crafts SYN packet: source IP = destination IP, source port = destination port\n"
     "2. Victim receives packet and responds with SYN-ACK\n"
     "3. SYN-ACK is sent to itself\n"
     "4. Infinite loop -> CPU 100% -> system unresponsive",
     "Block SYN packets with self-referencing IPs, apply anti-spoofing filters"},
    {"layer7_dos", "7-Layer DoS (Application Layer)", "DoS",
     "Sends massive legitimate HTTP requests at OSI Layer 7 (application layer). "
     "Since each request appears legitimate, it is extremely difficult to filter at network level.",
     "1. Attacker generates HTTP requests with varied URLs, User-Agents, and methods\n"
     "2. Each request individually appears as normal traffic\n"
     "3. Mass requests exhaust web server worker threads/processes\n"
     "4. Backend resources (DB queries, etc.) depleted -> service outage",
     "WAF (Web Application Firewall), CAPTCHA, behavior-based bot detection, Rate Limiting"},
    // DDoS attacks
    {"trinoo", "Trinoo", "DDoS",
     "One of the earliest DDoS tools. Uses a master-agent architecture where "
     "the master server commands multiple agents (daemons) to perform simultaneous UDP Flood attacks.",
     "1. Attacker sends attack command to Trinoo master (TCP 27665)\n"
     "2. Master propagates command to agents (UDP 27444)\n"
     "3. Agents execute UDP Flood on victim (UDP 31335)\n"
     "4. Simultaneous attack from multiple agents exhausts bandwidth",
     "Block known Trinoo ports (27665, 27444, 31335), monitor for anomalous traffic"},
    {"tfn", "TFN (Tribe Flood Network)", "DDoS",
     "An evolution of Trinoo supporting UDP Flood, SYN Flood, ICMP Flood, and Smurf attacks. "
     "Uses ICMP Echo Reply as a covert communication channel.",
     "1. Attacker sends commands to master via TFN client\n"
     "2. Master-to-agent communication uses ICMP Echo Reply (evades port-based detection)\n"
     "3. Agents execute specified attack type (UDP/SYN/ICMP/Smurf)\n"
     "4. Multi-protocol attacks increase defense complexity",
     "Monitor ICMP traffic, detect anomalous ICMP Echo Reply patterns, find and remove agents"},
    {"tfn_2k", "TFN 2K", "DDoS",
     "An evolution of TFN that encrypts master-agent communication and randomly changes "
     "communication protocols (TCP/UDP/ICMP). Extremely difficult to detect and trace.",
     "1. Attacker-to-master communication is encrypted (Base64 + XOR)\n"
     "2. Master-to-agent protocol changes randomly (TCP/UDP/ICMP)\n"
     "3. Decoy packets sent alongside to disrupt traffic analysis\n"
     "4. Supports SYN/UDP/ICMP/Smurf + Targa3 attacks",
     "Detect encrypted communication patterns, behavioral traffic analysis, Deep Packet Inspection (DPI)"},
    {"stacheldraht", "Stacheldraht", "DDoS",
     "German for 'barbed wire'. Combines Trinoo and TFN features with "
     "symmetric key encrypted master-agent communication and automatic agent updates.",
     "1. Handler (master) and agent communicate via symmetric key encryption (Blowfish-based)\n"
     "2. Agents auto-update to latest version via rcp\n"
     "3. Supports SYN Flood, UDP Flood, ICMP Flood, Smurf attacks\n"
     "4. Uses TCP 16660 (handler), TCP 65000 (agent) ports",
     "Block known ports, analyze encrypted traffic patterns, signature-based agent detection"},
    {"ddos_malware", "DDoS Using Malicious Code", "DDoS",
     "Zombie PCs infected with botnet malware attack simultaneously on C&C server commands. "
     "Simulates modern botnets like Mirai and Meris.",
     "1. Malware infects IoT devices/PCs to form a botnet\n"
     "2. C&C (Command & Control) server directs attack targets and methods\n"
     "3. Thousands to millions of zombies use diverse attack vectors simultaneously\n"
     "4. Combined HTTP Flood + SYN Flood + UDP Flood attack",
     "Strengthen IoT device security, block botnet C&C communication, use CDN/Anti-DDoS services"},
}},

// ---- KOREAN ----
{Language::KOREAN, {
    {"ping_of_death", "Ping of Death", "DoS",
     "ICMP Echo Request \xED\x8C\xA8\xED\x82\xB7\xEC\x9D\x84 IP \xEC\xB5\x9C\xEB\x8C\x80 \xED\x81\xAC\xEA\xB8\xB0(65,535\xEB\xB0\x94\xEC\x9D\xB4\xED\x8A\xB8)\xEB\xA5\xBC \xEC\xB4\x88\xEA\xB3\xBC\xED\x95\x98\xEB\x8F\x84\xEB\xA1\x9D \xEC\xA1\xB0\xEC\x9E\x91\xED\x95\x98\xEC\x97\xAC \xEC\xA0\x84\xEC\x86\xA1\xED\x95\xA9\xEB\x8B\x88\xEB\x8B\xA4. "
     "\xEC\x88\x98\xEC\x8B\xA0 \xEC\x8B\x9C\xEC\x8A\xA4\xED\x85\x9C\xEC\x9D\xB4 \xEC\xA1\xB0\xEA\xB0\x81\xEB\x82\x9C \xED\x8C\xA8\xED\x82\xB7\xEC\x9D\x84 \xEC\x9E\xAC\xEC\xA1\xB0\xEB\xA6\xBD\xED\x95\xA0 \xEB\x95\x8C \xEB\xB2\x84\xED\x8D\xBC \xEC\x98\xA4\xEB\xB2\x84\xED\x94\x8C\xEB\xA1\x9C\xEC\x9A\xB0\xEA\xB0\x80 \xEB\xB0\x9C\xEC\x83\x9D\xED\x95\x98\xEC\x97\xAC \xEC\x8B\x9C\xEC\x8A\xA4\xED\x85\x9C\xEC\x9D\xB4 \xEC\xB6\xA9\xEB\x8F\x8C\xED\x95\xA9\xEB\x8B\x88\xEB\x8B\xA4.",
     "1. \xEA\xB3\xB5\xEA\xB2\xA9\xEC\x9E\x90\xEA\xB0\x80 65,535\xEB\xB0\x94\xEC\x9D\xB4\xED\x8A\xB8\xEB\xA5\xBC \xEC\xB4\x88\xEA\xB3\xBC\xED\x95\x98\xEB\x8A\x94 ICMP \xED\x8C\xA8\xED\x82\xB7\xEC\x9D\x84 \xEC\x83\x9D\xEC\x84\xB1\n"
     "2. IP \xED\x94\x84\xEB\xA1\x9C\xED\x86\xA0\xEC\xBD\x9C\xEC\x97\x90 \xEC\x9D\x98\xED\x95\xB4 \xEC\x97\xAC\xEB\x9F\xAC \xEC\xA1\xB0\xEA\xB0\x81(fragment)\xEC\x9C\xBC\xEB\xA1\x9C \xEB\xB6\x84\xED\x95\xA0\xEB\x90\x98\xEC\x96\xB4 \xEC\xA0\x84\xEC\x86\xA1\n"
     "3. \xED\x94\xBC\xED\x95\xB4 \xEC\x8B\x9C\xEC\x8A\xA4\xED\x85\x9C\xEC\x9D\xB4 \xEC\xA1\xB0\xEA\xB0\x81\xEC\x9D\x84 \xEC\x9E\xAC\xEC\xA1\xB0\xEB\xA6\xBD\xED\x95\x98\xEB\xA9\xB4 \xEB\xB2\x84\xED\x8D\xBC \xED\x81\xAC\xEA\xB8\xB0\xEB\xA5\xBC \xEC\xB4\x88\xEA\xB3\xBC\n"
     "4. \xEB\xA9\x94\xEB\xAA\xA8\xEB\xA6\xAC \xEC\x98\xA4\xEB\xB2\x84\xED\x94\x8C\xEB\xA1\x9C\xEC\x9A\xB0 \xE2\x86\x92 \xEC\x8B\x9C\xEC\x8A\xA4\xED\x85\x9C \xEC\xB6\xA9\xEB\x8F\x8C(Blue Screen/Kernel Panic)",
     "\xEC\xB5\x9C\xEC\x8B\xA0 OS \xED\x8C\xA8\xEC\xB9\x98 \xEC\xA0\x81\xEC\x9A\xA9, ICMP \xED\x8C\xA8\xED\x82\xB7 \xED\x81\xAC\xEA\xB8\xB0 \xEC\xA0\x9C\xED\x95\x9C, \xEB\xB0\xA9\xED\x99\x94\xEB\xB2\xBD\xEC\x97\x90\xEC\x84\x9C \xEB\xB9\x84\xEC\xA0\x95\xEC\x83\x81 \xED\x81\xAC\xEA\xB8\xB0 ICMP \xEC\xB0\xA8\xEB\x8B\xA8"},
    {"syn_flooding", "SYN Flooding", "DoS",
     "TCP 3-way handshake\xEB\xA5\xBC \xEC\x95\x85\xEC\x9A\xA9\xED\x95\x98\xEC\x97\xAC SYN \xED\x8C\xA8\xED\x82\xB7\xEB\xA7\x8C \xEB\x8C\x80\xEB\x9F\x89\xEC\x9C\xBC\xEB\xA1\x9C \xEB\xB3\xB4\xEB\x82\xB4\xEA\xB3\xA0 ACK\xEB\xA5\xBC \xEB\xB3\xB4\xEB\x82\xB4\xEC\xA7\x80 \xEC\x95\x8A\xEC\x8A\xB5\xEB\x8B\x88\xEB\x8B\xA4. "
     "\xEC\x84\x9C\xEB\xB2\x84\xEC\x9D\x98 \xEB\xB0\xB1\xEB\xA1\x9C\xEA\xB7\xB8 \xED\x81\x90\xEA\xB0\x80 \xEB\xB0\x98\xEA\xB0\x9C\xEB\xB0\xA9(half-open) \xEC\x97\xB0\xEA\xB2\xB0\xEB\xA1\x9C \xEA\xB0\x80\xEB\x93\x9D \xEC\xB0\xA8\xEC\x84\x9C \xEC\xA0\x95\xEC\x83\x81 \xEC\x97\xB0\xEA\xB2\xB0\xEC\x9D\x84 \xEB\xB0\x9B\xEC\xA7\x80 \xEB\xAA\xBB\xED\x95\xA9\xEB\x8B\x88\xEB\x8B\xA4.",
     "1. \xEA\xB3\xB5\xEA\xB2\xA9\xEC\x9E\x90\xEA\xB0\x80 \xEC\x9C\x84\xEC\xA1\xB0\xEB\x90\x9C \xEC\xB6\x9C\xEB\xB0\x9C\xEC\xA7\x80 IP\xEB\xA1\x9C SYN \xED\x8C\xA8\xED\x82\xB7\xEC\x9D\x84 \xEB\x8C\x80\xEB\x9F\x89 \xEC\xA0\x84\xEC\x86\xA1\n"
     "2. \xEC\x84\x9C\xEB\xB2\x84\xEB\x8A\x94 \xEA\xB0\x81 SYN\xEC\x97\x90 \xEB\x8C\x80\xED\x95\xB4 SYN-ACK\xEB\xA5\xBC \xEC\x9D\x91\xEB\x8B\xB5\xED\x95\x98\xEA\xB3\xA0 \xEB\xB0\xB1\xEB\xA1\x9C\xEA\xB7\xB8\xEC\x97\x90 \xEA\xB8\xB0\xEB\xA1\x9D\n"
     "3. \xEC\x9C\x84\xEC\xA1\xB0\xEB\x90\x9C IP\xEC\x9D\xB4\xEB\xAF\x80\xEB\xA1\x9C ACK\xEA\xB0\x80 \xEB\x8F\x8C\xEC\x95\x84\xEC\x98\xA4\xEC\xA7\x80 \xEC\x95\x8A\xEC\x9D\x8C\n"
     "4. \xEB\xB0\xB1\xEB\xA1\x9C\xEA\xB7\xB8 \xED\x81\x90 \xED\x8F\xAC\xED\x99\x94 \xE2\x86\x92 \xEC\x8B\xA0\xEA\xB7\x9C TCP \xEC\x97\xB0\xEA\xB2\xB0 \xEB\xB6\x88\xEA\xB0\x80",
     "SYN Cookie \xED\x99\x9C\xEC\x84\xB1\xED\x99\x94, \xEB\xB0\xB1\xEB\xA1\x9C\xEA\xB7\xB8 \xED\x81\x90 \xED\x81\xAC\xEA\xB8\xB0 \xEC\xA6\x9D\xEA\xB0\x80, \xED\x83\x80\xEC\x9E\x84\xEC\x95\x84\xEC\x9B\x83 \xEC\xB6\x95\xEC\x86\x8C, \xEB\xB0\xA9\xED\x99\x94\xEB\xB2\xBD SYN \xEC\x86\x8D\xEB\x8F\x84 \xEC\xA0\x9C\xED\x95\x9C"},
    {"boink", "Boink", "DoS",
     "UDP \xED\x8C\xA8\xED\x82\xB7\xEC\x9D\x98 \xED\x94\x84\xEB\x9E\x98\xEA\xB7\xB8\xEB\xA8\xBC\xED\x8A\xB8 \xEC\x98\xA4\xED\x94\x84\xEC\x85\x8B\xEC\x9D\x84 \xEC\xA1\xB0\xEC\x9E\x91\xED\x95\x98\xEC\x97\xAC \xEA\xB2\xB9\xEC\xB9\x98\xEB\x8A\x94 \xEC\xA1\xB0\xEA\xB0\x81\xEC\x9D\x84 \xEC\x83\x9D\xEC\x84\xB1\xED\x95\xA9\xEB\x8B\x88\xEB\x8B\xA4. "
     "\xED\x94\xBC\xED\x95\xB4 \xEC\x8B\x9C\xEC\x8A\xA4\xED\x85\x9C\xEC\x9D\x98 IP \xEC\x9E\xAC\xEC\xA1\xB0\xEB\xA6\xBD \xEC\xBD\x94\xEB\x93\x9C\xEC\x97\x90\xEC\x84\x9C \xEC\x98\xA4\xEB\xA5\x98\xEB\xA5\xBC \xEC\x9C\xA0\xEB\xB0\x9C\xED\x95\x98\xEC\x97\xAC \xEC\x8B\x9C\xEC\x8A\xA4\xED\x85\x9C\xEC\x9D\x84 \xEB\x8B\xA4\xEC\x9A\xB4\xEC\x8B\x9C\xED\x82\xB5\xEB\x8B\x88\xEB\x8B\xA4.",
     "1. \xEA\xB3\xB5\xEA\xB2\xA9\xEC\x9E\x90\xEA\xB0\x80 \xEB\x8F\x99\xEC\x9D\xBC IP ID\xEB\xA5\xBC \xEA\xB0\x80\xEC\xA7\x84 UDP \xEC\xA1\xB0\xEA\xB0\x81\xEB\x93\xA4\xEC\x9D\x84 \xEC\xA0\x84\xEC\x86\xA1\n"
     "2. \xEA\xB0\x81 \xEC\xA1\xB0\xEA\xB0\x81\xEC\x9D\x98 \xEC\x98\xA4\xED\x94\x84\xEC\x85\x8B\xEC\x9D\xB4 \xEC\x9D\x98\xEB\x8F\x84\xEC\xA0\x81\xEC\x9C\xBC\xEB\xA1\x9C \xEA\xB2\xB9\xEC\xB9\x98\xEB\x8F\x84\xEB\xA1\x9D \xEC\x84\xA4\xEC\xA0\x95\n"
     "3. \xED\x94\xBC\xED\x95\xB4 \xEC\x8B\x9C\xEC\x8A\xA4\xED\x85\x9C\xEC\x9D\xB4 \xEC\x9E\xAC\xEC\xA1\xB0\xEB\xA6\xBD \xEC\x8B\x9C \xEA\xB2\xB9\xEC\xB9\xA8 \xEC\xB2\x98\xEB\xA6\xAC\xEC\x97\x90\xEC\x84\x9C \xEC\x98\xA4\xEB\xA5\x98 \xEB\xB0\x9C\xEC\x83\x9D\n"
     "4. \xEC\xBB\xA4\xEB\x84\x90 \xED\x8C\xA8\xEB\x8B\x89 \xEB\x98\x90\xEB\x8A\x94 \xEC\x8B\x9C\xEC\x8A\xA4\xED\x85\x9C \xED\x94\x84\xEB\xA6\xAC\xEC\xA6\x88",
     "OS \xED\x8C\xA8\xEC\xB9\x98 \xEC\xA0\x81\xEC\x9A\xA9 (\xED\x94\x84\xEB\x9E\x98\xEA\xB7\xB8\xEB\xA8\xBC\xED\x8A\xB8 \xEC\x9E\xAC\xEC\xA1\xB0\xEB\xA6\xBD \xEC\xBD\x94\xEB\x93\x9C \xEC\x88\x98\xEC\xA0\x95), \xEB\xB9\x84\xEC\xA0\x95\xEC\x83\x81 \xED\x94\x84\xEB\x9E\x98\xEA\xB7\xB8\xEB\xA8\xBC\xED\x8A\xB8 \xEC\xB0\xA8\xEB\x8B\xA8"},
    {"bonk", "Bonk", "DoS",
     "Boink\xEC\x9D\x98 \xEB\xB3\x80\xED\x98\x95\xEC\x9C\xBC\xEB\xA1\x9C, UDP \xED\x8F\xAC\xED\x8A\xB8 53(DNS)\xEC\x9D\x84 \xEB\x8C\x80\xEC\x83\x81\xEC\x9C\xBC\xEB\xA1\x9C \xEC\xA1\xB0\xEC\x9E\x91\xEB\x90\x9C \xED\x94\x84\xEB\x9E\x98\xEA\xB7\xB8\xEB\xA8\xBC\xED\x8A\xB8\xEB\xA5\xBC \xEC\xA0\x84\xEC\x86\xA1\xED\x95\xA9\xEB\x8B\x88\xEB\x8B\xA4. "
     "Windows NT/95 \xEC\x8B\x9C\xEC\x8A\xA4\xED\x85\x9C\xEC\x9D\x98 \xED\x94\x84\xEB\x9E\x98\xEA\xB7\xB8\xEB\xA8\xBC\xED\x8A\xB8 \xEC\xB2\x98\xEB\xA6\xAC \xEC\xB7\xA8\xEC\x95\xBD\xEC\xA0\x90\xEC\x9D\x84 \xEB\x85\xB8\xEB\xA6\xBD\xEB\x8B\x88\xEB\x8B\xA4.",
     "1. \xEA\xB3\xB5\xEA\xB2\xA9\xEC\x9E\x90\xEA\xB0\x80 DNS \xED\x8F\xAC\xED\x8A\xB8(53)\xEB\xA1\x9C \xEB\x91\x90 \xEA\xB0\x9C\xEC\x9D\x98 UDP \xED\x94\x84\xEB\x9E\x98\xEA\xB7\xB8\xEB\xA8\xBC\xED\x8A\xB8\xEB\xA5\xBC \xEC\xA0\x84\xEC\x86\xA1\n"
     "2. \xEC\xB2\xAB \xEB\xB2\x88\xEC\xA7\xB8 \xED\x94\x84\xEB\x9E\x98\xEA\xB7\xB8\xEB\xA8\xBC\xED\x8A\xB8: \xEC\x98\xA4\xED\x94\x84\xEC\x85\x8B 0, \xEC\xA0\x95\xEC\x83\x81 \xED\x81\xAC\xEA\xB8\xB0\n"
     "3. \xEB\x91\x90 \xEB\xB2\x88\xEC\xA7\xB8 \xED\x94\x84\xEB\x9E\x98\xEA\xB7\xB8\xEB\xA8\xBC\xED\x8A\xB8: \xEC\x98\xA4\xED\x94\x84\xEC\x85\x8B\xEC\x9D\xB4 \xEC\xB2\xAB \xEB\xB2\x88\xEC\xA7\xB8\xEC\x99\x80 \xEA\xB2\xB9\xEC\xB9\xA8\n"
     "4. \xEC\x9E\xAC\xEC\xA1\xB0\xEB\xA6\xBD \xEC\x8B\xA4\xED\x8C\xA8 \xE2\x86\x92 \xEC\x8B\x9C\xEC\x8A\xA4\xED\x85\x9C \xEB\xB8\x94\xEB\xA3\xA8\xEC\x8A\xA4\xED\x81\xAC\xEB\xA6\xB0(BSOD)",
     "OS \xEC\x97\x85\xEB\x8D\xB0\xEC\x9D\xB4\xED\x8A\xB8 \xEC\xA0\x81\xEC\x9A\xA9, DNS \xEC\x84\x9C\xEB\xB9\x84\xEC\x8A\xA4\xEC\x9D\x98 \xED\x94\x84\xEB\x9E\x98\xEA\xB7\xB8\xEB\xA8\xBC\xED\x8A\xB8 \xEC\xB2\x98\xEB\xA6\xAC \xEA\xB0\x95\xED\x99\x94"},
    {"teardrop", "Teardrop", "DoS",
     "IP \xEB\x8D\xB0\xEC\x9D\xB4\xED\x84\xB0\xEA\xB7\xB8\xEB\x9E\xA8\xEC\x9D\x98 \xED\x94\x84\xEB\x9E\x98\xEA\xB7\xB8\xEB\xA8\xBC\xED\x8A\xB8 \xEC\x98\xA4\xED\x94\x84\xEC\x85\x8B \xED\x95\x84\xEB\x93\x9C\xEB\xA5\xBC \xEC\xA1\xB0\xEC\x9E\x91\xED\x95\x98\xEC\x97\xAC \xEC\x9D\x8C\xEC\x88\x98 \xEA\xB8\xB8\xEC\x9D\xB4\xEA\xB0\x80 \xEC\x82\xB0\xEC\xB6\x9C\xEB\x90\x98\xEA\xB2\x8C \xEB\xA7\x8C\xEB\x93\xAD\xEB\x8B\x88\xEB\x8B\xA4. "
     "\xEC\x9D\xB4\xEB\xA1\x9C \xEC\x9D\xB8\xED\x95\xB4 \xED\x94\xBC\xED\x95\xB4 \xEC\x8B\x9C\xEC\x8A\xA4\xED\x85\x9C\xEC\x9D\x98 TCP/IP \xEC\x8A\xA4\xED\x83\x9D\xEC\x97\x90\xEC\x84\x9C \xEB\xA9\x94\xEB\xAA\xA8\xEB\xA6\xAC \xEC\xA0\x91\xEA\xB7\xBC \xEC\x98\xA4\xEB\xA5\x98\xEA\xB0\x80 \xEB\xB0\x9C\xEC\x83\x9D\xED\x95\xA9\xEB\x8B\x88\xEB\x8B\xA4.",
     "1. \xEA\xB3\xB5\xEA\xB2\xA9\xEC\x9E\x90\xEA\xB0\x80 \xEB\x91\x90 \xEA\xB0\x9C \xEC\x9D\xB4\xEC\x83\x81\xEC\x9D\x98 IP \xED\x94\x84\xEB\x9E\x98\xEA\xB7\xB8\xEB\xA8\xBC\xED\x8A\xB8\xEB\xA5\xBC \xEC\xA0\x84\xEC\x86\xA1\n"
     "2. \xEB\x91\x90 \xEB\xB2\x88\xEC\xA7\xB8 \xED\x94\x84\xEB\x9E\x98\xEA\xB7\xB8\xEB\xA8\xBC\xED\x8A\xB8\xEC\x9D\x98 \xEC\x98\xA4\xED\x94\x84\xEC\x85\x8B\xEC\x9D\xB4 \xEC\xB2\xAB \xEB\xB2\x88\xEC\xA7\xB8 \xEC\x95\x88\xEC\x97\x90 \xEC\x9C\x84\xEC\xB9\x98\xED\x95\x98\xEB\x8F\x84\xEB\xA1\x9D \xEC\x84\xA4\xEC\xA0\x95\n"
     "3. \xEC\x9E\xAC\xEC\xA1\xB0\xEB\xA6\xBD \xEC\x8B\x9C (\xEC\x98\xA4\xED\x94\x84\xEC\x85\x8B + \xED\x81\xAC\xEA\xB8\xB0) \xEA\xB3\x84\xEC\x82\xB0\xEC\x97\x90\xEC\x84\x9C \xEC\x9D\x8C\xEC\x88\x98 \xEB\x98\x90\xEB\x8A\x94 \xEB\xB9\x84\xEC\xA0\x95\xEC\x83\x81 \xEA\xB0\x92 \xEC\x82\xB0\xEC\xB6\x9C\n"
     "4. memcpy\xEC\x97\x90 \xEB\xB9\x84\xEC\xA0\x95\xEC\x83\x81 \xEA\xB8\xB8\xEC\x9D\xB4 \xEC\xA0\x84\xEB\x8B\xAC \xE2\x86\x92 \xEC\xBB\xA4\xEB\x84\x90 \xED\x81\xAC\xEB\x9E\x98\xEC\x8B\x9C",
     "OS \xEC\xBB\xA4\xEB\x84\x90 \xED\x8C\xA8\xEC\xB9\x98, \xED\x94\x84\xEB\x9E\x98\xEA\xB7\xB8\xEB\xA8\xBC\xED\x8A\xB8 \xEC\x9C\xA0\xED\x9A\xA8\xEC\x84\xB1 \xEA\xB2\x80\xEC\xA6\x9D \xEA\xB0\x95\xED\x99\x94, IDS/IPS\xEC\x97\x90\xEC\x84\x9C \xED\x83\x90\xEC\xA7\x80 \xEA\xB7\x9C\xEC\xB9\x99 \xEC\x84\xA4\xEC\xA0\x95"},
    {"land_attack", "Land Attack", "DoS",
     "\xEC\xB6\x9C\xEB\xB0\x9C\xEC\xA7\x80 IP\xEC\x99\x80 \xEB\xAA\xA9\xEC\xA0\x81\xEC\xA7\x80 IP\xEB\xA5\xBC \xEB\x8F\x99\xEC\x9D\xBC\xED\x95\x98\xEA\xB2\x8C \xEC\x84\xA4\xEC\xA0\x95\xED\x95\x9C SYN \xED\x8C\xA8\xED\x82\xB7\xEC\x9D\x84 \xEC\xA0\x84\xEC\x86\xA1\xED\x95\xA9\xEB\x8B\x88\xEB\x8B\xA4. "
     "\xED\x94\xBC\xED\x95\xB4 \xEC\x8B\x9C\xEC\x8A\xA4\xED\x85\x9C\xEC\x9D\xB4 \xEC\x9E\x90\xEA\xB8\xB0 \xEC\x9E\x90\xEC\x8B\xA0\xEC\x97\x90\xEA\xB2\x8C SYN-ACK\xEB\xA5\xBC \xEB\xB3\xB4\xEB\x82\xB4 \xEB\xAC\xB4\xED\x95\x9C \xEB\xA3\xA8\xED\x94\x84\xEC\x97\x90 \xEB\xB9\xA0\xEC\xA7\x91\xEB\x8B\x88\xEB\x8B\xA4.",
     "1. \xEA\xB3\xB5\xEA\xB2\xA9\xEC\x9E\x90\xEA\xB0\x80 SYN \xED\x8C\xA8\xED\x82\xB7\xEC\x9D\x84 \xEC\x83\x9D\xEC\x84\xB1: \xEC\xB6\x9C\xEB\xB0\x9C\xEC\xA7\x80 IP = \xEB\xAA\xA9\xEC\xA0\x81\xEC\xA7\x80 IP\n"
     "2. \xED\x94\xBC\xED\x95\xB4 \xEC\x8B\x9C\xEC\x8A\xA4\xED\x85\x9C\xEC\x9D\xB4 \xED\x8C\xA8\xED\x82\xB7\xEC\x9D\x84 \xEC\x88\x98\xEC\x8B\xA0\xED\x95\x98\xEA\xB3\xA0 SYN-ACK \xEC\x9D\x91\xEB\x8B\xB5\n"
     "3. SYN-ACK\xEA\xB0\x80 \xEC\x9E\x90\xEA\xB8\xB0 \xEC\x9E\x90\xEC\x8B\xA0\xEC\x97\x90\xEA\xB2\x8C \xEC\xA0\x84\xEC\x86\xA1\xEB\x90\xA8\n"
     "4. \xEB\xAC\xB4\xED\x95\x9C \xEB\xA3\xA8\xED\x94\x84 \xE2\x86\x92 CPU 100% \xE2\x86\x92 \xEC\x8B\x9C\xEC\x8A\xA4\xED\x85\x9C \xEC\x9D\x91\xEB\x8B\xB5 \xEB\xB6\x88\xEA\xB0\x80",
     "\xEC\x9E\x90\xEA\xB8\xB0 \xEC\x9E\x90\xEC\x8B\xA0 IP\xEC\x9D\x98 SYN \xED\x8C\xA8\xED\x82\xB7 \xEC\xB0\xA8\xEB\x8B\xA8, \xEC\x95\x88\xED\x8B\xB0\xEC\x8A\xA4\xED\x91\xB8\xED\x95\x91 \xED\x95\x84\xED\x84\xB0 \xEC\xA0\x81\xEC\x9A\xA9"},
    {"layer7_dos", "7-Layer DoS (Application Layer)", "DoS",
     "OSI 7\xEA\xB3\x84\xEC\xB8\xB5(\xEC\x95\xA0\xED\x94\x8C\xEB\xA6\xAC\xEC\xBC\x80\xEC\x9D\xB4\xEC\x85\x98 \xEB\xA0\x88\xEC\x9D\xB4\xEC\x96\xB4)\xEC\x97\x90\xEC\x84\x9C \xEC\xA0\x95\xEC\x83\x81\xEC\xA0\x81\xEC\x9D\xB8 HTTP \xEC\x9A\x94\xEC\xB2\xAD\xEC\x9D\x84 \xEB\x8C\x80\xEB\x9F\x89\xEC\x9C\xBC\xEB\xA1\x9C \xEC\xA0\x84\xEC\x86\xA1\xED\x95\xA9\xEB\x8B\x88\xEB\x8B\xA4. "
     "\xEC\x9A\x94\xEC\xB2\xAD \xEC\x9E\x90\xEC\xB2\xB4\xEA\xB0\x80 \xED\x95\xA9\xEB\xB2\x95\xEC\xA0\x81\xEC\x9D\xB4\xEB\xAF\x80\xEB\xA1\x9C \xEB\x84\xA4\xED\x8A\xB8\xEC\x9B\x8C\xED\x81\xAC \xEB\xA0\x88\xEB\xB2\xA8 \xEB\xB0\xA9\xED\x99\x94\xEB\xB2\xBD\xEC\x9C\xBC\xEB\xA1\x9C \xEA\xB5\xAC\xEB\xB6\x84\xEC\x9D\xB4 \xEB\xA7\xA4\xEC\x9A\xB0 \xEC\x96\xB4\xEB\xA0\xB5\xEC\x8A\xB5\xEB\x8B\x88\xEB\x8B\xA4.",
     "1. \xEA\xB3\xB5\xEA\xB2\xA9\xEC\x9E\x90\xEA\xB0\x80 \xEB\x8B\xA4\xEC\x96\x91\xED\x95\x9C URL, User-Agent, \xEB\xA9\x94\xEC\x84\x9C\xEB\x93\x9C\xEB\xA1\x9C HTTP \xEC\x9A\x94\xEC\xB2\xAD \xEC\x83\x9D\xEC\x84\xB1\n"
     "2. \xEA\xB0\x81 \xEC\x9A\x94\xEC\xB2\xAD\xEC\x9D\xB4 \xEA\xB0\x9C\xEB\xB3\x84\xEC\xA0\x81\xEC\x9C\xBC\xEB\xA1\x9C\xEB\x8A\x94 \xEC\xA0\x95\xEC\x83\x81\xEC\xA0\x81\xEC\x9D\xB8 \xED\x8A\xB8\xEB\x9E\x98\xED\x94\xBD\n"
     "3. \xEB\x8C\x80\xEB\x9F\x89\xEC\x9D\x98 \xEC\x9A\x94\xEC\xB2\xAD\xEC\x9D\xB4 \xEC\x9B\xB9 \xEC\x84\x9C\xEB\xB2\x84\xEC\x9D\x98 \xEC\x9B\x8C\xEC\xBB\xA4 \xEC\x8A\xA4\xEB\xA0\x88\xEB\x93\x9C/\xED\x94\x84\xEB\xA1\x9C\xEC\x84\xB8\xEC\x8A\xA4\xEB\xA5\xBC \xEA\xB3\xA0\xEA\xB0\x88\n"
     "4. \xEB\x8D\xB0\xEC\x9D\xB4\xED\x84\xB0\xEB\xB2\xA0\xEC\x9D\xB4\xEC\x8A\xA4 \xEC\xBF\xBC\xEB\xA6\xAC \xEB\x93\xB1 \xEB\xB0\xB1\xEC\x97\x94\xEB\x93\x9C \xEC\x9E\x90\xEC\x9B\x90\xEA\xB9\x8C\xEC\xA7\x80 \xEC\x86\x8C\xEC\xA7\x84 \xE2\x86\x92 \xEC\x84\x9C\xEB\xB9\x84\xEC\x8A\xA4 \xEC\xA4\x91\xEB\x8B\xA8",
     "WAF(\xEC\x9B\xB9 \xEB\xB0\xA9\xED\x99\x94\xEB\xB2\xBD), CAPTCHA, \xED\x96\x89\xEB\x8F\x99 \xEB\xB6\x84\xEC\x84\x9D \xEA\xB8\xB0\xEB\xB0\x98 \xEB\xB4\x87 \xED\x83\x90\xEC\xA7\x80, Rate Limiting"},
    {"trinoo", "Trinoo", "DDoS",
     "\xEC\xB5\x9C\xEC\xB4\x88\xEC\x9D\x98 DDoS \xEB\x8F\x84\xEA\xB5\xAC \xEC\xA4\x91 \xED\x95\x98\xEB\x82\x98\xEC\x9E\x85\xEB\x8B\x88\xEB\x8B\xA4. \xEB\xA7\x88\xEC\x8A\xA4\xED\x84\xB0-\xEC\x97\x90\xEC\x9D\xB4\xEC\xA0\x84\xED\x8A\xB8 \xEA\xB5\xAC\xEC\xA1\xB0\xEB\xA1\x9C "
     "\xEB\xA7\x88\xEC\x8A\xA4\xED\x84\xB0 \xEC\x84\x9C\xEB\xB2\x84\xEA\xB0\x80 \xEB\x8B\xA4\xEC\x88\x98\xEC\x9D\x98 \xEC\x97\x90\xEC\x9D\xB4\xEC\xA0\x84\xED\x8A\xB8\xEC\x97\x90 \xEB\xAA\x85\xEB\xA0\xB9\xEC\x9D\x84 \xEB\x82\xB4\xEB\xA0\xA4 \xEB\x8F\x99\xEC\x8B\x9C\xEC\x97\x90 UDP Flood \xEA\xB3\xB5\xEA\xB2\xA9\xEC\x9D\x84 \xEC\x88\x98\xED\x96\x89\xED\x95\xA9\xEB\x8B\x88\xEB\x8B\xA4.",
     "1. \xEA\xB3\xB5\xEA\xB2\xA9\xEC\x9E\x90\xEA\xB0\x80 Trinoo \xEB\xA7\x88\xEC\x8A\xA4\xED\x84\xB0\xEC\x97\x90 \xEA\xB3\xB5\xEA\xB2\xA9 \xEB\xAA\x85\xEB\xA0\xB9 \xEC\xA0\x84\xEC\x86\xA1 (TCP 27665)\n"
     "2. \xEB\xA7\x88\xEC\x8A\xA4\xED\x84\xB0\xEA\xB0\x80 \xEC\x97\x90\xEC\x9D\xB4\xEC\xA0\x84\xED\x8A\xB8\xEB\x93\xA4\xEC\x97\x90\xEA\xB2\x8C \xEB\xAA\x85\xEB\xA0\xB9 \xEC\xA0\x84\xED\x8C\x8C (UDP 27444)\n"
     "3. \xEC\x97\x90\xEC\x9D\xB4\xEC\xA0\x84\xED\x8A\xB8\xEB\x93\xA4\xEC\x9D\xB4 \xED\x94\xBC\xED\x95\xB4 \xEC\x8B\x9C\xEC\x8A\xA4\xED\x85\x9C\xEC\x97\x90 UDP Flood \xEC\x8B\xA4\xED\x96\x89 (UDP 31335)\n"
     "4. \xEB\x8B\xA4\xEC\x88\x98 \xEC\x97\x90\xEC\x9D\xB4\xEC\xA0\x84\xED\x8A\xB8\xEC\x9D\x98 \xEB\x8F\x99\xEC\x8B\x9C \xEA\xB3\xB5\xEA\xB2\xA9\xEC\x9C\xBC\xEB\xA1\x9C \xEB\x8C\x80\xEC\x97\xAD\xED\x8F\xAD \xEA\xB3\xA0\xEA\xB0\x88",
     "\xEC\x95\x8C\xEB\xA0\xA4\xEC\xA7\x84 Trinoo \xED\x8F\xAC\xED\x8A\xB8(27665, 27444, 31335) \xEC\xB0\xA8\xEB\x8B\xA8, \xEB\x84\xA4\xED\x8A\xB8\xEC\x9B\x8C\xED\x81\xAC \xEC\x9D\xB4\xEC\x83\x81 \xED\x8A\xB8\xEB\x9E\x98\xED\x94\xBD \xEB\xAA\xA8\xEB\x8B\x88\xED\x84\xB0\xEB\xA7\x81"},
    {"tfn", "TFN (Tribe Flood Network)", "DDoS",
     "Trinoo\xEC\x9D\x98 \xEB\xB0\x9C\xEC\xA0\x84\xED\x98\x95\xEC\x9C\xBC\xEB\xA1\x9C, UDP Flood\xEB\xBF\x90 \xEC\x95\x84\xEB\x8B\x88\xEB\x9D\xBC SYN Flood, ICMP Flood, Smurf \xEA\xB3\xB5\xEA\xB2\xA9\xEC\x9D\x84 "
     "\xEC\xA7\x80\xEC\x9B\x90\xED\x95\xA9\xEB\x8B\x88\xEB\x8B\xA4. ICMP Echo Reply\xEB\xA5\xBC \xEC\x9D\xB4\xEC\x9A\xA9\xED\x95\x9C \xEC\x9D\x80\xEB\x8B\x89 \xED\x86\xB5\xEC\x8B\xA0 \xEC\xB1\x84\xEB\x84\x90\xEC\x9D\x84 \xEC\x82\xAC\xEC\x9A\xA9\xED\x95\xA9\xEB\x8B\x88\xEB\x8B\xA4.",
     "1. \xEA\xB3\xB5\xEA\xB2\xA9\xEC\x9E\x90\xEA\xB0\x80 TFN \xED\x81\xB4\xEB\x9D\xBC\xEC\x9D\xB4\xEC\x96\xB8\xED\x8A\xB8\xEB\xA1\x9C \xEB\xA7\x88\xEC\x8A\xA4\xED\x84\xB0\xEC\x97\x90 \xEB\xAA\x85\xEB\xA0\xB9 \xEC\xA0\x84\xEC\x86\xA1\n"
     "2. \xEB\xA7\x88\xEC\x8A\xA4\xED\x84\xB0\xE2\x86\x92\xEC\x97\x90\xEC\x9D\xB4\xEC\xA0\x84\xED\x8A\xB8 \xED\x86\xB5\xEC\x8B\xA0\xEC\x97\x90 ICMP Echo Reply \xEC\x82\xAC\xEC\x9A\xA9\n"
     "3. \xEC\x97\x90\xEC\x9D\xB4\xEC\xA0\x84\xED\x8A\xB8\xEA\xB0\x80 \xEC\xA7\x80\xEC\xA0\x95\xEB\x90\x9C \xEA\xB3\xB5\xEA\xB2\xA9 \xEC\x9C\xA0\xED\x98\x95 \xEC\x8B\xA4\xED\x96\x89 (UDP/SYN/ICMP/Smurf)\n"
     "4. \xEB\x8B\xA4\xEC\xA4\x91 \xED\x94\x84\xEB\xA1\x9C\xED\x86\xA0\xEC\xBD\x9C \xEA\xB3\xB5\xEA\xB2\xA9\xEC\x9C\xBC\xEB\xA1\x9C \xEB\xB0\xA9\xEC\x96\xB4 \xEB\xB3\xB5\xEC\x9E\xA1\xEB\x8F\x84 \xEC\xA6\x9D\xEA\xB0\x80",
     "ICMP \xED\x8A\xB8\xEB\x9E\x98\xED\x94\xBD \xEB\xAA\xA8\xEB\x8B\x88\xED\x84\xB0\xEB\xA7\x81, \xEC\x9D\xB4\xEC\x83\x81 ICMP Echo Reply \xED\x8C\xA8\xED\x84\xB4 \xED\x83\x90\xEC\xA7\x80, \xEC\x97\x90\xEC\x9D\xB4\xEC\xA0\x84\xED\x8A\xB8 \xED\x83\x90\xEC\xA7\x80 \xEB\xB0\x8F \xEC\xA0\x9C\xEA\xB1\xB0"},
    {"tfn_2k", "TFN 2K", "DDoS",
     "TFN\xEC\x9D\x98 \xEB\xB0\x9C\xEC\xA0\x84\xED\x98\x95\xEC\x9C\xBC\xEB\xA1\x9C, \xEB\xA7\x88\xEC\x8A\xA4\xED\x84\xB0-\xEC\x97\x90\xEC\x9D\xB4\xEC\xA0\x84\xED\x8A\xB8 \xED\x86\xB5\xEC\x8B\xA0\xEC\x9D\x84 \xEC\x95\x94\xED\x98\xB8\xED\x99\x94\xED\x95\x98\xEA\xB3\xA0 \xED\x86\xB5\xEC\x8B\xA0 \xED\x94\x84\xEB\xA1\x9C\xED\x86\xA0\xEC\xBD\x9C\xEC\x9D\x84 "
     "\xEB\xAC\xB4\xEC\x9E\x91\xEC\x9C\x84\xEB\xA1\x9C \xEB\xB3\x80\xEA\xB2\xBD(TCP/UDP/ICMP)\xED\x95\xA9\xEB\x8B\x88\xEB\x8B\xA4. \xED\x83\x90\xEC\xA7\x80\xEC\x99\x80 \xEC\x97\xAD\xEC\xB6\x94\xEC\xA0\x81\xEC\x9D\xB4 \xEB\xA7\xA4\xEC\x9A\xB0 \xEC\x96\xB4\xEB\xA0\xB5\xEC\x8A\xB5\xEB\x8B\x88\xEB\x8B\xA4.",
     "1. \xEA\xB3\xB5\xEA\xB2\xA9\xEC\x9E\x90\xE2\x86\x92\xEB\xA7\x88\xEC\x8A\xA4\xED\x84\xB0 \xED\x86\xB5\xEC\x8B\xA0\xEC\x9D\xB4 \xEC\x95\x94\xED\x98\xB8\xED\x99\x94\xEB\x90\xA8 (Base64 + XOR)\n"
     "2. \xEB\xA7\x88\xEC\x8A\xA4\xED\x84\xB0\xE2\x86\x92\xEC\x97\x90\xEC\x9D\xB4\xEC\xA0\x84\xED\x8A\xB8 \xED\x86\xB5\xEC\x8B\xA0 \xED\x94\x84\xEB\xA1\x9C\xED\x86\xA0\xEC\xBD\x9C\xEC\x9D\xB4 \xEB\x9E\x9C\xEB\x8D\xA4 \xEB\xB3\x80\xEA\xB2\xBD (TCP/UDP/ICMP)\n"
     "3. \xEB\x94\x94\xEC\xBD\x94\xEC\x9D\xB4(decoy) \xED\x8C\xA8\xED\x82\xB7\xEC\x9D\x84 \xED\x95\xA8\xEA\xBB\x98 \xEC\xA0\x84\xEC\x86\xA1\xED\x95\x98\xEC\x97\xAC \xED\x8A\xB8\xEB\x9E\x98\xED\x94\xBD \xEB\xB6\x84\xEC\x84\x9D \xEB\xB0\xA9\xED\x95\xB4\n"
     "4. SYN/UDP/ICMP/Smurf + Targa3 \xEA\xB3\xB5\xEA\xB2\xA9 \xEC\xA7\x80\xEC\x9B\x90",
     "\xEC\x95\x94\xED\x98\xB8\xED\x99\x94 \xED\x86\xB5\xEC\x8B\xA0 \xED\x8C\xA8\xED\x84\xB4 \xED\x83\x90\xEC\xA7\x80, \xEC\x9D\xB4\xEC\x83\x81 \xED\x8A\xB8\xEB\x9E\x98\xED\x94\xBD \xED\x96\x89\xEB\x8F\x99 \xEB\xB6\x84\xEC\x84\x9D, \xEC\x8B\xAC\xEC\xB8\xB5 \xED\x8C\xA8\xED\x82\xB7 \xEA\xB2\x80\xEC\x82\xAC(DPI)"},
    {"stacheldraht", "Stacheldraht", "DDoS",
     "\xEB\x8F\x85\xEC\x9D\xBC\xEC\x96\xB4\xEB\xA1\x9C '\xEC\xB2\xA0\xEC\xA1\xB0\xEB\xA7\x9D'\xEC\x9D\x84 \xEB\x9C\xBB\xED\x95\xA9\xEB\x8B\x88\xEB\x8B\xA4. Trinoo\xEC\x99\x80 TFN\xEC\x9D\x98 \xEA\xB8\xB0\xEB\x8A\xA5\xEC\x9D\x84 \xEA\xB2\xB0\xED\x95\xA9\xED\x95\x98\xEA\xB3\xA0, "
     "\xEB\xA7\x88\xEC\x8A\xA4\xED\x84\xB0-\xEC\x97\x90\xEC\x9D\xB4\xEC\xA0\x84\xED\x8A\xB8 \xEA\xB0\x84 \xEB\x8C\x80\xEC\xB9\xAD \xED\x82\xA4 \xEC\x95\x94\xED\x98\xB8\xED\x99\x94 \xED\x86\xB5\xEC\x8B\xA0\xEA\xB3\xBC \xEC\x97\x90\xEC\x9D\xB4\xEC\xA0\x84\xED\x8A\xB8 \xEC\x9E\x90\xEB\x8F\x99 \xEC\x97\x85\xEB\x8D\xB0\xEC\x9D\xB4\xED\x8A\xB8 \xEA\xB8\xB0\xEB\x8A\xA5\xEC\x9D\x84 \xEA\xB0\x96\xEC\xB6\x94\xEC\x97\x88\xEC\x8A\xB5\xEB\x8B\x88\xEB\x8B\xA4.",
     "1. \xED\x95\xB8\xEB\x93\xA4\xEB\x9F\xAC(\xEB\xA7\x88\xEC\x8A\xA4\xED\x84\xB0)\xEC\x99\x80 \xEC\x97\x90\xEC\x9D\xB4\xEC\xA0\x84\xED\x8A\xB8 \xEA\xB0\x84 \xEB\x8C\x80\xEC\xB9\xAD \xED\x82\xA4 \xEC\x95\x94\xED\x98\xB8\xED\x99\x94 (Blowfish \xEA\xB8\xB0\xEB\xB0\x98)\n"
     "2. \xEC\x97\x90\xEC\x9D\xB4\xEC\xA0\x84\xED\x8A\xB8\xEA\xB0\x80 rcp\xEB\xA5\xBC \xED\x86\xB5\xED\x95\xB4 \xEC\x9E\x90\xEB\x8F\x99\xEC\x9C\xBC\xEB\xA1\x9C \xEC\xB5\x9C\xEC\x8B\xA0 \xEB\xB2\x84\xEC\xA0\x84\xEC\x9C\xBC\xEB\xA1\x9C \xEC\x97\x85\xEB\x8D\xB0\xEC\x9D\xB4\xED\x8A\xB8\n"
     "3. SYN Flood, UDP Flood, ICMP Flood, Smurf \xEA\xB3\xB5\xEA\xB2\xA9 \xEC\xA7\x80\xEC\x9B\x90\n"
     "4. TCP 16660(\xED\x95\xB8\xEB\x93\xA4\xEB\x9F\xAC), TCP 65000(\xEC\x97\x90\xEC\x9D\xB4\xEC\xA0\x84\xED\x8A\xB8) \xED\x8F\xAC\xED\x8A\xB8 \xEC\x82\xAC\xEC\x9A\xA9",
     "\xEC\x95\x8C\xEB\xA0\xA4\xEC\xA7\x84 \xED\x8F\xAC\xED\x8A\xB8 \xEC\xB0\xA8\xEB\x8B\xA8, \xEC\x95\x94\xED\x98\xB8\xED\x99\x94 \xED\x8A\xB8\xEB\x9E\x98\xED\x94\xBD \xED\x8C\xA8\xED\x84\xB4 \xEB\xB6\x84\xEC\x84\x9D, \xEC\x97\x90\xEC\x9D\xB4\xEC\xA0\x84\xED\x8A\xB8 \xEC\x8B\x9C\xEA\xB7\xB8\xEB\x8B\x88\xEC\xB2\x98 \xEA\xB8\xB0\xEB\xB0\x98 \xED\x83\x90\xEC\xA7\x80"},
    {"ddos_malware", "DDoS Using Malicious Code", "DDoS",
     "\xEC\x95\x85\xEC\x84\xB1\xEC\xBD\x94\xEB\x93\x9C(\xEB\xB4\x87\xEB\x84\xB7 \xEB\xA9\x80\xEC\x9B\xA8\xEC\x96\xB4)\xEC\x97\x90 \xEA\xB0\x90\xEC\x97\xBC\xEB\x90\x9C \xEC\xA2\x80\xEB\xB9\x84 PC\xEB\x93\xA4\xEC\x9D\xB4 C&C \xEC\x84\x9C\xEB\xB2\x84\xEC\x9D\x98 \xEB\xAA\x85\xEB\xA0\xB9\xEC\x97\x90 \xEB\x94\xB0\xEB\x9D\xBC "
     "\xEC\x9D\xBC\xEC\xA0\x9C\xED\x9E\x88 \xEA\xB3\xB5\xEA\xB2\xA9\xED\x95\xA9\xEB\x8B\x88\xEB\x8B\xA4. Mirai, Meris \xEB\x93\xB1 \xED\x98\x84\xEB\x8C\x80\xEC\xA0\x81 \xEB\xB4\x87\xEB\x84\xB7\xEC\x9D\x98 \xEB\x8F\x99\xEC\x9E\x91 \xEB\xB0\xA9\xEC\x8B\x9D\xEC\x9D\x84 \xEC\x8B\x9C\xEB\xAE\xAC\xEB\xA0\x88\xEC\x9D\xB4\xEC\x85\x98\xED\x95\xA9\xEB\x8B\x88\xEB\x8B\xA4.",
     "1. \xEC\x95\x85\xEC\x84\xB1\xEC\xBD\x94\xEB\x93\x9C\xEA\xB0\x80 IoT \xEA\xB8\xB0\xEA\xB8\xB0/PC\xEC\x97\x90 \xEA\xB0\x90\xEC\x97\xBC\xEB\x90\x98\xEC\x96\xB4 \xEB\xB4\x87\xEB\x84\xB7 \xED\x98\x95\xEC\x84\xB1\n"
     "2. C&C(Command & Control) \xEC\x84\x9C\xEB\xB2\x84\xEA\xB0\x80 \xEA\xB3\xB5\xEA\xB2\xA9 \xEB\xAA\xA9\xED\x91\x9C\xEC\x99\x80 \xEB\xB0\xA9\xEB\xB2\x95\xEC\x9D\x84 \xEC\xA7\x80\xEC\x8B\x9C\n"
     "3. \xEC\x88\x98\xEC\xB2\x9C~\xEC\x88\x98\xEB\xB0\xB1\xEB\xA7\x8C \xEC\xA2\x80\xEB\xB9\x84\xEA\xB0\x80 \xEB\x8F\x99\xEC\x8B\x9C\xEC\x97\x90 \xEB\x8B\xA4\xEC\x96\x91\xED\x95\x9C \xEA\xB3\xB5\xEA\xB2\xA9 \xEB\xB2\xA1\xED\x84\xB0 \xEC\x82\xAC\xEC\x9A\xA9\n"
     "4. HTTP Flood + SYN Flood + UDP Flood \xEB\xB3\xB5\xED\x95\xA9 \xEA\xB3\xB5\xEA\xB2\xA9",
     "IoT \xEA\xB8\xB0\xEA\xB8\xB0 \xEB\xB3\xB4\xEC\x95\x88 \xEA\xB0\x95\xED\x99\x94, \xEB\xB4\x87\xEB\x84\xB7 C&C \xED\x86\xB5\xEC\x8B\xA0 \xEC\xB0\xA8\xEB\x8B\xA8, CDN/Anti-DDoS \xEC\x84\x9C\xEB\xB9\x84\xEC\x8A\xA4 \xEC\x82\xAC\xEC\x9A\xA9"},
}},

// ---- SPANISH ----
{Language::SPANISH, {
    {"ping_of_death", "Ping of Death", "DoS",
     "Envia paquetes ICMP Echo Request manipulados para exceder el tamano maximo de IP (65,535 bytes). "
     "Cuando el sistema victima reensambla los paquetes fragmentados, ocurre un desbordamiento de buffer.",
     "1. El atacante genera paquetes ICMP que exceden 65,535 bytes\n"
     "2. Los paquetes se dividen en multiples fragmentos por el protocolo IP\n"
     "3. El sistema victima reensambla los fragmentos, excediendo el tamano del buffer\n"
     "4. Desbordamiento de memoria -> caida del sistema (Blue Screen / Kernel Panic)",
     "Aplicar parches de SO, limitar tamano de paquetes ICMP, bloquear ICMP sobredimensionados en firewall"},
    {"syn_flooding", "SYN Flooding", "DoS",
     "Explota el handshake TCP de 3 vias enviando paquetes SYN masivos sin completar con ACK. "
     "La cola de backlog del servidor se llena con conexiones semi-abiertas.",
     "1. El atacante envia paquetes SYN masivos con IPs de origen falsificadas\n"
     "2. El servidor responde con SYN-ACK y registra en el backlog\n"
     "3. Las IPs falsificadas nunca devuelven ACK\n"
     "4. Cola de backlog saturada -> nuevas conexiones TCP rechazadas",
     "Habilitar SYN Cookies, aumentar tamano del backlog, reducir timeout, limitar tasa SYN en firewall"},
    {"boink", "Boink", "DoS",
     "Manipula los offsets de fragmentos UDP para crear fragmentos superpuestos. "
     "Provoca errores en el codigo de reensamblaje IP de la victima.",
     "1. El atacante envia fragmentos UDP con IDs IP identicos\n"
     "2. Los offsets de fragmentos se configuran intencionalmente para superponerse\n"
     "3. El reensamblaje de la victima encuentra errores de manejo de superposicion\n"
     "4. Panico del kernel o congelamiento del sistema",
     "Aplicar parches de SO, bloquear fragmentos malformados"},
    {"bonk", "Bonk", "DoS",
     "Una variante de Boink dirigida al puerto UDP 53 (DNS) con fragmentos superpuestos manipulados. "
     "Explota vulnerabilidades de manejo de fragmentos en sistemas Windows NT/95.",
     "1. El atacante envia dos fragmentos UDP al puerto DNS (53)\n"
     "2. Primer fragmento: offset 0, tamano normal\n"
     "3. Segundo fragmento: offset se superpone con el primero\n"
     "4. Fallo de reensamblaje -> Pantalla Azul de la Muerte (BSOD)",
     "Aplicar actualizaciones de SO, fortalecer manejo de fragmentos del servicio DNS"},
    {"teardrop", "Teardrop", "DoS",
     "Manipula los campos de offset de fragmentos de datagramas IP para producir valores de longitud negativos. "
     "Esto causa errores de acceso a memoria en la pila TCP/IP de la victima.",
     "1. El atacante envia dos o mas fragmentos IP\n"
     "2. El offset del segundo fragmento se establece dentro del primer fragmento\n"
     "3. El reensamblaje calcula un valor negativo o invalido de (offset + tamano)\n"
     "4. Longitud invalida pasada a memcpy -> caida del kernel",
     "Parches del kernel, fortalecer validacion de fragmentos, configurar reglas de deteccion IDS/IPS"},
    {"land_attack", "Land Attack", "DoS",
     "Envia paquetes SYN con IP de origen identica a la IP de destino. "
     "La victima envia SYN-ACK a si misma, entrando en un bucle infinito.",
     "1. El atacante crea paquete SYN: IP origen = IP destino, puerto origen = puerto destino\n"
     "2. La victima recibe el paquete y responde con SYN-ACK\n"
     "3. SYN-ACK se envia a si mismo\n"
     "4. Bucle infinito -> CPU 100% -> sistema sin respuesta",
     "Bloquear paquetes SYN con IPs auto-referenciadas, aplicar filtros anti-spoofing"},
    {"layer7_dos", "7-Layer DoS (Application Layer)", "DoS",
     "Envia solicitudes HTTP legitimas masivas en la capa 7 de OSI (capa de aplicacion). "
     "Como cada solicitud parece legitima, es extremadamente dificil filtrar a nivel de red.",
     "1. El atacante genera solicitudes HTTP con URLs, User-Agents y metodos variados\n"
     "2. Cada solicitud individualmente parece trafico normal\n"
     "3. Las solicitudes masivas agotan los hilos/procesos del servidor web\n"
     "4. Recursos backend (consultas DB, etc.) agotados -> interrupcion del servicio",
     "WAF, CAPTCHA, deteccion de bots basada en comportamiento, Rate Limiting"},
    {"trinoo", "Trinoo", "DDoS",
     "Una de las primeras herramientas DDoS. Usa arquitectura maestro-agente donde "
     "el servidor maestro ordena a multiples agentes realizar ataques UDP Flood simultaneos.",
     "1. El atacante envia comando de ataque al maestro Trinoo (TCP 27665)\n"
     "2. El maestro propaga el comando a los agentes (UDP 27444)\n"
     "3. Los agentes ejecutan UDP Flood contra la victima (UDP 31335)\n"
     "4. Ataque simultaneo de multiples agentes agota el ancho de banda",
     "Bloquear puertos conocidos de Trinoo (27665, 27444, 31335), monitorear trafico anomalo"},
    {"tfn", "TFN (Tribe Flood Network)", "DDoS",
     "Una evolucion de Trinoo que soporta UDP Flood, SYN Flood, ICMP Flood y ataques Smurf. "
     "Usa ICMP Echo Reply como canal de comunicacion encubierto.",
     "1. El atacante envia comandos al maestro via cliente TFN\n"
     "2. Comunicacion maestro-agente usa ICMP Echo Reply (evade deteccion por puertos)\n"
     "3. Los agentes ejecutan el tipo de ataque especificado (UDP/SYN/ICMP/Smurf)\n"
     "4. Ataques multi-protocolo aumentan la complejidad de defensa",
     "Monitorear trafico ICMP, detectar patrones anomalos de ICMP Echo Reply, encontrar y eliminar agentes"},
    {"tfn_2k", "TFN 2K", "DDoS",
     "Una evolucion de TFN que cifra la comunicacion maestro-agente y cambia aleatoriamente "
     "los protocolos de comunicacion (TCP/UDP/ICMP). Extremadamente dificil de detectar y rastrear.",
     "1. Comunicacion atacante-maestro cifrada (Base64 + XOR)\n"
     "2. Protocolo maestro-agente cambia aleatoriamente (TCP/UDP/ICMP)\n"
     "3. Paquetes senuelo enviados junto para interrumpir analisis de trafico\n"
     "4. Soporta ataques SYN/UDP/ICMP/Smurf + Targa3",
     "Detectar patrones de comunicacion cifrada, analisis conductual de trafico, Inspeccion Profunda de Paquetes (DPI)"},
    {"stacheldraht", "Stacheldraht", "DDoS",
     "Aleman para 'alambre de puas'. Combina caracteristicas de Trinoo y TFN con "
     "comunicacion cifrada por clave simetrica y actualizaciones automaticas de agentes.",
     "1. Handler (maestro) y agente se comunican via cifrado de clave simetrica (basado en Blowfish)\n"
     "2. Los agentes se auto-actualizan a la ultima version via rcp\n"
     "3. Soporta SYN Flood, UDP Flood, ICMP Flood, ataques Smurf\n"
     "4. Usa puertos TCP 16660 (handler), TCP 65000 (agente)",
     "Bloquear puertos conocidos, analizar patrones de trafico cifrado, deteccion de agentes basada en firmas"},
    {"ddos_malware", "DDoS Using Malicious Code", "DDoS",
     "PCs zombi infectados con malware de botnet atacan simultaneamente bajo comandos del servidor C&C. "
     "Simula botnets modernos como Mirai y Meris.",
     "1. El malware infecta dispositivos IoT/PCs para formar una botnet\n"
     "2. El servidor C&C (Comando y Control) dirige objetivos y metodos de ataque\n"
     "3. Miles a millones de zombis usan diversos vectores de ataque simultaneamente\n"
     "4. Ataque combinado HTTP Flood + SYN Flood + UDP Flood",
     "Fortalecer seguridad de dispositivos IoT, bloquear comunicacion C&C de botnet, usar servicios CDN/Anti-DDoS"},
}},

};

// ============================================================
//  Constructor / Destructor
// ============================================================
AttackEngine::AttackEngine(PacketQueue& queue) : queue_(queue) {}

AttackEngine::~AttackEngine() {
    stop();
}

// ============================================================
//  Attack list
// ============================================================
std::vector<AttackInfo> AttackEngine::list_attacks(Language lang) const {
    auto it = attack_catalogs_.find(lang);
    if (it != attack_catalogs_.end()) return it->second;
    return attack_catalogs_.at(Language::ENGLISH);
}

AttackInfo AttackEngine::get_attack_info(AttackType type, Language lang) const {
    std::string key = attack_type_key(type);
    auto& catalog = attack_catalogs_.count(lang) ? attack_catalogs_.at(lang) : attack_catalogs_.at(Language::ENGLISH);
    for (auto& a : catalog) {
        if (a.key == key) return a;
    }
    return {};
}

// ============================================================
//  Attack control
// ============================================================
bool AttackEngine::start(AttackType type, const AttackParams& params) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (running_) return false;

    current_type_ = type;
    current_params_ = params;
    packets_sent_ = 0;
    pps_ = 0;
    start_time_ = now_sec();
    running_ = true;

    logs_.add(std::string(L("Attack started: ", "공격 시작: ", "Ataque iniciado: ")) + attack_type_name(type));
    logs_.add("  " + std::string(L("Intensity: ", "강도: ", "Intensidad: ")) + std::to_string(params.intensity) +
              ", " + std::string(L("Pkt size: ", "패킷크기: ", "Tam. paquete: ")) + std::to_string(params.packet_size));
    if (is_ddos(type))
        logs_.add("  " + std::string(L("Bots: ", "봇 수: ", "Bots: ")) + std::to_string(params.num_bots));

    threads_.emplace_back(&AttackEngine::run_attack, this);
    return true;
}

void AttackEngine::stop() {
    running_ = false;
    for (auto& t : threads_) {
        if (t.joinable()) t.join();
    }
    threads_.clear();
    logs_.add(L("Attack stopped", "공격 중지됨", "Ataque detenido"));
}

AttackMetrics AttackEngine::get_metrics() const {
    AttackMetrics m;
    m.type = current_type_;
    m.running = running_;
    m.packets_sent = packets_sent_;
    m.packets_per_sec = pps_;
    if (start_time_ > 0)
        m.elapsed_sec = now_sec() - start_time_;
    m.active_bots = is_ddos(current_type_) ? current_params_.num_bots : 0;
    return m;
}

// ============================================================
//  Packet transmission
// ============================================================
void AttackEngine::send_packet(const SimPacket& pkt) {
    queue_.push(pkt);
    packets_sent_++;
}

// ============================================================
//  Attack router
// ============================================================
void AttackEngine::run_attack() {
    switch (current_type_) {
        case AttackType::PING_OF_DEATH:  generate_ping_of_death(current_params_); break;
        case AttackType::SYN_FLOODING:   generate_syn_flooding(current_params_);  break;
        case AttackType::BOINK:          generate_boink(current_params_);          break;
        case AttackType::BONK:           generate_bonk(current_params_);           break;
        case AttackType::TEARDROP:       generate_teardrop(current_params_);       break;
        case AttackType::LAND_ATTACK:    generate_land_attack(current_params_);    break;
        case AttackType::LAYER7_DOS:     generate_layer7_dos(current_params_);     break;
        case AttackType::TRINOO:         generate_trinoo(current_params_);         break;
        case AttackType::TFN:            generate_tfn(current_params_);            break;
        case AttackType::TFN_2K:         generate_tfn_2k(current_params_);         break;
        case AttackType::STACHELDRAHT:   generate_stacheldraht(current_params_);   break;
        case AttackType::DDOS_MALWARE:   generate_ddos_malware(current_params_);   break;
        default: break;
    }
    running_ = false;
}

// ============================================================
//  DoS attack implementations
// ============================================================

void AttackEngine::generate_ping_of_death(const AttackParams& p) {
    logs_.add(L("[Ping of Death] Generating oversized ICMP packets (>65,535B)",
               "[Ping of Death] 65,535바이트 초과 ICMP 패킷 생성 시작",
               "[Ping of Death] Generando paquetes ICMP sobredimensionados (>65,535B)"));
    uint32_t seq = 0;
    uint32_t target_ip = 0x7F000001;
    auto last_log = now_sec();

    while (running_) {
        for (int i = 0; i < p.intensity && running_; i++) {
            uint32_t total_size = 65536 + random_int(1, 1000);
            uint32_t frag_id = seq;
            uint32_t offset = 0;
            int frag_count = 0;

            while (offset < total_size && running_) {
                uint32_t frag_size = std::min((uint32_t)p.packet_size, total_size - offset);
                SimPacket pkt{};
                pkt.type = AttackType::PING_OF_DEATH;
                pkt.src_ip = random_ip();
                pkt.src_port = 0;
                pkt.dst_ip = target_ip;
                pkt.dst_port = 0;
                pkt.seq = seq++;
                pkt.payload_size = frag_size;
                pkt.frag_offset = offset;
                pkt.frag_id = frag_id;
                pkt.flags = (offset + frag_size < total_size) ? 0x2000 : 0; // MF flag
                pkt.bot_id = 0;
                pkt.timestamp = now_sec();
                send_packet(pkt);
                offset += frag_size;
                frag_count++;
            }

            if (now_sec() - last_log > 2.0) {
                logs_.add("[Ping of Death] Sent: " + std::to_string(packets_sent_.load()) +
                         " fragments, pkt size: " + std::to_string(total_size) + "B (oversized)");
                pps_ = packets_sent_ / std::max(0.1, now_sec() - start_time_);
                last_log = now_sec();
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void AttackEngine::generate_syn_flooding(const AttackParams& p) {
    logs_.add(L("[SYN Flooding] Mass half-open connection generation started", "[SYN Flooding] 반개방 연결 대량 생성 시작", "[SYN Flooding] Generacion masiva de conexiones semi-abiertas iniciada"));
    uint32_t seq = 0;
    uint32_t target_ip = 0x7F000001;
    auto last_log = now_sec();

    while (running_) {
        for (int i = 0; i < p.intensity && running_; i++) {
            SimPacket pkt{};
            pkt.type = AttackType::SYN_FLOODING;
            pkt.src_ip = random_ip();  // Spoofed source IP
            pkt.src_port = random_port();
            pkt.dst_ip = target_ip;
            pkt.dst_port = 80;
            pkt.seq = seq++;
            pkt.payload_size = 0;
            pkt.frag_offset = 0;
            pkt.frag_id = 0;
            pkt.flags = FLAG_SYN;  // SYN only
            pkt.bot_id = 0;
            pkt.timestamp = now_sec();
            send_packet(pkt);
        }

        if (now_sec() - last_log > 2.0) {
            logs_.add("[SYN Flooding] SYN pkts: " + std::to_string(packets_sent_.load()) +
                     ", spoofed IPs");
            pps_ = packets_sent_ / std::max(0.1, now_sec() - start_time_);
            last_log = now_sec();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void AttackEngine::generate_boink(const AttackParams& p) {
    logs_.add(L("[Boink] Overlapping UDP fragment attack started", "[Boink] 겹치는 UDP 프래그먼트 공격 시작", "[Boink] Ataque de fragmentos UDP superpuestos iniciado"));
    uint32_t seq = 0;
    uint32_t target_ip = 0x7F000001;
    auto last_log = now_sec();

    while (running_) {
        for (int i = 0; i < p.intensity && running_; i++) {
            uint32_t frag_id = seq / 3;

            // Send three overlapping fragments
            for (int f = 0; f < 3 && running_; f++) {
                SimPacket pkt{};
                pkt.type = AttackType::BOINK;
                pkt.src_ip = random_ip();
                pkt.src_port = random_port();
                pkt.dst_ip = target_ip;
                pkt.dst_port = random_int(1, 65535);
                pkt.seq = seq++;
                pkt.payload_size = p.packet_size;
                // Intentionally overlapping offset
                pkt.frag_offset = f * (p.packet_size / 2);  // 50% overlap
                pkt.frag_id = frag_id;
                pkt.flags = (f < 2) ? 0x2000 : 0;
                pkt.bot_id = 0;
                pkt.timestamp = now_sec();
                send_packet(pkt);
            }
        }

        if (now_sec() - last_log > 2.0) {
            logs_.add("[Boink] Overlapping fragments: " + std::to_string(packets_sent_.load()));
            pps_ = packets_sent_ / std::max(0.1, now_sec() - start_time_);
            last_log = now_sec();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void AttackEngine::generate_bonk(const AttackParams& p) {
    logs_.add(L("[Bonk] DNS port fragment attack started", "[Bonk] DNS 포트 대상 프래그먼트 공격 시작", "[Bonk] Ataque de fragmentos al puerto DNS iniciado"));
    uint32_t seq = 0;
    uint32_t target_ip = 0x7F000001;
    auto last_log = now_sec();

    while (running_) {
        for (int i = 0; i < p.intensity && running_; i++) {
            uint32_t frag_id = seq / 2;

            // Two overlapping fragments targeting DNS port 53
            for (int f = 0; f < 2 && running_; f++) {
                SimPacket pkt{};
                pkt.type = AttackType::BONK;
                pkt.src_ip = random_ip();
                pkt.src_port = random_port();
                pkt.dst_ip = target_ip;
                pkt.dst_port = 53;  // DNS port
                pkt.seq = seq++;
                pkt.payload_size = p.packet_size;
                pkt.frag_offset = (f == 0) ? 0 : p.packet_size - 1; // 1-byte overlap
                pkt.frag_id = frag_id;
                pkt.flags = (f == 0) ? 0x2000 : 0;
                pkt.bot_id = 0;
                pkt.timestamp = now_sec();
                send_packet(pkt);
            }
        }

        if (now_sec() - last_log > 2.0) {
            logs_.add("[Bonk] DNS fragment attack: " + std::to_string(packets_sent_.load()));
            pps_ = packets_sent_ / std::max(0.1, now_sec() - start_time_);
            last_log = now_sec();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void AttackEngine::generate_teardrop(const AttackParams& p) {
    logs_.add(L("[Teardrop] Negative-length fragment attack started", "[Teardrop] 음수 길이 프래그먼트 공격 시작", "[Teardrop] Ataque de fragmentos con longitud negativa iniciado"));
    uint32_t seq = 0;
    uint32_t target_ip = 0x7F000001;
    auto last_log = now_sec();

    while (running_) {
        for (int i = 0; i < p.intensity && running_; i++) {
            uint32_t frag_id = seq / 2;

            // First fragment: normal
            SimPacket pkt1{};
            pkt1.type = AttackType::TEARDROP;
            pkt1.src_ip = random_ip();
            pkt1.src_port = random_port();
            pkt1.dst_ip = target_ip;
            pkt1.dst_port = random_int(1, 65535);
            pkt1.seq = seq++;
            pkt1.payload_size = p.packet_size;
            pkt1.frag_offset = 0;
            pkt1.frag_id = frag_id;
            pkt1.flags = 0x2000; // MF
            pkt1.bot_id = 0;
            pkt1.timestamp = now_sec();
            send_packet(pkt1);

            // Second fragment: offset inside first -> negative length
            SimPacket pkt2 = pkt1;
            pkt2.seq = seq++;
            pkt2.payload_size = p.packet_size;
            pkt2.frag_offset = p.packet_size / 4;  // Inside first fragment
            pkt2.flags = 0; // Last fragment
            pkt2.timestamp = now_sec();
            send_packet(pkt2);
        }

        if (now_sec() - last_log > 2.0) {
            logs_.add("[Teardrop] Malformed fragments: " + std::to_string(packets_sent_.load()));
            pps_ = packets_sent_ / std::max(0.1, now_sec() - start_time_);
            last_log = now_sec();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void AttackEngine::generate_land_attack(const AttackParams& p) {
    logs_.add(L("[Land Attack] Generating src=dst IP SYN packets", "[Land Attack] 출발지=목적지 IP SYN 패킷 생성 시작", "[Land Attack] Generando paquetes SYN con IP origen=destino"));
    uint32_t seq = 0;
    uint32_t target_ip = 0x7F000001;
    auto last_log = now_sec();

    while (running_) {
        for (int i = 0; i < p.intensity && running_; i++) {
            uint16_t port = random_int(80, 443);

            SimPacket pkt{};
            pkt.type = AttackType::LAND_ATTACK;
            pkt.src_ip = target_ip;     // src = dst!
            pkt.src_port = port;        // src port = dst port!
            pkt.dst_ip = target_ip;
            pkt.dst_port = port;
            pkt.seq = seq++;
            pkt.payload_size = 0;
            pkt.frag_offset = 0;
            pkt.frag_id = 0;
            pkt.flags = FLAG_SYN;
            pkt.bot_id = 0;
            pkt.timestamp = now_sec();
            send_packet(pkt);
        }

        if (now_sec() - last_log > 2.0) {
            logs_.add("[Land Attack] Self-ref SYN: " + std::to_string(packets_sent_.load()) +
                     " (src=dst=" + ip_to_str(target_ip) + ")");
            pps_ = packets_sent_ / std::max(0.1, now_sec() - start_time_);
            last_log = now_sec();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void AttackEngine::generate_layer7_dos(const AttackParams& p) {
    logs_.add(L("[7-Layer DoS] Application layer HTTP Flood started", "[7-Layer DoS] 애플리케이션 레이어 HTTP Flood 시작", "[7-Layer DoS] HTTP Flood de capa de aplicacion iniciado"));
    uint32_t seq = 0;
    uint32_t target_ip = 0x7F000001;
    auto last_log = now_sec();

    while (running_) {
        for (int i = 0; i < p.intensity && running_; i++) {
            SimPacket pkt{};
            pkt.type = AttackType::LAYER7_DOS;
            pkt.src_ip = random_ip();
            pkt.src_port = random_port();
            pkt.dst_ip = target_ip;
            pkt.dst_port = 80;
            pkt.seq = seq++;
            pkt.payload_size = random_int(512, 4096); // HTTP request size
            pkt.frag_offset = 0;
            pkt.frag_id = 0;
            pkt.flags = FLAG_SYN | FLAG_ACK | FLAG_PSH; // Full TCP conn
            pkt.bot_id = 0;
            pkt.timestamp = now_sec();
            send_packet(pkt);
        }

        if (now_sec() - last_log > 2.0) {
            logs_.add("[7-Layer DoS] HTTP requests: " + std::to_string(packets_sent_.load()) +
                     " (GET/POST mix)");
            pps_ = packets_sent_ / std::max(0.1, now_sec() - start_time_);
            last_log = now_sec();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// ============================================================
//  DDoS attack implementations
// ============================================================

void AttackEngine::generate_trinoo(const AttackParams& p) {
    logs_.add(std::string(L("[Trinoo] Master-agent UDP Flood started (bots: ", "[Trinoo] 마스터-에이전트 UDP Flood 시작 (봇 ", "[Trinoo] UDP Flood maestro-agente iniciado (bots: ")) + std::to_string(p.num_bots) + ")");
    uint32_t target_ip = 0x7F000001;

    // Master -> agent command simulation
    logs_.add(L("[Trinoo] Master(TCP:27665) -> Agent(UDP:27444) command propagation", "[Trinoo] 마스터(TCP:27665) → 에이전트(UDP:27444) 명령 전파", "[Trinoo] Maestro(TCP:27665) -> Agente(UDP:27444) propagacion de comando"));
    for (int b = 0; b < p.num_bots; b++) {
        logs_.add("[Trinoo] 에이전트 #" + std::to_string(b) +
                 " activated (" + ip_to_str(random_ip()) + ")");
    }

    std::vector<std::thread> bot_threads;
    for (int b = 0; b < p.num_bots && running_; b++) {
        bot_threads.emplace_back([this, b, p, target_ip]() {
            uint32_t bot_ip = random_ip();
            uint32_t seq = 0;
            while (running_) {
                for (int i = 0; i < p.intensity && running_; i++) {
                    SimPacket pkt{};
                    pkt.type = AttackType::TRINOO;
                    pkt.src_ip = bot_ip;
                    pkt.src_port = 31335; // Trinoo agent port
                    pkt.dst_ip = target_ip;
                    pkt.dst_port = random_int(1, 65535);
                    pkt.seq = seq++;
                    pkt.payload_size = p.packet_size;
                    pkt.flags = 0; // UDP
                    pkt.bot_id = b;
                    pkt.timestamp = now_sec();
                    send_packet(pkt);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });
    }

    auto last_log = now_sec();
    while (running_) {
        if (now_sec() - last_log > 2.0) {
            logs_.add("[Trinoo] Total UDP Flood: " + std::to_string(packets_sent_.load()) +
                     " (bots: " + std::to_string(p.num_bots) + ")");
            pps_ = packets_sent_ / std::max(0.1, now_sec() - start_time_);
            last_log = now_sec();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    for (auto& t : bot_threads)
        if (t.joinable()) t.join();
}

void AttackEngine::generate_tfn(const AttackParams& p) {
    logs_.add(std::string(L("[TFN] Tribe Flood Network started (bots: ", "[TFN] Tribe Flood Network 시작 (봇 ", "[TFN] Tribe Flood Network iniciado (bots: ")) + std::to_string(p.num_bots) + ")");
    logs_.add(L("[TFN] Commands propagated to agents via ICMP Echo Reply", "[TFN] ICMP Echo Reply 채널로 에이전트에 명령 전파", "[TFN] Comandos propagados a agentes via ICMP Echo Reply"));

    uint32_t target_ip = 0x7F000001;

    std::vector<std::thread> bot_threads;
    for (int b = 0; b < p.num_bots && running_; b++) {
        bot_threads.emplace_back([this, b, p, target_ip]() {
            uint32_t bot_ip = random_ip();
            uint32_t seq = 0;
            // Each bot uses different attack type (TFN feature)
            int method = b % 4; // 0:UDP, 1:SYN, 2:ICMP, 3:Smurf

            while (running_) {
                for (int i = 0; i < p.intensity && running_; i++) {
                    SimPacket pkt{};
                    pkt.type = AttackType::TFN;
                    pkt.src_ip = bot_ip;
                    pkt.src_port = random_port();
                    pkt.dst_ip = target_ip;
                    pkt.seq = seq++;
                    pkt.payload_size = p.packet_size;
                    pkt.bot_id = b;
                    pkt.timestamp = now_sec();

                    switch (method) {
                        case 0: // UDP Flood
                            pkt.dst_port = random_int(1, 65535);
                            pkt.flags = 0;
                            break;
                        case 1: // SYN Flood
                            pkt.dst_port = 80;
                            pkt.flags = FLAG_SYN;
                            break;
                        case 2: // ICMP Flood
                            pkt.dst_port = 0;
                            pkt.flags = 0x0800; // ICMP Echo
                            break;
                        case 3: // Smurf
                            pkt.src_ip = target_ip; // Reflection attack
                            pkt.dst_port = 0;
                            pkt.flags = 0x0800;
                            break;
                    }
                    send_packet(pkt);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });
    }

    auto last_log = now_sec();
    while (running_) {
        if (now_sec() - last_log > 2.0) {
            logs_.add("[TFN] Multi-protocol attack: " + std::to_string(packets_sent_.load()) +
                     " (UDP+SYN+ICMP+Smurf)");
            pps_ = packets_sent_ / std::max(0.1, now_sec() - start_time_);
            last_log = now_sec();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    for (auto& t : bot_threads)
        if (t.joinable()) t.join();
}

void AttackEngine::generate_tfn_2k(const AttackParams& p) {
    logs_.add(std::string(L("[TFN 2K] Encrypted DDoS started (bots: ", "[TFN 2K] 암호화 통신 DDoS 시작 (봇 ", "[TFN 2K] DDoS cifrado iniciado (bots: ")) + std::to_string(p.num_bots) + ")");
    logs_.add(L("[TFN 2K] Master<->Agent encrypted (Base64+XOR)", "[TFN 2K] 마스터↔에이전트 통신 암호화 (Base64+XOR)", "[TFN 2K] Maestro<->Agente cifrado (Base64+XOR)"));
    logs_.add(L("[TFN 2K] Random protocol switching enabled", "[TFN 2K] 통신 프로토콜 랜덤 변경 활성화", "[TFN 2K] Cambio aleatorio de protocolo activado"));

    uint32_t target_ip = 0x7F000001;

    std::vector<std::thread> bot_threads;
    for (int b = 0; b < p.num_bots && running_; b++) {
        bot_threads.emplace_back([this, b, p, target_ip]() {
            uint32_t bot_ip = random_ip();
            uint32_t seq = 0;

            while (running_) {
                // TFN 2K: protocol changes each cycle
                int method = random_int(0, 4);

                for (int i = 0; i < p.intensity && running_; i++) {
                    SimPacket pkt{};
                    pkt.type = AttackType::TFN_2K;
                    pkt.src_ip = bot_ip;
                    pkt.src_port = random_port();
                    pkt.dst_ip = target_ip;
                    pkt.seq = seq++;
                    pkt.payload_size = p.packet_size;
                    pkt.bot_id = b;
                    pkt.timestamp = now_sec();

                    switch (method) {
                        case 0: // UDP
                            pkt.dst_port = random_int(1, 65535);
                            pkt.flags = 0;
                            break;
                        case 1: // SYN
                            pkt.dst_port = random_int(80, 8080);
                            pkt.flags = FLAG_SYN;
                            break;
                        case 2: // ICMP
                            pkt.dst_port = 0;
                            pkt.flags = 0x0800;
                            break;
                        case 3: // Smurf
                            pkt.src_ip = target_ip;
                            pkt.dst_port = 0;
                            pkt.flags = 0x0800;
                            break;
                        case 4: // Targa3 (mixed)
                            pkt.dst_port = random_int(1, 65535);
                            pkt.flags = random_int(0, 0xFFFF);
                            break;
                    }

                    // Decoy packet insertion (TFN 2K feature)
                    if (random_int(0, 3) == 0) {
                        SimPacket decoy = pkt;
                        decoy.dst_ip = random_ip(); // Random destination
                        decoy.payload_size = random_int(64, 512);
                        send_packet(decoy);
                    }

                    send_packet(pkt);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });
    }

    auto last_log = now_sec();
    while (running_) {
        if (now_sec() - last_log > 2.0) {
            logs_.add("[TFN 2K] Encrypted DDoS: " + std::to_string(packets_sent_.load()) +
                     " (random proto, w/ decoys)");
            pps_ = packets_sent_ / std::max(0.1, now_sec() - start_time_);
            last_log = now_sec();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    for (auto& t : bot_threads)
        if (t.joinable()) t.join();
}

void AttackEngine::generate_stacheldraht(const AttackParams& p) {
    logs_.add(std::string(L("[Stacheldraht] Barbed-wire DDoS started (bots: ", "[Stacheldraht] 철조망 DDoS 시작 (봇 ", "[Stacheldraht] DDoS alambre-de-puas iniciado (bots: ")) + std::to_string(p.num_bots) + ")");
    logs_.add(L("[Stacheldraht] Handler<->Agent Blowfish encrypted", "[Stacheldraht] 핸들러↔에이전트 Blowfish 암호화 통신", "[Stacheldraht] Handler<->Agente cifrado Blowfish"));
    logs_.add(L("[Stacheldraht] Handler(TCP:16660), Agent(TCP:65000)", "[Stacheldraht] 핸들러(TCP:16660), 에이전트(TCP:65000)", "[Stacheldraht] Handler(TCP:16660), Agente(TCP:65000)"));

    uint32_t target_ip = 0x7F000001;

    // Agent auto-update simulation
    for (int b = 0; b < p.num_bots; b++) {
        logs_.add("[Stacheldraht] 에이전트 #" + std::to_string(b) +
                 " updated (rcp)");
    }

    std::vector<std::thread> bot_threads;
    for (int b = 0; b < p.num_bots && running_; b++) {
        bot_threads.emplace_back([this, b, p, target_ip]() {
            uint32_t bot_ip = random_ip();
            uint32_t seq = 0;
            int method = b % 4; // SYN/UDP/ICMP/Smurf

            while (running_) {
                for (int i = 0; i < p.intensity && running_; i++) {
                    SimPacket pkt{};
                    pkt.type = AttackType::STACHELDRAHT;
                    pkt.src_ip = bot_ip;
                    pkt.src_port = 65000;
                    pkt.dst_ip = target_ip;
                    pkt.seq = seq++;
                    pkt.payload_size = p.packet_size;
                    pkt.bot_id = b;
                    pkt.timestamp = now_sec();

                    switch (method) {
                        case 0: pkt.dst_port = 80; pkt.flags = FLAG_SYN; break;
                        case 1: pkt.dst_port = random_int(1, 65535); pkt.flags = 0; break;
                        case 2: pkt.dst_port = 0; pkt.flags = 0x0800; break;
                        case 3: pkt.src_ip = target_ip; pkt.dst_port = 0; pkt.flags = 0x0800; break;
                    }
                    send_packet(pkt);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });
    }

    auto last_log = now_sec();
    while (running_) {
        if (now_sec() - last_log > 2.0) {
            logs_.add("[Stacheldraht] Encrypted DDoS: " + std::to_string(packets_sent_.load()) +
                     " (Blowfish, " + std::to_string(p.num_bots) + " agents)");
            pps_ = packets_sent_ / std::max(0.1, now_sec() - start_time_);
            last_log = now_sec();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    for (auto& t : bot_threads)
        if (t.joinable()) t.join();
}

void AttackEngine::generate_ddos_malware(const AttackParams& p) {
    logs_.add(std::string(L("[DDoS Malware] Botnet DDoS started (zombies: ", "[DDoS Malware] 봇넷 기반 DDoS 시작 (좀비 ", "[DDoS Malware] DDoS botnet iniciado (zombis: ")) + std::to_string(p.num_bots) + ")");
    logs_.add(L("[DDoS Malware] C&C server -> botnet attack command", "[DDoS Malware] C&C 서버 → 봇넷 공격 명령 전파", "[DDoS Malware] Servidor C&C -> comando de ataque botnet"));
    logs_.add(L("[DDoS Malware] Combined vectors: HTTP+SYN+UDP Flood", "[DDoS Malware] 복합 공격 벡터: HTTP Flood + SYN Flood + UDP Flood", "[DDoS Malware] Vectores combinados: HTTP+SYN+UDP Flood"));

    uint32_t target_ip = 0x7F000001;

    // Infection simulation
    for (int b = 0; b < p.num_bots; b++) {
        std::string device_types[] = {"IoT Camera", "Smart TV", "Router", "NAS", "PC"};
        logs_.add("[DDoS Malware] Zombie #" + std::to_string(b) +
                 " (" + device_types[b % 5] + " @ " + ip_to_str(random_ip()) + ") C&C connected");
    }

    std::vector<std::thread> bot_threads;
    for (int b = 0; b < p.num_bots && running_; b++) {
        bot_threads.emplace_back([this, b, p, target_ip]() {
            uint32_t bot_ip = random_ip();
            uint32_t seq = 0;

            while (running_) {
                // Botnet: multiple attack vectors simultaneously
                for (int i = 0; i < p.intensity && running_; i++) {
                    int method = random_int(0, 2);

                    SimPacket pkt{};
                    pkt.type = AttackType::DDOS_MALWARE;
                    pkt.src_ip = bot_ip;
                    pkt.src_port = random_port();
                    pkt.dst_ip = target_ip;
                    pkt.seq = seq++;
                    pkt.bot_id = b;
                    pkt.timestamp = now_sec();

                    switch (method) {
                        case 0: // HTTP Flood
                            pkt.dst_port = 80;
                            pkt.flags = FLAG_SYN | FLAG_ACK | FLAG_PSH;
                            pkt.payload_size = random_int(512, 4096);
                            break;
                        case 1: // SYN Flood
                            pkt.dst_port = random_int(80, 8080);
                            pkt.flags = FLAG_SYN;
                            pkt.payload_size = 0;
                            break;
                        case 2: // UDP Flood
                            pkt.dst_port = random_int(1, 65535);
                            pkt.flags = 0;
                            pkt.payload_size = p.packet_size;
                            break;
                    }
                    send_packet(pkt);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });
    }

    auto last_log = now_sec();
    while (running_) {
        if (now_sec() - last_log > 2.0) {
            logs_.add("[DDoS Malware] Botnet attack: " + std::to_string(packets_sent_.load()) +
                     " (HTTP+SYN+UDP combined, zombies: " + std::to_string(p.num_bots) + ")");
            pps_ = packets_sent_ / std::max(0.1, now_sec() - start_time_);
            last_log = now_sec();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    for (auto& t : bot_threads)
        if (t.joinable()) t.join();
}
