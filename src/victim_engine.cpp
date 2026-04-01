#include "victim_engine.h"
#include <iostream>
#include <algorithm>

VictimEngine::VictimEngine(PacketQueue& queue) : queue_(queue) {}

VictimEngine::~VictimEngine() {
    stop();
}

void VictimEngine::start() {
    running_ = true;
    last_metrics_update_ = now_sec();
    logs_.add(L("[Server] Victim server simulation started", "[서버] 피해 서버 시뮬레이션 시작", "[Servidor] Simulacion de servidor victima iniciada"));
    logs_.add(L("[Server] Max connections: 1000, ports: 80, 443, 53", "[서버] 최대 연결: 1000, 포트: 80, 443, 53", "[Servidor] Max conexiones: 1000, puertos: 80, 443, 53"));

    process_thread_ = std::thread(&VictimEngine::process_loop, this);
    metrics_thread_ = std::thread([this]() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            update_metrics();
        }
    });
}

void VictimEngine::stop() {
    running_ = false;
    if (process_thread_.joinable()) process_thread_.join();
    if (metrics_thread_.joinable()) metrics_thread_.join();
}

void VictimEngine::reset() {
    std::lock_guard<std::mutex> lk(mtx_);
    total_packets_ = 0;
    last_total_ = 0;
    pps_ = 0;
    active_conns_ = 0;
    half_open_ = 0;
    dropped_ = 0;
    fragmented_ = 0;
    bandwidth_ = 0;
    cpu_ = 0;
    memory_ = 15;
    response_ms_ = 5;
    status_ = L("Normal", "정상", "Normal");
    attack_counts_.clear();
    src_ip_counts_.clear();
    pkt_timestamps_.clear();
    syn_tracker_.clear();
    land_attack_count_ = 0;
    oversized_pkt_count_ = 0;
    frag_overlap_count_ = 0;
    logs_.clear();
    logs_.add(L("[Server] Metrics reset", "[서버] 메트릭 초기화됨", "[Servidor] Metricas reiniciadas"));
}

VictimMetrics VictimEngine::get_metrics() {
    std::lock_guard<std::mutex> lk(mtx_);
    VictimMetrics m;
    m.status = status_;
    m.cpu_usage = cpu_;
    m.memory_usage = memory_;
    m.bandwidth_mbps = bandwidth_;
    m.total_packets = total_packets_;
    m.packets_per_sec = pps_;
    m.active_connections = active_conns_;
    m.half_open_connections = half_open_;
    m.max_connections = 1000;
    m.dropped_packets = dropped_;
    m.fragmented_packets = fragmented_;
    m.avg_response_ms = response_ms_;
    m.attack_type_counts = attack_counts_;

    // Return only the top source IPs
    std::vector<std::pair<std::string, uint64_t>> sorted_ips(src_ip_counts_.begin(), src_ip_counts_.end());
    std::sort(sorted_ips.begin(), sorted_ips.end(),
              [](auto& a, auto& b) { return a.second > b.second; });
    m.source_ip_counts.clear();
    for (size_t i = 0; i < std::min((size_t)10, sorted_ips.size()); i++)
        m.source_ip_counts[sorted_ips[i].first] = sorted_ips[i].second;

    return m;
}

void VictimEngine::process_loop() {
    while (running_) {
        auto packets = queue_.drain(5000);
        if (packets.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

        std::lock_guard<std::mutex> lk(mtx_);
        for (auto& pkt : packets) {
            process_packet(pkt);
        }
    }
}

void VictimEngine::process_packet(const SimPacket& pkt) {
    total_packets_++;
    double t = now_sec();
    pkt_timestamps_.push_back(t);

    // Count per attack type
    std::string type_name = attack_type_name(pkt.type);
    attack_counts_[type_name]++;

    // Source IP count
    std::string src = ip_to_str(pkt.src_ip);
    src_ip_counts_[src]++;

    // Simulate effects by attack type
    switch (pkt.type) {
        case AttackType::PING_OF_DEATH:
            if (pkt.payload_size > 65535) oversized_pkt_count_++;
            fragmented_++;
            // First fragment receive handling (simulation)
            break;

        case AttackType::SYN_FLOODING:
            half_open_++;
            syn_tracker_[pkt.src_ip]++;
            if (half_open_ > 800) dropped_++;
            break;

        case AttackType::BOINK:
        case AttackType::BONK:
        case AttackType::TEARDROP:
            fragmented_++;
            frag_overlap_count_++;
            break;

        case AttackType::LAND_ATTACK:
            land_attack_count_++;
            if (pkt.src_ip == pkt.dst_ip) active_conns_ += 2; // Self-referencing loop
            break;

        case AttackType::LAYER7_DOS:
            active_conns_++;
            break;

        case AttackType::TRINOO:
        case AttackType::TFN:
        case AttackType::TFN_2K:
        case AttackType::STACHELDRAHT:
        case AttackType::DDOS_MALWARE:
            if (pkt.flags & FLAG_SYN) half_open_++;
            else active_conns_++;
            break;

        default:
            break;
    }

    // Attack detection log (major events only)
    detect_attack(pkt);
}

void VictimEngine::detect_attack(const SimPacket& pkt) {
    static int log_throttle = 0;
    log_throttle++;
    if (log_throttle % 500 != 1) return; // Log once per 500 packets

    std::string src = ip_to_str(pkt.src_ip);
    std::string type = attack_type_name(pkt.type);

    switch (pkt.type) {
        case AttackType::PING_OF_DEATH:
            logs_.add(std::string(L("[DETECT] Ping of Death - Oversized ICMP fragment (", "[탐지] Ping of Death - 비정상 크기 ICMP 프래그먼트 (", "[DETECTAR] Ping of Death - Fragmento ICMP sobredimensionado (")) +
                     std::to_string(pkt.payload_size) + "B) from " + src);
            break;
        case AttackType::SYN_FLOODING:
            logs_.add(std::string(L("[DETECT] SYN Flood - Half-open connections: ", "[탐지] SYN Flood - 반개방 연결 ", "[DETECTAR] SYN Flood - Conexiones semi-abiertas: ")) + std::to_string(half_open_) +
                     std::string(L(" (backlog saturation risk)", "개 (백로그 포화 위험)", " (riesgo de saturacion de backlog)")));
            break;
        case AttackType::BOINK:
            logs_.add(std::string(L("[DETECT] Boink - Overlapping UDP fragment (offset=", "[탐지] Boink - 겹치는 UDP 프래그먼트 감지 (offset=", "[DETECTAR] Boink - Fragmento UDP superpuesto (offset=")) +
                     std::to_string(pkt.frag_offset) + ") from " + src);
            break;
        case AttackType::BONK:
            logs_.add(std::string(L("[DETECT] Bonk - Malformed DNS(53) fragment from ", "[탐지] Bonk - DNS(53) 대상 비정상 프래그먼트 from ", "[DETECTAR] Bonk - Fragmento DNS(53) malformado de ")) + src);
            break;
        case AttackType::TEARDROP:
            logs_.add(std::string(L("[DETECT] Teardrop - Negative-length fragment (overlap=", "[탐지] Teardrop - 음수 길이 프래그먼트 감지 (overlap=", "[DETECTAR] Teardrop - Fragmento longitud negativa (overlap=")) +
                     std::to_string(frag_overlap_count_) + ")");
            break;
        case AttackType::LAND_ATTACK:
            logs_.add(std::string(L("[WARN] Land Attack - src=dst (", "[경고] Land Attack - src=dst (", "[AVISO] Land Attack - src=dst (")) + src + ":" +
                     std::to_string(pkt.src_port) + ") self-ref SYN");
            break;
        case AttackType::LAYER7_DOS:
            logs_.add(std::string(L("[DETECT] L7 DoS - Mass HTTP requests (", "[탐지] L7 DoS - 대량 HTTP 요청 (", "[DETECTAR] L7 DoS - Solicitudes HTTP masivas (")) +
                     std::to_string(pps_) + " req/s)");
            break;
        case AttackType::TRINOO:
            logs_.add(std::string(L("[DETECT] Trinoo - Bot #", "[탐지] Trinoo - 봇 #", "[DETECTAR] Trinoo - Bot #")) + std::to_string(pkt.bot_id) +
                     " UDP Flood (port:" + std::to_string(pkt.src_port) + ") from " + src);
            break;
        case AttackType::TFN:
            logs_.add(std::string(L("[DETECT] TFN - Bot #", "[탐지] TFN - 봇 #", "[DETECTAR] TFN - Bot #")) + std::to_string(pkt.bot_id) +
                     " multi-protocol attack from " + src);
            break;
        case AttackType::TFN_2K:
            logs_.add(std::string(L("[DETECT] TFN 2K - Encrypted DDoS, Bot #", "[탐지] TFN 2K - 암호화 통신 DDoS, 봇 #", "[DETECTAR] TFN 2K - DDoS cifrado, Bot #")) +
                     std::to_string(pkt.bot_id) + " from " + src);
            break;
        case AttackType::STACHELDRAHT:
            logs_.add(std::string(L("[DETECT] Stacheldraht - Encrypted agent #", "[탐지] Stacheldraht - 암호화 에이전트 #", "[DETECTAR] Stacheldraht - Agente cifrado #")) +
                     std::to_string(pkt.bot_id) + " from " + src);
            break;
        case AttackType::DDOS_MALWARE:
            logs_.add(std::string(L("[DETECT] Botnet DDoS - Zombie #", "[탐지] 봇넷 DDoS - 좀비 #", "[DETECTAR] Botnet DDoS - Zombi #")) + std::to_string(pkt.bot_id) +
                     " combined attack from " + src);
            break;
        default:
            break;
    }
}

void VictimEngine::update_metrics() {
    std::lock_guard<std::mutex> lk(mtx_);
    double t = now_sec();
    double dt = t - last_metrics_update_;
    if (dt < 0.1) return;
    last_metrics_update_ = t;

    // PPS calculation
    while (!pkt_timestamps_.empty() && t - pkt_timestamps_.front() > 1.0)
        pkt_timestamps_.pop_front();
    pps_ = (double)pkt_timestamps_.size();

    // Bandwidth (MB/s -> Mbps)
    bandwidth_ = pps_ * 1024.0 * 8.0 / 1000000.0;

    // Connection decay (disconnect over time)
    if (active_conns_ > 0) active_conns_ = std::max(0, active_conns_ - (int)(pps_ * 0.01));
    if (half_open_ > 0) half_open_ = std::max(0, half_open_ - (int)(dt * 10));

    // Load calculation
    double load_factor = (double)(active_conns_ + half_open_) / 1000.0;
    load_factor += pps_ / 10000.0;
    load_factor += frag_overlap_count_ * 0.001;
    load_factor += land_attack_count_ * 0.005;
    load_factor = std::min(load_factor, 1.5);

    cpu_ = std::min(100.0, load_factor * 80.0 + (oversized_pkt_count_ > 0 ? 20.0 : 0.0));
    memory_ = std::min(100.0, 15.0 + load_factor * 70.0 + half_open_ * 0.02);
    response_ms_ = 5.0 + load_factor * 5000.0;

    // Determine server status
    if (load_factor > 1.0) {
        status_ = L("Service Denied (DOWN)", "서비스 거부 (다운)", "Servicio Denegado (CAIDO)");
        dropped_ += (int)(pps_ * 0.8);
    } else if (load_factor > 0.8) {
        status_ = L("Severe Delay", "심각한 지연", "Retraso Severo");
        dropped_ += (int)(pps_ * 0.3);
    } else if (load_factor > 0.5) {
        status_ = L("Delay Occurring", "지연 발생", "Retraso Ocurriendo");
    } else if (load_factor > 0.2) {
        status_ = L("Load Increasing", "부하 증가", "Carga Aumentando");
    } else {
        status_ = L("Normal", "정상", "Normal");
    }
}
