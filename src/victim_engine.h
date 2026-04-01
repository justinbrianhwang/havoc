#pragma once
#include "common.h"
#include <atomic>
#include <thread>
#include <map>

// ============================================================
//  Victim server metrics
// ============================================================
struct VictimMetrics {
    std::string status = "Normal";
    double      cpu_usage = 0.0;
    double      memory_usage = 15.0;
    double      bandwidth_mbps = 0.0;
    uint64_t    total_packets = 0;
    double      packets_per_sec = 0.0;
    int         active_connections = 0;
    int         half_open_connections = 0;
    int         max_connections = 1000;
    int         dropped_packets = 0;
    int         fragmented_packets = 0;
    double      avg_response_ms = 5.0;
    std::map<std::string, uint64_t> attack_type_counts;
    std::map<std::string, uint64_t> source_ip_counts;
};

// ============================================================
//  Victim server engine
// ============================================================
class VictimEngine {
public:
    VictimEngine(PacketQueue& queue);
    ~VictimEngine();

    void start();
    void stop();
    void reset();

    VictimMetrics get_metrics();
    LogBuffer& logs() { return logs_; }

private:
    void process_loop();
    void update_metrics();
    void process_packet(const SimPacket& pkt);
    void detect_attack(const SimPacket& pkt);

    PacketQueue&        queue_;
    LogBuffer           logs_;
    std::atomic<bool>   running_{false};
    std::thread         process_thread_;
    std::thread         metrics_thread_;
    std::mutex          mtx_;

    // Internal state
    uint64_t    total_packets_ = 0;
    uint64_t    last_total_ = 0;
    double      pps_ = 0;
    int         active_conns_ = 0;
    int         half_open_ = 0;
    int         dropped_ = 0;
    int         fragmented_ = 0;
    double      bandwidth_ = 0;
    double      cpu_ = 0;
    double      memory_ = 15;
    double      response_ms_ = 5;
    std::string status_ = "Normal";

    std::map<std::string, uint64_t> attack_counts_;
    std::map<std::string, uint64_t> src_ip_counts_;

    // Time-based tracking
    std::deque<double> pkt_timestamps_;
    double last_metrics_update_ = 0;

    // Attack detection state
    std::map<uint32_t, int> syn_tracker_;  // SYN count per IP
    int land_attack_count_ = 0;
    int oversized_pkt_count_ = 0;
    int frag_overlap_count_ = 0;
};
