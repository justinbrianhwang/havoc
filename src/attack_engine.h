#pragma once
#include "common.h"
#include <thread>
#include <atomic>
#include <vector>
#include <memory>

// ============================================================
//  Attack base interface
// ============================================================
struct AttackInfo {
    std::string key;
    std::string name;
    std::string category;     // "DoS" or "DDoS"
    std::string description;
    std::string principle;
    std::string defense;
};

struct AttackParams {
    int intensity  = 50;      // Attack intensity (packets/sec)
    int num_bots   = 10;      // Number of DDoS bots
    int packet_size = 1024;   // Packet size
};

struct AttackMetrics {
    AttackType  type = AttackType::NONE;
    bool        running = false;
    uint64_t    packets_sent = 0;
    double      packets_per_sec = 0;
    double      elapsed_sec = 0;
    int         active_bots = 0;
};

// ============================================================
//  Attack engine
// ============================================================
class AttackEngine {
public:
    AttackEngine(PacketQueue& queue);
    ~AttackEngine();

    // Attack list
    std::vector<AttackInfo> list_attacks(Language lang = Language::ENGLISH) const;
    AttackInfo get_attack_info(AttackType type, Language lang = Language::ENGLISH) const;

    // Attack control
    bool start(AttackType type, const AttackParams& params);
    void stop();

    // Status
    AttackMetrics get_metrics() const;
    LogBuffer& logs() { return logs_; }

private:
    void run_attack();
    void generate_ping_of_death(const AttackParams& p);
    void generate_syn_flooding(const AttackParams& p);
    void generate_boink(const AttackParams& p);
    void generate_bonk(const AttackParams& p);
    void generate_teardrop(const AttackParams& p);
    void generate_land_attack(const AttackParams& p);
    void generate_layer7_dos(const AttackParams& p);
    void generate_trinoo(const AttackParams& p);
    void generate_tfn(const AttackParams& p);
    void generate_tfn_2k(const AttackParams& p);
    void generate_stacheldraht(const AttackParams& p);
    void generate_ddos_malware(const AttackParams& p);

    void send_packet(const SimPacket& pkt);

    PacketQueue&    queue_;
    LogBuffer       logs_;

    std::atomic<bool>   running_{false};
    AttackType          current_type_ = AttackType::NONE;
    AttackParams        current_params_;
    std::vector<std::thread> threads_;
    std::mutex          mtx_;

    std::atomic<uint64_t> packets_sent_{0};
    double              start_time_ = 0;
    std::atomic<double> pps_{0};

    static const std::map<Language, std::vector<AttackInfo>> attack_catalogs_;
};
