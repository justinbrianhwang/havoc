#pragma once
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <functional>
#include <map>
#include <thread>
#include <condition_variable>
#include <random>
#include <algorithm>

// ============================================================
//  Language enumeration + global setting
// ============================================================
enum class Language { KOREAN, ENGLISH, SPANISH };

// Global language (set by GUI, read by engines for log messages)
inline Language& g_language() {
    static Language lang = Language::ENGLISH;
    return lang;
}

// Trilingual log string helper: returns the string for the current language
// Usage: L("English", "한국어", "Espanol")
struct L {
    const char* en; const char* ko; const char* es;
    L(const char* e, const char* k, const char* s) : en(e), ko(k), es(s) {}
    const char* get() const {
        switch (g_language()) {
            case Language::KOREAN:  return ko;
            case Language::SPANISH: return es;
            default:                return en;
        }
    }
    operator std::string() const { return get(); }
};

// ============================================================
//  Attack type enumeration
// ============================================================
enum class AttackType : int {
    NONE = 0,
    // DoS attacks
    PING_OF_DEATH   = 1,
    SYN_FLOODING    = 2,
    BOINK           = 3,
    BONK            = 4,
    TEARDROP        = 5,
    LAND_ATTACK     = 6,
    LAYER7_DOS      = 7,
    // DDoS attacks
    TRINOO          = 8,
    TFN             = 9,
    TFN_2K          = 10,
    STACHELDRAHT    = 11,
    DDOS_MALWARE    = 12,
};

inline const char* attack_type_name(AttackType t) {
    switch (t) {
        case AttackType::PING_OF_DEATH:  return "Ping of Death";
        case AttackType::SYN_FLOODING:   return "SYN Flooding";
        case AttackType::BOINK:          return "Boink";
        case AttackType::BONK:           return "Bonk";
        case AttackType::TEARDROP:       return "Teardrop";
        case AttackType::LAND_ATTACK:    return "Land Attack";
        case AttackType::LAYER7_DOS:     return "7-Layer DoS";
        case AttackType::TRINOO:         return "Trinoo";
        case AttackType::TFN:            return "TFN";
        case AttackType::TFN_2K:         return "TFN 2K";
        case AttackType::STACHELDRAHT:   return "Stacheldraht";
        case AttackType::DDOS_MALWARE:   return "DDoS Malware";
        default:                         return "None";
    }
}

inline const char* attack_type_key(AttackType t) {
    switch (t) {
        case AttackType::PING_OF_DEATH:  return "ping_of_death";
        case AttackType::SYN_FLOODING:   return "syn_flooding";
        case AttackType::BOINK:          return "boink";
        case AttackType::BONK:           return "bonk";
        case AttackType::TEARDROP:       return "teardrop";
        case AttackType::LAND_ATTACK:    return "land_attack";
        case AttackType::LAYER7_DOS:     return "layer7_dos";
        case AttackType::TRINOO:         return "trinoo";
        case AttackType::TFN:            return "tfn";
        case AttackType::TFN_2K:         return "tfn_2k";
        case AttackType::STACHELDRAHT:   return "stacheldraht";
        case AttackType::DDOS_MALWARE:   return "ddos_malware";
        default:                         return "none";
    }
}

inline AttackType attack_type_from_key(const std::string& key) {
    if (key == "ping_of_death")  return AttackType::PING_OF_DEATH;
    if (key == "syn_flooding")   return AttackType::SYN_FLOODING;
    if (key == "boink")          return AttackType::BOINK;
    if (key == "bonk")           return AttackType::BONK;
    if (key == "teardrop")       return AttackType::TEARDROP;
    if (key == "land_attack")    return AttackType::LAND_ATTACK;
    if (key == "layer7_dos")     return AttackType::LAYER7_DOS;
    if (key == "trinoo")         return AttackType::TRINOO;
    if (key == "tfn")            return AttackType::TFN;
    if (key == "tfn_2k")         return AttackType::TFN_2K;
    if (key == "stacheldraht")   return AttackType::STACHELDRAHT;
    if (key == "ddos_malware")   return AttackType::DDOS_MALWARE;
    return AttackType::NONE;
}

inline bool is_ddos(AttackType t) {
    return static_cast<int>(t) >= 8;
}

// ============================================================
//  Simulation packet
// ============================================================
struct SimPacket {
    AttackType  type;
    uint32_t    src_ip;
    uint16_t    src_port;
    uint32_t    dst_ip;
    uint16_t    dst_port;
    uint32_t    seq;
    uint32_t    payload_size;
    uint32_t    frag_offset;
    uint32_t    frag_id;
    uint16_t    flags;        // TCP: SYN=0x02, ACK=0x10, FIN=0x01
    uint16_t    bot_id;
    double      timestamp;
};

// TCP flags
constexpr uint16_t FLAG_FIN = 0x01;
constexpr uint16_t FLAG_SYN = 0x02;
constexpr uint16_t FLAG_RST = 0x04;
constexpr uint16_t FLAG_PSH = 0x08;
constexpr uint16_t FLAG_ACK = 0x10;

// ============================================================
//  Thread-safe packet queue
// ============================================================
class PacketQueue {
public:
    void push(const SimPacket& pkt) {
        std::lock_guard<std::mutex> lk(mtx_);
        queue_.push_back(pkt);
        if (queue_.size() > 100000) queue_.pop_front();
    }

    std::vector<SimPacket> drain(size_t max_count = 10000) {
        std::lock_guard<std::mutex> lk(mtx_);
        std::vector<SimPacket> out;
        size_t n = std::min(max_count, queue_.size());
        out.reserve(n);
        for (size_t i = 0; i < n; i++) {
            out.push_back(queue_.front());
            queue_.pop_front();
        }
        return out;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return queue_.size();
    }

private:
    mutable std::mutex mtx_;
    std::deque<SimPacket> queue_;
};

// ============================================================
//  Log buffer
// ============================================================
class LogBuffer {
public:
    void add(const std::string& msg) {
        std::lock_guard<std::mutex> lk(mtx_);
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf;
        localtime_r(&t, &tm_buf);
        char ts[16];
        std::strftime(ts, sizeof(ts), "%H:%M:%S", &tm_buf);
        entries_.push_back(std::string("[") + ts + "] " + msg);
        if (entries_.size() > 500) entries_.pop_front();
    }

    std::vector<std::string> recent(size_t n = 30) const {
        std::lock_guard<std::mutex> lk(mtx_);
        std::vector<std::string> out;
        size_t start = entries_.size() > n ? entries_.size() - n : 0;
        for (size_t i = start; i < entries_.size(); i++)
            out.push_back(entries_[i]);
        return out;
    }

    void clear() {
        std::lock_guard<std::mutex> lk(mtx_);
        entries_.clear();
    }

private:
    mutable std::mutex mtx_;
    std::deque<std::string> entries_;
};

// ============================================================
//  Simple JSON builder
// ============================================================
class Json {
public:
    static std::string escape(const std::string& s) {
        std::string out;
        out.reserve(s.size() + 10);
        for (char c : s) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:   out += c;
            }
        }
        return out;
    }

    static std::string str(const std::string& s) {
        return "\"" + escape(s) + "\"";
    }

    static std::string num(double n) {
        if (n == (int64_t)n) return std::to_string((int64_t)n);
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2) << n;
        return ss.str();
    }

    static std::string boolean(bool b) {
        return b ? "true" : "false";
    }

    static std::string array(const std::vector<std::string>& items) {
        std::string out = "[";
        for (size_t i = 0; i < items.size(); i++) {
            if (i > 0) out += ",";
            out += items[i];
        }
        out += "]";
        return out;
    }

    static std::string object(const std::vector<std::pair<std::string, std::string>>& kv) {
        std::string out = "{";
        for (size_t i = 0; i < kv.size(); i++) {
            if (i > 0) out += ",";
            out += "\"" + kv[i].first + "\":" + kv[i].second;
        }
        out += "}";
        return out;
    }
};

// ============================================================
//  Utilities
// ============================================================
inline double now_sec() {
    return std::chrono::duration<double>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
}

inline uint32_t random_ip() {
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<uint32_t> dist(0x0A000001, 0xC0A8FFFE);
    return dist(rng);
}

inline uint16_t random_port() {
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<uint16_t> dist(1024, 65535);
    return dist(rng);
}

inline int random_int(int lo, int hi) {
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(lo, hi);
    return dist(rng);
}

inline std::string ip_to_str(uint32_t ip) {
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >>  8) & 0xFF) + "." +
           std::to_string( ip        & 0xFF);
}

// Simple URL decoding
inline std::string url_decode(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '%' && i + 2 < s.size()) {
            int val = 0;
            std::sscanf(s.c_str() + i + 1, "%2x", &val);
            out += (char)val;
            i += 2;
        } else if (s[i] == '+') {
            out += ' ';
        } else {
            out += s[i];
        }
    }
    return out;
}

// Simple JSON parsing (key-value extraction)
inline std::string json_get_string(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos);
    if (pos == std::string::npos) return "";
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return "";
    auto end = json.find('"', pos + 1);
    if (end == std::string::npos) return "";
    return json.substr(pos + 1, end - pos - 1);
}

inline int json_get_int(const std::string& json, const std::string& key, int def = 0) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return def;
    pos = json.find(':', pos);
    if (pos == std::string::npos) return def;
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    try { return std::stoi(json.substr(pos)); }
    catch (...) { return def; }
}
