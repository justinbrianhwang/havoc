#include "common.h"
#include "http_server.h"
#include "attack_engine.h"
#include "victim_engine.h"
#include "gui.h"
#include <iostream>
#include <csignal>

// Request discrete GPU on systems with hybrid graphics (NVIDIA Optimus / AMD Switchable)
extern "C" {
    __attribute__((visibility("default"))) unsigned long NvOptimusEnablement = 1;
    __attribute__((visibility("default"))) int AmdPowerXpressRequestHighPerformance = 1;
}

static std::atomic<bool> g_running{true};

void signal_handler(int) {
    g_running = false;
}

int main(int argc, char* argv[]) {
    int api_port = 7777;
    bool headless = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--headless" || arg == "-H") {
            headless = true;
        } else if (arg == "--port" || arg == "-p") {
            if (i + 1 < argc) api_port = std::atoi(argv[++i]);
        } else {
            int p = std::atoi(arg.c_str());
            if (p > 0) api_port = p;
        }
    }

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Shared packet queue
    PacketQueue packet_queue;

    // Initialize engines
    AttackEngine attacker(packet_queue);
    VictimEngine victim(packet_queue);
    victim.start();

    // HTTP API server (for Python client)
    HttpServer api_server;

    api_server.route("GET", "/api/info", [&](const HttpRequest&) -> HttpResponse {
        return HttpResponse::json(Json::object({
            {"name",    Json::str("HAVOC Server")},
            {"version", Json::str("1.0.0")},
            {"port",    Json::num(api_port)},
            {"attacks", Json::num(12)},
        }));
    });

    api_server.route("GET", "/api/attacks", [&](const HttpRequest&) -> HttpResponse {
        auto attacks = attacker.list_attacks();
        std::vector<std::string> items;
        for (auto& a : attacks) {
            items.push_back(Json::object({
                {"key",         Json::str(a.key)},
                {"name",        Json::str(a.name)},
                {"category",    Json::str(a.category)},
                {"description", Json::str(a.description)},
                {"principle",   Json::str(a.principle)},
                {"defense",     Json::str(a.defense)},
            }));
        }
        return HttpResponse::json(Json::array(items));
    });

    api_server.route("POST", "/api/attack/start", [&](const HttpRequest& req) -> HttpResponse {
        std::string type_key = json_get_string(req.body, "attack_type");
        AttackType type = attack_type_from_key(type_key);
        if (type == AttackType::NONE)
            return HttpResponse::error("unknown attack type: " + type_key);

        AttackParams params;
        params.intensity   = json_get_int(req.body, "intensity", 50);
        params.num_bots    = json_get_int(req.body, "num_bots", 10);
        params.packet_size = json_get_int(req.body, "packet_size", 1024);

        if (!attacker.start(type, params))
            return HttpResponse::error("attack already running");

        return HttpResponse::json(Json::object({
            {"status", Json::str("started")},
            {"attack_type", Json::str(type_key)},
        }));
    });

    api_server.route("POST", "/api/attack/stop", [&](const HttpRequest&) -> HttpResponse {
        attacker.stop();
        return HttpResponse::json(Json::object({{"status", Json::str("stopped")}}));
    });

    api_server.route("GET", "/api/attack/status", [&](const HttpRequest&) -> HttpResponse {
        auto m = attacker.get_metrics();
        auto log_entries = attacker.logs().recent(30);
        std::vector<std::string> log_json;
        for (auto& l : log_entries) log_json.push_back(Json::str(l));

        return HttpResponse::json(Json::object({
            {"attack_type",     Json::str(attack_type_name(m.type))},
            {"attack_key",      Json::str(attack_type_key(m.type))},
            {"running",         Json::boolean(m.running)},
            {"packets_sent",    Json::num((double)m.packets_sent)},
            {"packets_per_sec", Json::num(m.packets_per_sec)},
            {"elapsed_sec",     Json::num(m.elapsed_sec)},
            {"active_bots",     Json::num(m.active_bots)},
            {"logs",            Json::array(log_json)},
        }));
    });

    api_server.route("GET", "/api/victim/metrics", [&](const HttpRequest&) -> HttpResponse {
        auto m = victim.get_metrics();

        std::vector<std::string> atk_items;
        for (auto& [k, v] : m.attack_type_counts)
            atk_items.push_back(Json::object({{"type", Json::str(k)}, {"count", Json::num((double)v)}}));

        std::vector<std::string> ip_items;
        for (auto& [k, v] : m.source_ip_counts)
            ip_items.push_back(Json::object({{"ip", Json::str(k)}, {"count", Json::num((double)v)}}));

        auto log_entries = victim.logs().recent(30);
        std::vector<std::string> log_json;
        for (auto& l : log_entries) log_json.push_back(Json::str(l));

        return HttpResponse::json(Json::object({
            {"status",              Json::str(m.status)},
            {"cpu_usage",           Json::num(m.cpu_usage)},
            {"memory_usage",        Json::num(m.memory_usage)},
            {"bandwidth_mbps",      Json::num(m.bandwidth_mbps)},
            {"total_packets",       Json::num((double)m.total_packets)},
            {"packets_per_sec",     Json::num(m.packets_per_sec)},
            {"active_connections",  Json::num(m.active_connections)},
            {"half_open",           Json::num(m.half_open_connections)},
            {"max_connections",     Json::num(m.max_connections)},
            {"dropped_packets",     Json::num(m.dropped_packets)},
            {"fragmented_packets",  Json::num(m.fragmented_packets)},
            {"avg_response_ms",     Json::num(m.avg_response_ms)},
            {"attack_types",        Json::array(atk_items)},
            {"top_sources",         Json::array(ip_items)},
            {"logs",                Json::array(log_json)},
        }));
    });

    api_server.route("POST", "/api/victim/reset", [&](const HttpRequest&) -> HttpResponse {
        victim.reset();
        return HttpResponse::json(Json::object({{"status", Json::str("reset")}}));
    });

    // Start API server
    if (!api_server.start("0.0.0.0", api_port)) {
        std::cerr << "API server failed to start (port " << api_port << ")\n";
        return 1;
    }

    if (headless) {
        // Headless mode: API server only, no GUI
        std::cout << "============================================================\n";
        std::cout << "  HAVOC Server (Headless Mode)\n";
        std::cout << "============================================================\n";
        std::cout << "[*] API Port: " << api_port << "\n";
        std::cout << "[*] Python: attack_sim.Simulator('localhost', " << api_port << ")\n";
        std::cout << "Ctrl+C to quit\n\n";

        while (g_running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    } else {
        // GUI mode
        SimulatorGUI gui(attacker, victim, api_port);
        gui.run();
    }

    // Cleanup
    attacker.stop();
    victim.stop();
    api_server.stop();

    return 0;
}
