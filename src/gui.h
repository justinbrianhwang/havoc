#pragma once
#include "common.h"
#include "attack_engine.h"
#include "victim_engine.h"
#include <vector>
#include <string>
#include <cstring>

// ============================================================
//  Multilingual support (Language enum in common.h)
// ============================================================

struct LangStrings {
    // Start screen
    const char* title;
    const char* subtitle;
    const char* lang_label;
    const char* btn_howto;
    const char* btn_start;
    const char* btn_creator;
    const char* btn_quit;

    // Usage guide
    const char* howto_title;
    const char* howto_text;

    // Creator
    const char* creator_title;
    const char* creator_text;

    // Main UI
    const char* attacker_title;
    const char* victim_title;
    const char* attack_selection;
    const char* dos_header;
    const char* ddos_header;
    const char* parameters;
    const char* intensity;
    const char* bot_count;
    const char* packet_size;
    const char* btn_start_attack;
    const char* btn_stop_attack;
    const char* btn_reset;
    const char* attack_log;
    const char* server_status;
    const char* realtime_graphs;
    const char* attack_detection;
    const char* top_sources;
    const char* server_log;
    const char* no_attacks;
    const char* view_details;
    const char* description;
    const char* principle;
    const char* defense;
    const char* packets_sent;
    const char* elapsed;
    const char* active_bots;
    const char* idle;
    const char* attacking;
    const char* back_to_menu;

    // Status
    const char* status_normal;
    const char* status_load;
    const char* status_delay;
    const char* status_severe;
    const char* status_down;
};

const LangStrings& get_strings(Language lang);

// ============================================================
//  GUI class
// ============================================================
enum class AppScreen {
    START_SCREEN,
    MAIN_SCREEN
};

class SimulatorGUI {
public:
    SimulatorGUI(AttackEngine& attacker, VictimEngine& victim, int api_port);
    ~SimulatorGUI();

    bool run();

private:
    bool init_window();
    void shutdown();
    void render_frame();

    // Screens
    void render_start_screen();
    void render_main_screen();
    void render_howto_popup();
    void render_creator_popup();

    // Main screen panels
    void render_menu_bar();
    void render_attacker_panel();
    void render_victim_panel();
    void render_attack_detail_popup();

    // Style
    void setup_style();
    bool load_fonts();

    AttackEngine&   attacker_;
    VictimEngine&   victim_;
    int             api_port_;

    struct GLFWwindow* window_ = nullptr;

    // App state
    AppScreen screen_ = AppScreen::START_SCREEN;
    Language  language_ = Language::ENGLISH;
    bool show_howto_ = false;
    bool show_creator_ = false;

    // Attack UI state
    int  selected_attack_ = 0;
    int  intensity_ = 50;
    int  num_bots_ = 10;
    int  packet_size_ = 1024;
    bool attack_running_ = false;
    bool show_detail_popup_ = false;

    // Graph history
    static const int HISTORY_SIZE = 120;
    float pps_history_[HISTORY_SIZE] = {};
    float cpu_history_[HISTORY_SIZE] = {};
    float mem_history_[HISTORY_SIZE] = {};
    int   history_offset_ = 0;
};
