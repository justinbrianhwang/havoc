#include "gui.h"

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include <GLFW/glfw3.h>
#include <cstdio>
#include <cmath>
#include <algorithm>
#include <string>
#include <cstring>

// ============================================================
//  Multilingual strings
// ============================================================
static const LangStrings LANG_KO = {
    // Start screen
    "HAVOC",  // Security Attack Simulator
    "Network Attack Simulation Engine",  // Educational Network Security Simulator
    "\xEC\x96\xB8\xEC\x96\xB4",  // Language
    "\xEC\x82\xAC\xEC\x9A\xA9 \xEB\xB0\xA9\xEB\xB2\x95",  // Usage Guide
    "\xEC\x8B\x9C\xEC\x9E\x91",  // Start
    "\xEC\xA0\x9C\xEC\x9E\x91\xEC\x9E\x90 \xEC\xA0\x95\xEB\xB3\xB4",  // Creator Info
    "\xEC\xA2\x85\xEB\xA3\x8C",  // Quit
    // Usage guide
    "\xEC\x82\xAC\xEC\x9A\xA9 \xEB\xB0\xA9\xEB\xB2\x95",  // Usage Guide
    "1. \xEC\x99\xBC\xEC\xAA\xBD \xED\x8C\xA8\xEB\x84\x90\xEC\x97\x90\xEC\x84\x9C \xEA\xB3\xB5\xEA\xB2\xA9 \xEC\x9C\xA0\xED\x98\x95\xEC\x9D\x84 \xEC\x84\xA0\xED\x83\x9D\xED\x95\x98\xEC\x84\xB8\xEC\x9A\x94\n"  // 1. Select an attack type from the left panel
    "2. \xED\x8C\x8C\xEB\x9D\xBC\xEB\xAF\xB8\xED\x84\xB0\xEB\xA5\xBC \xEC\xA1\xB0\xEC\xA0\x88\xED\x95\x98\xEC\x84\xB8\xEC\x9A\x94 (\xEA\xB0\x95\xEB\x8F\x84, \xEB\xB4\x87 \xEC\x88\x98, \xED\x8C\xA8\xED\x82\xB7 \xED\x81\xAC\xEA\xB8\xB0)\n"  // 2. Adjust parameters (intensity, bot count, packet size)
    "3. '\xEA\xB3\xB5\xEA\xB2\xA9 \xEC\x8B\x9C\xEC\x9E\x91' \xEB\xB2\x84\xED\x8A\xBC\xEC\x9D\x84 \xED\x81\xB4\xEB\xA6\xAD\xED\x95\x98\xEC\x97\xAC \xEC\x8B\x9C\xEB\xAE\xAC\xEB\xA0\x88\xEC\x9D\xB4\xEC\x85\x98\xEC\x9D\x84 \xEC\x8B\x9C\xEC\x9E\x91\xED\x95\x98\xEC\x84\xB8\xEC\x9A\x94\n"  // 3. Click 'Start Attack' to begin simulation
    "4. \xEC\x98\xA4\xEB\xA5\xB8\xEC\xAA\xBD \xED\x8C\xA8\xEB\x84\x90\xEC\x97\x90\xEC\x84\x9C \xED\x94\xBC\xED\x95\xB4 \xEC\x84\x9C\xEB\xB2\x84 \xEC\x83\x81\xED\x83\x9C\xEB\xA5\xBC \xEB\xAA\xA8\xEB\x8B\x88\xED\x84\xB0\xEB\xA7\x81\xED\x95\x98\xEC\x84\xB8\xEC\x9A\x94\n"  // 4. Monitor victim server status on the right panel
    "5. '\xEA\xB3\xB5\xEA\xB2\xA9 \xEC\xA4\x91\xEC\xA7\x80' \xEB\xB2\x84\xED\x8A\xBC\xEC\x9C\xBC\xEB\xA1\x9C \xEA\xB3\xB5\xEA\xB2\xA9\xEC\x9D\x84 \xEC\xA4\x91\xEC\xA7\x80\xED\x95\x98\xEC\x84\xB8\xEC\x9A\x94\n"  // 5. Click 'Stop Attack' to stop
    "6. '\xEC\xB4\x88\xEA\xB8\xB0\xED\x99\x94' \xEB\xB2\x84\xED\x8A\xBC\xEC\x9C\xBC\xEB\xA1\x9C \xEB\xAA\xA8\xEB\x93\xA0 \xEC\x83\x81\xED\x83\x9C\xEB\xA5\xBC \xEC\xB4\x88\xEA\xB8\xB0\xED\x99\x94\xED\x95\x98\xEC\x84\xB8\xEC\x9A\x94\n\n"  // 6. Click 'Reset' to clear all state
    "Python API:\n"
    "  import attack_sim\n"
    "  sim = attack_sim.Simulator('localhost', 7777)\n"
    "  sim.start_attack('syn_flooding', intensity=100)\n"
    "  sim.get_victim_metrics()\n"
    "  sim.stop_attack()\n\n"
    "Headless \xEB\xAA\xA8\xEB\x93\x9C:\n"  // Headless mode
    "  ./start.sh 7777 --headless",
    // Creator
    "\xEC\xA0\x9C\xEC\x9E\x91\xEC\x9E\x90 \xEC\xA0\x95\xEB\xB3\xB4",  // Creator Info
    "HAVOC v1.0.0\n\n"
    "\xEA\xB0\x9C\xEB\xB0\x9C\xEC\x9E\x90: Sunjun Hwang\n"
    "AI & Quantum Computing Researcher\n"
    "Building Robust AI Systems that Work in the Real World\n"
    "https://www.sjhwang.com/\n\n"
    "C++17, OpenGL, Dear ImGui \xEA\xB8\xB0\xEB\xB0\x98 \xEA\xB0\x9C\xEB\xB0\x9C\n\n"
    "\xEC\x9D\xB4 \xEC\x8B\x9C\xEB\xAE\xAC\xEB\xA0\x88\xEC\x9D\xB4\xED\x84\xB0\xEB\x8A\x94 \xEA\xB5\x90\xEC\x9C\xA1 \xEB\xB0\x8F \xEC\x97\xB0\xEA\xB5\xAC \xEB\xAA\xA9\xEC\xA0\x81\xEC\x9C\xBC\xEB\xA1\x9C\xEB\xA7\x8C \xEC\x82\xAC\xEC\x9A\xA9\xED\x95\x98\xEC\x84\xB8\xEC\x9A\x94.\n"
    "\xEB\xAA\xA8\xEB\x93\xA0 \xEA\xB3\xB5\xEA\xB2\xA9\xEC\x9D\x80 \xEB\x82\xB4\xEB\xB6\x80\xEC\x97\x90\xEC\x84\x9C \xEC\x8B\x9C\xEB\xAE\xAC\xEB\xA0\x88\xEC\x9D\xB4\xEC\x85\x98\xEB\x90\x98\xEB\xA9\xB0, \xEC\x8B\xA4\xEC\xA0\x9C \xEB\x84\xA4\xED\x8A\xB8\xEC\x9B\x8C\xED\x81\xAC \xED\x8A\xB8\xEB\x9E\x98\xED\x94\xBD\xEC\x9D\x80 \xEB\xB0\x9C\xEC\x83\x9D\xED\x95\x98\xEC\xA7\x80 \xEC\x95\x8A\xEC\x8A\xB5\xEB\x8B\x88\xEB\x8B\xA4.\n\n"
    "\xEC\xA7\x80\xEC\x9B\x90 \xEA\xB3\xB5\xEA\xB2\xA9:\n"
    "  DoS:  Ping of Death, SYN Flooding, Boink, Bonk,\n"
    "        Teardrop, Land Attack, 7-Layer DoS\n"
    "  DDoS: Trinoo, TFN, TFN 2K, Stacheldraht,\n"
    "        DDoS Using Malicious Code\n",
    // Main UI
    "\xEA\xB3\xB5\xEA\xB2\xA9\xEC\x9E\x90 \xEC\xA0\x9C\xEC\x96\xB4",  // Attacker Control
    "\xED\x94\xBC\xED\x95\xB4\xEC\x9E\x90 \xEB\xAA\xA8\xEB\x8B\x88\xED\x84\xB0\xEB\xA7\x81",  // Victim Monitoring
    "\xEA\xB3\xB5\xEA\xB2\xA9 \xEC\x84\xA0\xED\x83\x9D",  // Attack Selection
    "--- DoS \xEA\xB3\xB5\xEA\xB2\xA9 ---",  // --- DoS Attacks ---
    "--- DDoS \xEA\xB3\xB5\xEA\xB2\xA9 ---",  // --- DDoS Attacks ---
    "\xED\x8C\x8C\xEB\x9D\xBC\xEB\xAF\xB8\xED\x84\xB0",  // Parameters
    "\xEA\xB0\x95\xEB\x8F\x84",  // Intensity
    "\xEB\xB4\x87 \xEC\x88\x98",  // Bot Count
    "\xED\x8C\xA8\xED\x82\xB7 \xED\x81\xAC\xEA\xB8\xB0",  // Packet Size
    "\xEA\xB3\xB5\xEA\xB2\xA9 \xEC\x8B\x9C\xEC\x9E\x91",  // Start Attack
    "\xEA\xB3\xB5\xEA\xB2\xA9 \xEC\xA4\x91\xEC\xA7\x80",  // Stop Attack
    "\xEC\x84\x9C\xEB\xB2\x84 \xEC\xB4\x88\xEA\xB8\xB0\xED\x99\x94",  // Reset Server
    "\xEA\xB3\xB5\xEA\xB2\xA9 \xEB\xA1\x9C\xEA\xB7\xB8",  // Attack Log
    "\xEC\x84\x9C\xEB\xB2\x84 \xEC\x83\x81\xED\x83\x9C",  // Server Status
    "\xEC\x8B\xA4\xEC\x8B\x9C\xEA\xB0\x84 \xEA\xB7\xB8\xEB\x9E\x98\xED\x94\x84",  // Real-time Graphs
    "\xEA\xB3\xB5\xEA\xB2\xA9 \xED\x83\x90\xEC\xA7\x80",  // Attack Detection
    "\xEC\x83\x81\xEC\x9C\x84 \xEA\xB3\xB5\xEA\xB2\xA9 IP",  // Top Source IPs
    "\xEC\x84\x9C\xEB\xB2\x84 \xEB\xA1\x9C\xEA\xB7\xB8",  // Server Log
    "(\xED\x83\x90\xEC\xA7\x80\xEB\x90\x9C \xEA\xB3\xB5\xEA\xB2\xA9 \xEC\x97\x86\xEC\x9D\x8C)",  // (No attacks detected)
    "\xEC\x83\x81\xEC\x84\xB8 \xEB\xB3\xB4\xEA\xB8\xB0...",  // View Details...
    "\xEC\x84\xA4\xEB\xAA\x85",  // Description
    "\xEA\xB3\xB5\xEA\xB2\xA9 \xEC\x9B\x90\xEB\xA6\xAC",  // Attack Principle
    "\xEB\xB0\xA9\xEC\x96\xB4 \xEB\xB0\xA9\xEB\xB2\x95",  // Defense Methods
    "\xEC\xA0\x84\xEC\x86\xA1 \xED\x8C\xA8\xED\x82\xB7",  // Packets Sent
    "\xEA\xB2\xBD\xEA\xB3\xBC \xEC\x8B\x9C\xEA\xB0\x84",  // Elapsed Time
    "\xED\x99\x9C\xEC\x84\xB1 \xEB\xB4\x87",  // Active Bots
    "\xEB\x8C\x80\xEA\xB8\xB0 \xEC\xA4\x91",  // Idle
    "\xEA\xB3\xB5\xEA\xB2\xA9 \xEC\xA4\x91",  // Attacking
    "\xEB\xA9\x94\xEB\x89\xB4\xEB\xA1\x9C \xEB\x8F\x8C\xEC\x95\x84\xEA\xB0\x80\xEA\xB8\xB0",  // Back to Menu
    "\xEC\xA0\x95\xEC\x83\x81",  // Normal
    "\xEB\xB6\x80\xED\x95\x98 \xEC\xA6\x9D\xEA\xB0\x80",  // Load Increasing
    "\xEC\xA7\x80\xEC\x97\xB0 \xEB\xB0\x9C\xEC\x83\x9D",  // Delay Occurring
    "\xEC\x8B\xAC\xEA\xB0\x81\xED\x95\x9C \xEC\xA7\x80\xEC\x97\xB0",  // Severe Delay
    "\xEC\x84\x9C\xEB\xB9\x84\xEC\x8A\xA4 \xEA\xB1\xB0\xEB\xB6\x80 (\xEB\x8B\xA4\xEC\x9A\xB4)",  // Service Denied (DOWN)
};

static const LangStrings LANG_EN = {
    "HAVOC",
    "Network Attack Simulation Engine",
    "Language",
    "Usage Guide",
    "START",
    "Creator Info",
    "QUIT",
    "Usage Guide",
    "1. Select an attack type from the left panel\n"
    "2. Adjust parameters (intensity, bot count, packet size)\n"
    "3. Click START ATTACK to begin the simulation\n"
    "4. Monitor the victim server metrics on the right panel\n"
    "5. Click STOP ATTACK to stop\n"
    "6. Click RESET to clear all metrics\n\n"
    "Python API:\n"
    "  import attack_sim\n"
    "  sim = attack_sim.Simulator('localhost', 7777)\n"
    "  sim.start_attack('syn_flooding', intensity=100)\n"
    "  sim.get_victim_metrics()\n"
    "  sim.stop_attack()\n\n"
    "Headless mode:\n"
    "  ./start.sh 7777 --headless",
    "Creator Info",
    "HAVOC v1.0.0\n\n"
    "Developed by Sunjun Hwang\n"
    "AI & Quantum Computing Researcher\n"
    "Building Robust AI Systems that Work in the Real World\n"
    "https://www.sjhwang.com/\n\n"
    "Built with C++17, OpenGL, Dear ImGui\n\n"
    "This simulator is designed for educational and research purposes only.\n"
    "All attacks are simulated internally - no real network traffic is generated.\n\n"
    "Supported Attacks:\n"
    "  DoS:  Ping of Death, SYN Flooding, Boink, Bonk,\n"
    "        Teardrop, Land Attack, 7-Layer DoS\n"
    "  DDoS: Trinoo, TFN, TFN 2K, Stacheldraht,\n"
    "        DDoS Using Malicious Code\n",
    "ATTACKER CONTROL", "VICTIM MONITORING",
    "Attack Selection",
    "--- DoS Attacks ---", "--- DDoS Attacks ---",
    "Parameters", "Intensity", "Bot Count", "Packet Size",
    "START ATTACK", "STOP ATTACK", "RESET SERVER",
    "Attack Log", "Server Status", "Real-time Graphs",
    "Attack Detection", "Top Source IPs", "Server Log",
    "(No attacks detected)", "View Details...",
    "Description", "Attack Principle", "Defense Methods",
    "Packets Sent", "Elapsed", "Active Bots",
    "IDLE", "ATTACKING",
    "Back to Menu",
    "Normal", "Load Increasing", "Delay Occurring", "Severe Delay", "Service Denied (DOWN)",
};

static const LangStrings LANG_ES = {
    "HAVOC",
    "Motor de Simulacion de Ataques de Red",
    "Idioma",
    "Guia de Uso",
    "INICIAR",
    "Info del Creador",
    "SALIR",
    "Guia de Uso",
    "1. Seleccione un tipo de ataque del panel izquierdo\n"
    "2. Ajuste los parametros (intensidad, bots, tamano de paquete)\n"
    "3. Haga clic en INICIAR ATAQUE para comenzar la simulacion\n"
    "4. Monitoree las metricas del servidor victima en el panel derecho\n"
    "5. Haga clic en DETENER ATAQUE para detener\n"
    "6. Haga clic en REINICIAR para borrar todas las metricas\n\n"
    "API de Python:\n"
    "  import attack_sim\n"
    "  sim = attack_sim.Simulator('localhost', 7777)\n"
    "  sim.start_attack('syn_flooding', intensity=100)\n"
    "  sim.get_victim_metrics()\n"
    "  sim.stop_attack()\n\n"
    "Modo sin interfaz:\n"
    "  ./start.sh 7777 --headless",
    "Info del Creador",
    "HAVOC v1.0.0\n\n"
    "Desarrollado por Sunjun Hwang\n"
    "AI & Quantum Computing Researcher\n"
    "Building Robust AI Systems that Work in the Real World\n"
    "https://www.sjhwang.com/\n\n"
    "Construido con C++17, OpenGL, Dear ImGui\n\n"
    "Este simulador esta disenado solo para fines educativos e investigacion.\n"
    "Todos los ataques se simulan internamente - no se genera trafico de red real.\n\n"
    "Ataques Soportados:\n"
    "  DoS:  Ping of Death, SYN Flooding, Boink, Bonk,\n"
    "        Teardrop, Land Attack, 7-Layer DoS\n"
    "  DDoS: Trinoo, TFN, TFN 2K, Stacheldraht,\n"
    "        DDoS Using Malicious Code\n",
    "CONTROL DE ATACANTE", "MONITOREO DE VICTIMA",
    "Seleccion de Ataque",
    "--- Ataques DoS ---", "--- Ataques DDoS ---",
    "Parametros", "Intensidad", "Cantidad de Bots", "Tamano de Paquete",
    "INICIAR ATAQUE", "DETENER ATAQUE", "REINICIAR SERVIDOR",
    "Registro de Ataque", "Estado del Servidor", "Graficos en Tiempo Real",
    "Deteccion de Ataques", "IPs de Origen Principales", "Registro del Servidor",
    "(No se detectaron ataques)", "Ver Detalles...",
    "Descripcion", "Principio de Ataque", "Metodos de Defensa",
    "Paquetes Enviados", "Tiempo", "Bots Activos",
    "INACTIVO", "ATACANDO",
    "Volver al Menu",
    "Normal", "Carga Aumentando", "Retraso Ocurriendo", "Retraso Severo", "Servicio Denegado (CAIDO)",
};

const LangStrings& get_strings(Language lang) {
    switch (lang) {
        case Language::ENGLISH: return LANG_EN;
        case Language::SPANISH: return LANG_ES;
        default:                return LANG_KO;
    }
}

// ============================================================
//  Construction/Destruction
// ============================================================
SimulatorGUI::SimulatorGUI(AttackEngine& attacker, VictimEngine& victim, int api_port)
    : attacker_(attacker), victim_(victim), api_port_(api_port)
{
    memset(pps_history_, 0, sizeof(pps_history_));
    memset(cpu_history_, 0, sizeof(cpu_history_));
    memset(mem_history_, 0, sizeof(mem_history_));
}

SimulatorGUI::~SimulatorGUI() {
    shutdown();
}

// ============================================================
//  Initialization
// ============================================================
static void glfw_error_callback(int error, const char* desc) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, desc);
}

bool SimulatorGUI::init_window() {
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) return false;

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);

    window_ = glfwCreateWindow(1400, 850,
        "HAVOC - Network Attack Simulation Engine", nullptr, nullptr);
    if (!window_) {
        glfwTerminate();
        return false;
    }

    glfwMakeContextCurrent(window_);
    glfwSwapInterval(1); // VSync

    // Log GPU info
    const char* renderer = (const char*)glGetString(GL_RENDERER);
    const char* vendor   = (const char*)glGetString(GL_VENDOR);
    const char* version  = (const char*)glGetString(GL_VERSION);
    fprintf(stderr, "[GPU] Renderer: %s\n", renderer ? renderer : "unknown");
    fprintf(stderr, "[GPU] Vendor:   %s\n", vendor   ? vendor   : "unknown");
    fprintf(stderr, "[GPU] OpenGL:   %s\n", version  ? version  : "unknown");

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui_ImplGlfw_InitForOpenGL(window_, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    load_fonts();
    setup_style();

    return true;
}

bool SimulatorGUI::load_fonts() {
    ImGuiIO& io = ImGui::GetIO();

    const char* font_paths[] = {
        "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
        "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/nanum/NanumGothicBold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        nullptr
    };

    for (int i = 0; font_paths[i]; i++) {
        FILE* f = fopen(font_paths[i], "rb");
        if (f) {
            fclose(f);
            // Default font (16px)
            io.Fonts->AddFontFromFileTTF(font_paths[i], 16.0f, nullptr,
                                         io.Fonts->GetGlyphRangesKorean());
            // Large font (32px) - for titles
            io.Fonts->AddFontFromFileTTF(font_paths[i], 32.0f, nullptr,
                                         io.Fonts->GetGlyphRangesKorean());
            // Medium font (20px)
            io.Fonts->AddFontFromFileTTF(font_paths[i], 20.0f, nullptr,
                                         io.Fonts->GetGlyphRangesKorean());
            fprintf(stderr, "[GUI] Font loaded: %s\n", font_paths[i]);
            return true;
        }
    }

    fprintf(stderr, "[GUI] No Korean font found, using default\n");
    // Load default font in multiple sizes
    io.Fonts->AddFontDefault();
    ImFontConfig cfg;
    cfg.SizePixels = 32.0f;
    io.Fonts->AddFontDefault(&cfg);
    cfg.SizePixels = 20.0f;
    io.Fonts->AddFontDefault(&cfg);
    return false;
}

void SimulatorGUI::setup_style() {
    ImGuiStyle& style = ImGui::GetStyle();
    ImGui::StyleColorsDark();

    ImVec4* colors = style.Colors;
    colors[ImGuiCol_WindowBg]           = ImVec4(0.06f, 0.06f, 0.10f, 1.00f);
    colors[ImGuiCol_ChildBg]            = ImVec4(0.07f, 0.07f, 0.12f, 1.00f);
    colors[ImGuiCol_PopupBg]            = ImVec4(0.08f, 0.08f, 0.14f, 0.97f);
    colors[ImGuiCol_Border]             = ImVec4(0.15f, 0.20f, 0.30f, 1.00f);
    colors[ImGuiCol_FrameBg]            = ImVec4(0.10f, 0.12f, 0.18f, 1.00f);
    colors[ImGuiCol_FrameBgHovered]     = ImVec4(0.15f, 0.18f, 0.28f, 1.00f);
    colors[ImGuiCol_FrameBgActive]      = ImVec4(0.20f, 0.25f, 0.35f, 1.00f);
    colors[ImGuiCol_TitleBg]            = ImVec4(0.05f, 0.05f, 0.08f, 1.00f);
    colors[ImGuiCol_TitleBgActive]      = ImVec4(0.08f, 0.10f, 0.18f, 1.00f);
    colors[ImGuiCol_Header]             = ImVec4(0.15f, 0.20f, 0.35f, 1.00f);
    colors[ImGuiCol_HeaderHovered]      = ImVec4(0.20f, 0.30f, 0.50f, 1.00f);
    colors[ImGuiCol_HeaderActive]       = ImVec4(0.25f, 0.35f, 0.55f, 1.00f);
    colors[ImGuiCol_Button]             = ImVec4(0.15f, 0.20f, 0.35f, 1.00f);
    colors[ImGuiCol_ButtonHovered]      = ImVec4(0.25f, 0.35f, 0.55f, 1.00f);
    colors[ImGuiCol_ButtonActive]       = ImVec4(0.30f, 0.40f, 0.60f, 1.00f);
    colors[ImGuiCol_PlotLines]          = ImVec4(0.30f, 0.75f, 0.95f, 1.00f);
    colors[ImGuiCol_PlotHistogram]      = ImVec4(0.90f, 0.40f, 0.10f, 1.00f);
    colors[ImGuiCol_TableHeaderBg]      = ImVec4(0.10f, 0.12f, 0.20f, 1.00f);
    colors[ImGuiCol_TableBorderStrong]  = ImVec4(0.15f, 0.20f, 0.30f, 1.00f);
    colors[ImGuiCol_TableBorderLight]   = ImVec4(0.12f, 0.15f, 0.22f, 1.00f);

    style.WindowRounding    = 6.0f;
    style.ChildRounding     = 4.0f;
    style.FrameRounding     = 4.0f;
    style.PopupRounding     = 4.0f;
    style.GrabRounding      = 3.0f;
    style.TabRounding       = 4.0f;
    style.WindowPadding     = ImVec2(12, 12);
    style.FramePadding      = ImVec2(8, 4);
    style.ItemSpacing       = ImVec2(8, 6);
}

void SimulatorGUI::shutdown() {
    if (window_) {
        ImGui_ImplOpenGL3_Shutdown();
        ImGui_ImplGlfw_Shutdown();
        ImGui::DestroyContext();
        glfwDestroyWindow(window_);
        glfwTerminate();
        window_ = nullptr;
    }
}

// ============================================================
//  Main loop
// ============================================================
bool SimulatorGUI::run() {
    if (!init_window()) {
        fprintf(stderr, "[GUI] Window initialization failed!\n");
        return false;
    }

    while (!glfwWindowShouldClose(window_)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        render_frame();

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window_, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.04f, 0.04f, 0.07f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window_);
    }

    return true;
}

void SimulatorGUI::render_frame() {
    switch (screen_) {
        case AppScreen::START_SCREEN:
            render_start_screen();
            break;
        case AppScreen::MAIN_SCREEN:
            render_main_screen();
            break;
    }

    if (show_howto_)   render_howto_popup();
    if (show_creator_) render_creator_popup();
    if (show_detail_popup_) render_attack_detail_popup();
}

// ============================================================
//  Start screen
// ============================================================
void SimulatorGUI::render_start_screen() {
    auto& S = get_strings(language_);

    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("##StartScreen", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize);

    ImGuiIO& io = ImGui::GetIO();
    float win_w = ImGui::GetContentRegionAvail().x;
    float win_h = ImGui::GetContentRegionAvail().y;

    // Cursor positioning for center alignment
    float content_w = 500;
    float start_x = (win_w - content_w) / 2.0f;
    float start_y = win_h * 0.12f;

    // ===== 1. Title =====
    ImGui::SetCursorPos(ImVec2(0, start_y));

    // Title in large font
    if (io.Fonts->Fonts.Size > 1)
        ImGui::PushFont(io.Fonts->Fonts[1]); // 32px font

    ImVec2 title_size = ImGui::CalcTextSize(S.title);
    ImGui::SetCursorPosX((win_w - title_size.x) / 2.0f);
    ImGui::TextColored(ImVec4(0.3f, 0.75f, 0.95f, 1.0f), "%s", S.title);

    if (io.Fonts->Fonts.Size > 1)
        ImGui::PopFont();

    // Subtitle
    ImGui::Spacing();
    if (io.Fonts->Fonts.Size > 2)
        ImGui::PushFont(io.Fonts->Fonts[2]); // 20px font

    ImVec2 sub_size = ImGui::CalcTextSize(S.subtitle);
    ImGui::SetCursorPosX((win_w - sub_size.x) / 2.0f);
    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, 1.0f), "%s", S.subtitle);

    if (io.Fonts->Fonts.Size > 2)
        ImGui::PopFont();

    // Separator line
    ImGui::Spacing();
    ImGui::Spacing();
    ImGui::SetCursorPosX(start_x);
    ImGui::PushStyleColor(ImGuiCol_Separator, ImVec4(0.2f, 0.3f, 0.5f, 0.5f));
    ImVec2 sep_start = ImGui::GetCursorScreenPos();
    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddLine(
        ImVec2(sep_start.x, sep_start.y),
        ImVec2(sep_start.x + content_w, sep_start.y),
        ImGui::ColorConvertFloat4ToU32(ImVec4(0.2f, 0.4f, 0.7f, 0.5f)), 1.0f);
    ImGui::PopStyleColor();
    ImGui::Spacing();
    ImGui::Spacing();

    // ===== 2. Language selection =====
    ImGui::SetCursorPosX(start_x);
    ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.7f, 1.0f), "%s:", S.lang_label);
    ImGui::SameLine();

    auto lang_btn = [&](const char* label, Language lang, float r, float g, float b) {
        bool is_selected = (language_ == lang);
        if (is_selected) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(r * 0.6f, g * 0.6f, b * 0.6f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(r * 0.7f, g * 0.7f, b * 0.7f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(r * 0.8f, g * 0.8f, b * 0.8f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        }
        if (ImGui::Button(label, ImVec2(120, 30))) {
            language_ = lang;
            g_language() = lang;
        }
        if (is_selected) {
            ImGui::PopStyleColor(4);
        }
    };

    lang_btn("Korean",  Language::KOREAN,  0.2f, 0.5f, 0.9f);
    ImGui::SameLine();
    lang_btn("English", Language::ENGLISH, 0.2f, 0.7f, 0.4f);
    ImGui::SameLine();
    lang_btn("Spanish", Language::SPANISH, 0.9f, 0.5f, 0.2f);

    ImGui::Spacing();
    ImGui::Spacing();
    ImGui::Spacing();

    // ===== 3. Usage guide button =====
    float btn_w = 350;
    float btn_h = 45;
    float btn_x = (win_w - btn_w) / 2.0f;

    ImGui::SetCursorPosX(btn_x);
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.12f, 0.18f, 0.30f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.18f, 0.28f, 0.45f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.22f, 0.35f, 0.55f, 1.0f));
    if (ImGui::Button(S.btn_howto, ImVec2(btn_w, btn_h))) {
        show_howto_ = true;
    }
    ImGui::PopStyleColor(3);

    ImGui::Spacing();
    ImGui::Spacing();

    // ===== 4. START button =====
    ImGui::SetCursorPosX(btn_x);
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.15f, 0.55f, 0.25f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.2f, 0.7f, 0.3f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.25f, 0.8f, 0.35f, 1.0f));

    if (io.Fonts->Fonts.Size > 2)
        ImGui::PushFont(io.Fonts->Fonts[2]);
    if (ImGui::Button(S.btn_start, ImVec2(btn_w, 60))) {
        screen_ = AppScreen::MAIN_SCREEN;
    }
    if (io.Fonts->Fonts.Size > 2)
        ImGui::PopFont();
    ImGui::PopStyleColor(3);

    ImGui::Spacing();
    ImGui::Spacing();

    // ===== 5. Creator info button =====
    ImGui::SetCursorPosX(btn_x);
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.12f, 0.18f, 0.30f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.18f, 0.28f, 0.45f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.22f, 0.35f, 0.55f, 1.0f));
    if (ImGui::Button(S.btn_creator, ImVec2(btn_w, btn_h))) {
        show_creator_ = true;
    }
    ImGui::PopStyleColor(3);

    ImGui::Spacing();
    ImGui::Spacing();
    ImGui::Spacing();

    // QUIT button
    ImGui::SetCursorPosX(btn_x);
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.5f, 0.12f, 0.12f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.7f, 0.15f, 0.15f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.85f, 0.2f, 0.2f, 1.0f));
    if (ImGui::Button(S.btn_quit, ImVec2(btn_w, 35))) {
        glfwSetWindowShouldClose(window_, GLFW_TRUE);
    }
    ImGui::PopStyleColor(3);

    // Author credit
    ImGui::SetCursorPos(ImVec2(0, win_h - 45));
    {
        const char* author_line = "Developed by Sunjun Hwang | sjhwang.com";
        ImVec2 author_size = ImGui::CalcTextSize(author_line);
        ImGui::SetCursorPosX((win_w - author_size.x) / 2.0f);
        ImGui::TextColored(ImVec4(0.45f, 0.55f, 0.70f, 1.0f), "%s", author_line);
    }

    // Footer info
    {
        char footer_buf[128];
        snprintf(footer_buf, sizeof(footer_buf),
                 "Python API: localhost:%d | Educational Use Only", api_port_);
        ImVec2 info_size = ImGui::CalcTextSize(footer_buf);
        ImGui::SetCursorPosX((win_w - info_size.x) / 2.0f);
        ImGui::TextColored(ImVec4(0.35f, 0.35f, 0.45f, 1.0f), "%s", footer_buf);
    }

    ImGui::End();
}

// ============================================================
//  Usage guide popup
// ============================================================
void SimulatorGUI::render_howto_popup() {
    auto& S = get_strings(language_);
    ImGui::SetNextWindowSize(ImVec2(600, 450), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(),
                           ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));
    ImGui::Begin(S.howto_title, &show_howto_);
    ImGui::PushTextWrapPos(ImGui::GetContentRegionAvail().x);
    ImGui::TextWrapped("%s", S.howto_text);
    ImGui::PopTextWrapPos();
    ImGui::End();
}

// ============================================================
//  Creator popup
// ============================================================
void SimulatorGUI::render_creator_popup() {
    auto& S = get_strings(language_);
    ImGui::SetNextWindowSize(ImVec2(550, 400), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(),
                           ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));
    ImGui::Begin(S.creator_title, &show_creator_);
    ImGui::PushTextWrapPos(ImGui::GetContentRegionAvail().x);
    ImGui::TextWrapped("%s", S.creator_text);
    ImGui::PopTextWrapPos();
    ImGui::End();
}

// ============================================================
//  Main screen
// ============================================================
void SimulatorGUI::render_main_screen() {
    auto vm = victim_.get_metrics();
    auto am = attacker_.get_metrics();

    if (attack_running_ && !am.running)
        attack_running_ = false;

    // Update history
    pps_history_[history_offset_] = (float)vm.packets_per_sec;
    cpu_history_[history_offset_] = (float)vm.cpu_usage;
    mem_history_[history_offset_] = (float)vm.memory_usage;
    history_offset_ = (history_offset_ + 1) % HISTORY_SIZE;

    // Fullscreen window
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("##MainWindow", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_MenuBar);

    render_menu_bar();

    float panel_width = ImGui::GetContentRegionAvail().x;
    float left_width = panel_width * 0.38f;

    ImGui::BeginChild("AttackerPanel", ImVec2(left_width, 0), ImGuiChildFlags_Borders);
    render_attacker_panel();
    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("VictimPanel", ImVec2(0, 0), ImGuiChildFlags_Borders);
    render_victim_panel();
    ImGui::EndChild();

    ImGui::End();
}

// ============================================================
//  Menu bar
// ============================================================
void SimulatorGUI::render_menu_bar() {
    auto& S = get_strings(language_);

    if (ImGui::BeginMenuBar()) {
        // Back button
        if (ImGui::SmallButton(S.back_to_menu)) {
            if (attack_running_) {
                attacker_.stop();
                attack_running_ = false;
            }
            screen_ = AppScreen::START_SCREEN;
        }
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.4f, 1.0f), "|");
        ImGui::SameLine();

        ImGui::TextColored(ImVec4(0.3f, 0.75f, 0.95f, 1.0f), "%s", S.title);
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.4f, 1.0f), "|");
        ImGui::SameLine();

        if (attack_running_) {
            auto m = attacker_.get_metrics();
            ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%s:", S.attacking);
            ImGui::SameLine();
            ImGui::Text("%s [%.0f pkt/s, %.1fs]",
                       attack_type_name(m.type), m.packets_per_sec, m.elapsed_sec);
        } else {
            ImGui::TextColored(ImVec4(0.3f, 0.9f, 0.3f, 1.0f), "%s", S.idle);
        }

        ImGui::SameLine(ImGui::GetWindowWidth() - 200);
        ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.5f, 1.0f),
                          "API: localhost:%d", api_port_);

        ImGui::EndMenuBar();
    }
}

// ============================================================
//  Attacker panel
// ============================================================
void SimulatorGUI::render_attacker_panel() {
    auto& S = get_strings(language_);
    auto attacks = attacker_.list_attacks(language_);

    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", S.attacker_title);
    ImGui::Separator();
    ImGui::Spacing();

    // Attack list
    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "[ %s ]", S.attack_selection);
    ImGui::Spacing();

    float list_height = ImGui::GetContentRegionAvail().y * 0.38f;
    ImGui::BeginChild("AttackList", ImVec2(0, list_height), ImGuiChildFlags_Borders);

    std::string current_cat;
    for (int i = 0; i < (int)attacks.size(); i++) {
        if (attacks[i].category != current_cat) {
            current_cat = attacks[i].category;
            ImGui::Spacing();
            if (current_cat == "DoS")
                ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.2f, 1.0f), "%s", S.dos_header);
            else
                ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%s", S.ddos_header);
            ImGui::Spacing();
        }

        char label[128];
        snprintf(label, sizeof(label), "%2d. %s", i + 1, attacks[i].name.c_str());

        if (ImGui::Selectable(label, selected_attack_ == i))
            selected_attack_ = i;

        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::PushTextWrapPos(400);
            ImGui::TextColored(ImVec4(0.3f, 0.75f, 0.95f, 1.0f), "%s", attacks[i].name.c_str());
            ImGui::Text("%s", attacks[i].description.c_str());
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }
    }
    ImGui::EndChild();

    // Selected attack description
    ImGui::Spacing();
    if (selected_attack_ >= 0 && selected_attack_ < (int)attacks.size()) {
        auto& atk = attacks[selected_attack_];
        ImGui::TextColored(ImVec4(0.3f, 0.75f, 0.95f, 1.0f), "%s", atk.name.c_str());
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.5f, 1.0f), "[%s]", atk.category.c_str());
        ImGui::PushTextWrapPos(ImGui::GetContentRegionAvail().x);
        ImGui::TextWrapped("%s", atk.description.c_str());
        ImGui::PopTextWrapPos();
        if (ImGui::SmallButton(S.view_details))
            show_detail_popup_ = true;
    }

    // Parameters
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "[ %s ]", S.parameters);
    ImGui::Spacing();

    ImGui::SliderInt(S.intensity, &intensity_, 10, 200, "%d pkt/cycle");
    if (selected_attack_ >= 7)
        ImGui::SliderInt(S.bot_count, &num_bots_, 2, 50);
    ImGui::SliderInt(S.packet_size, &packet_size_, 64, 65535, "%d bytes");

    // Buttons
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    float btn_w = ImGui::GetContentRegionAvail().x;

    if (!attack_running_) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.7f, 0.15f, 0.15f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.85f, 0.2f, 0.2f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.95f, 0.25f, 0.25f, 1.0f));
        if (ImGui::Button(S.btn_start_attack, ImVec2(btn_w, 35))) {
            if (selected_attack_ >= 0 && selected_attack_ < (int)attacks.size()) {
                AttackType type = attack_type_from_key(attacks[selected_attack_].key);
                AttackParams params;
                params.intensity = intensity_;
                params.num_bots = num_bots_;
                params.packet_size = packet_size_;
                attacker_.start(type, params);
                attack_running_ = true;
            }
        }
        ImGui::PopStyleColor(3);
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.5f, 0.0f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9f, 0.6f, 0.1f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f, 0.7f, 0.2f, 1.0f));
        if (ImGui::Button(S.btn_stop_attack, ImVec2(btn_w, 35))) {
            attacker_.stop();
            attack_running_ = false;
        }
        ImGui::PopStyleColor(3);

        auto m = attacker_.get_metrics();
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%s: %lu",
                          S.packets_sent, (unsigned long)m.packets_sent);
        ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "PPS: %.0f | %s: %.1fs",
                          m.packets_per_sec, S.elapsed, m.elapsed_sec);
        if (m.active_bots > 0)
            ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%s: %d",
                              S.active_bots, m.active_bots);
    }

    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.15f, 0.3f, 0.6f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.2f, 0.4f, 0.7f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.25f, 0.45f, 0.8f, 1.0f));
    if (ImGui::Button(S.btn_reset, ImVec2(btn_w, 28))) {
        if (attack_running_) { attacker_.stop(); attack_running_ = false; }
        victim_.reset();
        memset(pps_history_, 0, sizeof(pps_history_));
        memset(cpu_history_, 0, sizeof(cpu_history_));
        memset(mem_history_, 0, sizeof(mem_history_));
        history_offset_ = 0;
    }
    ImGui::PopStyleColor(3);

    // Attack log
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "[ %s ]", S.attack_log);
    ImGui::BeginChild("AttackLog", ImVec2(0, 0), ImGuiChildFlags_Borders);
    auto atk_logs = attacker_.logs().recent(20);
    for (auto& log : atk_logs)
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.5f, 0.9f), "%s", log.c_str());
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
        ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();
}

// ============================================================
//  Victim panel
// ============================================================
void SimulatorGUI::render_victim_panel() {
    auto& S = get_strings(language_);
    auto m = victim_.get_metrics();

    ImGui::TextColored(ImVec4(0.3f, 0.9f, 0.4f, 1.0f), "%s", S.victim_title);
    ImGui::Separator();
    ImGui::Spacing();

    // Status badge
    ImVec4 status_color;
    std::string status_text = m.status;

    auto has = [&](const char* s) { return status_text.find(s) != std::string::npos; };
    if (has("DOWN") || has("다운") || has("CAIDO") || has("Denied") || has("거부") || has("Denegado")) {
        status_color = ImVec4(1.0f, 0.1f, 0.1f, 1.0f);
        status_text = S.status_down;
    } else if (has("Severe") || has("심각") || has("Severo")) {
        status_color = ImVec4(1.0f, 0.3f, 0.2f, 1.0f);
        status_text = S.status_severe;
    } else if (has("Delay") || has("지연") || has("Retraso")) {
        status_color = ImVec4(1.0f, 0.7f, 0.2f, 1.0f);
        status_text = S.status_delay;
    } else if (has("Load") || has("부하") || has("Carga")) {
        status_color = ImVec4(1.0f, 0.85f, 0.3f, 1.0f);
        status_text = S.status_load;
    } else {
        status_color = ImVec4(0.2f, 0.9f, 0.3f, 1.0f);
        status_text = S.status_normal;
    }

    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, 1.0f), "%s:", S.server_status);
    ImGui::SameLine();

    ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList* draw = ImGui::GetWindowDrawList();
    ImVec2 ts = ImGui::CalcTextSize(status_text.c_str());
    draw->AddRectFilled(
        ImVec2(p.x - 4, p.y - 2), ImVec2(p.x + ts.x + 8, p.y + ts.y + 4),
        ImGui::ColorConvertFloat4ToU32(ImVec4(status_color.x*0.3f, status_color.y*0.3f, status_color.z*0.3f, 0.8f)),
        4.0f);
    ImGui::TextColored(status_color, "%s", status_text.c_str());
    ImGui::Spacing();

    float gauge_w = ImGui::GetContentRegionAvail().x;

    // CPU
    {
        float cpu = (float)m.cpu_usage / 100.0f;
        ImVec4 c = cpu > 0.8f ? ImVec4(1,0.2f,0.2f,1) : cpu > 0.5f ? ImVec4(1,0.7f,0.2f,1) : ImVec4(0.3f,0.9f,0.4f,1);
        ImGui::TextColored(ImVec4(0.5f,0.5f,0.6f,1), "CPU");
        ImGui::SameLine(50);
        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, c);
        char ov[32]; snprintf(ov, 32, "%.1f%%", m.cpu_usage);
        ImGui::ProgressBar(cpu, ImVec2(gauge_w - 60, 18), ov);
        ImGui::PopStyleColor();
    }

    // Memory
    {
        float mem = (float)m.memory_usage / 100.0f;
        ImVec4 c = mem > 0.8f ? ImVec4(1,0.2f,0.2f,1) : mem > 0.5f ? ImVec4(1,0.7f,0.2f,1) : ImVec4(0.3f,0.8f,0.95f,1);
        ImGui::TextColored(ImVec4(0.5f,0.5f,0.6f,1), "MEM");
        ImGui::SameLine(50);
        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, c);
        char ov[32]; snprintf(ov, 32, "%.1f%%", m.memory_usage);
        ImGui::ProgressBar(mem, ImVec2(gauge_w - 60, 18), ov);
        ImGui::PopStyleColor();
    }

    // Connections
    {
        float conn = std::min((float)(m.active_connections + m.half_open_connections) / m.max_connections, 1.0f);
        ImVec4 c = conn > 0.8f ? ImVec4(1,0.2f,0.2f,1) : conn > 0.5f ? ImVec4(1,0.7f,0.2f,1) : ImVec4(0.3f,0.9f,0.4f,1);
        ImGui::TextColored(ImVec4(0.5f,0.5f,0.6f,1), "CONN");
        ImGui::SameLine(50);
        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, c);
        char ov[64]; snprintf(ov, 64, "%d / %d", m.active_connections + m.half_open_connections, m.max_connections);
        ImGui::ProgressBar(conn, ImVec2(gauge_w - 60, 18), ov);
        ImGui::PopStyleColor();
    }

    // Numeric metrics
    ImGui::Spacing();
    if (ImGui::BeginTable("M1", 4, ImGuiTableFlags_SizingStretchSame)) {
        ImGui::TableNextColumn();
        ImGui::TextColored(ImVec4(0.5f,0.5f,0.6f,1), "PPS");
        ImGui::TextColored(ImVec4(0.3f,0.75f,0.95f,1), "%.0f", m.packets_per_sec);
        ImGui::TableNextColumn();
        ImGui::TextColored(ImVec4(0.5f,0.5f,0.6f,1), "Bandwidth");
        ImGui::TextColored(ImVec4(0.3f,0.75f,0.95f,1), "%.2f Mbps", m.bandwidth_mbps);
        ImGui::TableNextColumn();
        ImGui::TextColored(ImVec4(0.5f,0.5f,0.6f,1), "Total");
        ImGui::Text("%lu", (unsigned long)m.total_packets);
        ImGui::TableNextColumn();
        ImGui::TextColored(ImVec4(0.5f,0.5f,0.6f,1), "Dropped");
        if (m.dropped_packets > 0)
            ImGui::TextColored(ImVec4(1,0.3f,0.3f,1), "%d", m.dropped_packets);
        else ImGui::Text("0");
        ImGui::EndTable();
    }

    ImGui::Spacing();
    ImGui::Separator();

    // Graphs
    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "[ %s ]", S.realtime_graphs);
    ImGui::Spacing();

    // PPS graph
    {
        float linear[HISTORY_SIZE];
        for (int i = 0; i < HISTORY_SIZE; i++)
            linear[i] = pps_history_[(history_offset_ + i) % HISTORY_SIZE];
        float mx = *std::max_element(linear, linear + HISTORY_SIZE);
        if (mx < 10) mx = 10;
        char ov[64]; snprintf(ov, 64, "PPS (max: %.0f)", mx);
        ImGui::PushStyleColor(ImGuiCol_PlotLines, ImVec4(0.3f,0.75f,0.95f,1));
        ImGui::PlotLines("##PPS", linear, HISTORY_SIZE, 0, ov, 0, mx*1.1f, ImVec2(gauge_w, 70));
        ImGui::PopStyleColor();
    }

    // CPU graph
    {
        float linear[HISTORY_SIZE];
        for (int i = 0; i < HISTORY_SIZE; i++)
            linear[i] = cpu_history_[(history_offset_ + i) % HISTORY_SIZE];
        ImGui::PushStyleColor(ImGuiCol_PlotLines, ImVec4(1,0.4f,0.3f,1));
        ImGui::PlotLines("##CPU", linear, HISTORY_SIZE, 0, "CPU %", 0, 100, ImVec2(gauge_w, 70));
        ImGui::PopStyleColor();
    }

    ImGui::Spacing();
    ImGui::Separator();

    // Attack detection
    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "[ %s ]", S.attack_detection);
    if (!m.attack_type_counts.empty()) {
        if (ImGui::BeginTable("AT", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
            ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Count", ImGuiTableColumnFlags_WidthFixed, 80);
            ImGui::TableHeadersRow();
            for (auto& [type, count] : m.attack_type_counts) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextColored(ImVec4(1,0.4f,0.4f,1), "%s", type.c_str());
                ImGui::TableNextColumn();
                ImGui::Text("%lu", (unsigned long)count);
            }
            ImGui::EndTable();
        }
    } else {
        ImGui::TextColored(ImVec4(0.4f,0.4f,0.4f,1), "%s", S.no_attacks);
    }

    // Source IPs
    if (!m.source_ip_counts.empty()) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "[ %s ]", S.top_sources);
        if (ImGui::BeginTable("SI", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
            ImGui::TableSetupColumn("IP", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Pkts", ImGuiTableColumnFlags_WidthFixed, 80);
            ImGui::TableHeadersRow();
            for (auto& [ip, count] : m.source_ip_counts) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextColored(ImVec4(0.8f,0.5f,0.9f,1), "%s", ip.c_str());
                ImGui::TableNextColumn();
                ImGui::Text("%lu", (unsigned long)count);
            }
            ImGui::EndTable();
        }
    }

    // Server log
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "[ %s ]", S.server_log);
    ImGui::BeginChild("ServerLog", ImVec2(0, 0), ImGuiChildFlags_Borders);
    auto logs = victim_.logs().recent(25);
    for (auto& log : logs) {
        ImVec4 color(0.5f, 0.5f, 0.5f, 0.9f);
        if (log.find("[DETECT]") != std::string::npos || log.find("[탐지]") != std::string::npos || log.find("[DETECTAR]") != std::string::npos)
            color = ImVec4(1,0.4f,0.4f,1);
        else if (log.find("[WARN]") != std::string::npos || log.find("[경고]") != std::string::npos || log.find("[AVISO]") != std::string::npos)
            color = ImVec4(1,0.7f,0.2f,1);
        else if (log.find("[Server]") != std::string::npos || log.find("[서버]") != std::string::npos || log.find("[Servidor]") != std::string::npos)
            color = ImVec4(0.3f,0.9f,0.4f,1);
        ImGui::TextColored(color, "%s", log.c_str());
    }
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
        ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();
}

// ============================================================
//  Attack detail popup
// ============================================================
void SimulatorGUI::render_attack_detail_popup() {
    auto& S = get_strings(language_);
    auto attacks = attacker_.list_attacks(language_);
    if (selected_attack_ < 0 || selected_attack_ >= (int)attacks.size()) {
        show_detail_popup_ = false;
        return;
    }

    auto& atk = attacks[selected_attack_];
    ImGui::SetNextWindowSize(ImVec2(700, 500), ImGuiCond_FirstUseEver);
    ImGui::Begin(atk.name.c_str(), &show_detail_popup_);

    ImGui::TextColored(ImVec4(0.3f,0.75f,0.95f,1), "%s", atk.name.c_str());
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.5f,0.5f,0.5f,1), "[%s]", atk.category.c_str());
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::TextColored(ImVec4(1,0.8f,0.3f,1), "%s:", S.description);
    ImGui::PushTextWrapPos(ImGui::GetContentRegionAvail().x);
    ImGui::TextWrapped("%s", atk.description.c_str());
    ImGui::PopTextWrapPos();
    ImGui::Spacing();

    ImGui::TextColored(ImVec4(1,0.8f,0.3f,1), "%s:", S.principle);
    ImGui::PushTextWrapPos(ImGui::GetContentRegionAvail().x);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.3f,0.9f,0.5f,1));
    ImGui::TextWrapped("%s", atk.principle.c_str());
    ImGui::PopStyleColor();
    ImGui::PopTextWrapPos();
    ImGui::Spacing();

    ImGui::TextColored(ImVec4(1,0.8f,0.3f,1), "%s:", S.defense);
    ImGui::PushTextWrapPos(ImGui::GetContentRegionAvail().x);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f,0.85f,0.3f,1));
    ImGui::TextWrapped("%s", atk.defense.c_str());
    ImGui::PopStyleColor();
    ImGui::PopTextWrapPos();

    ImGui::End();
}
