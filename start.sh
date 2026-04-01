#!/bin/bash
#
# HAVOC - Network Attack Simulation Engine
# Auto-downloads dependencies, builds, and runs
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

BINARY="build/havoc"
PORT="${1:-7777}"
IMGUI_VERSION="v1.91.8"
IMGUI_DIR="imgui"

echo "============================================================"
echo "  HAVOC - Network Attack Simulation Engine"
echo "  Educational Purpose Only"
echo "============================================================"
echo ""

# ===== 1. System dependencies =====
echo "[1/4] Checking system dependencies..."

MISSING=""

if ! command -v g++ &> /dev/null; then
    MISSING="$MISSING build-essential"
fi

if ! pkg-config --exists glfw3 2>/dev/null; then
    MISSING="$MISSING libglfw3-dev"
fi

if [ ! -f /usr/include/GL/gl.h ] && ! dpkg -l libgl1-mesa-dev &>/dev/null 2>&1; then
    MISSING="$MISSING libgl1-mesa-dev"
fi

if ! command -v pkg-config &> /dev/null; then
    MISSING="$MISSING pkg-config"
fi

if [ -n "$MISSING" ]; then
    echo ""
    echo "[!] Missing packages:$MISSING"
    echo ""
    echo "    sudo apt install$MISSING"
    echo ""
    echo "Full install command:"
    echo "    sudo apt install build-essential libglfw3-dev libgl1-mesa-dev pkg-config fonts-nanum"
    echo ""
    exit 1
fi

echo "  OK"

# ===== 2. ImGui =====
echo "[2/4] Checking ImGui..."

if [ ! -d "$IMGUI_DIR" ]; then
    echo "  Downloading ImGui $IMGUI_VERSION..."

    if command -v git &> /dev/null; then
        git clone --depth 1 --branch "$IMGUI_VERSION" \
            https://github.com/ocornut/imgui.git "$IMGUI_DIR" 2>&1 | tail -1
    else
        TARBALL_URL="https://github.com/ocornut/imgui/archive/refs/tags/${IMGUI_VERSION}.tar.gz"
        wget -q "$TARBALL_URL" -O imgui.tar.gz
        tar xzf imgui.tar.gz
        mv "imgui-${IMGUI_VERSION#v}" "$IMGUI_DIR"
        rm imgui.tar.gz
    fi

    echo "  OK"
else
    echo "  OK (exists)"
fi

# ===== 3. Fonts =====
echo "[3/4] Checking fonts..."

FONT_OK=0
for fp in /usr/share/fonts/truetype/nanum/NanumGothic.ttf \
          /usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc \
          /usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc; do
    if [ -f "$fp" ]; then
        FONT_OK=1
        break
    fi
done

if [ $FONT_OK -eq 1 ]; then
    echo "  OK"
else
    echo "  Warning: Korean font not found (install fonts-nanum for Korean support)"
fi

# ===== 4. Build =====
echo "[4/4] Building..."

NEED_BUILD=0

if [ ! -f "$BINARY" ]; then
    NEED_BUILD=1
else
    for src in src/*.cpp src/*.h; do
        if [ -f "$src" ] && [ "$src" -nt "$BINARY" ]; then
            NEED_BUILD=1
            break
        fi
    done
fi

if [ $NEED_BUILD -eq 1 ]; then
    make -j$(nproc) 2>&1
    if [ ! -f "$BINARY" ]; then
        echo "[ERROR] Build failed!"
        exit 1
    fi
fi

echo ""
echo "============================================================"
echo "  Starting HAVOC..."
echo "  Python API: attack_sim.Simulator('localhost', $PORT)"
echo "  Headless:   ./start.sh $PORT --headless"
echo "============================================================"
echo ""

shift 2>/dev/null || true
exec "$BINARY" --port "$PORT" "$@"
