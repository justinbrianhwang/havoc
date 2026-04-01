CXX      = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -Wno-unused-parameter -pthread
SRCDIR   = src
BUILDDIR = build
IMGUIDIR = imgui
TARGET   = $(BUILDDIR)/havoc

LDFLAGS  = -lglfw -lGL -ldl -lpthread

# ImGui sources
IMGUI_CORE = imgui imgui_draw imgui_tables imgui_widgets
IMGUI_BE   = imgui_impl_glfw imgui_impl_opengl3

# Project sources
APP_SRCS = main http_server attack_engine victim_engine gui

# 오브젝트 파일
IMGUI_CORE_OBJS = $(IMGUI_CORE:%=$(BUILDDIR)/im_%.o)
IMGUI_BE_OBJS   = $(IMGUI_BE:%=$(BUILDDIR)/im_%.o)
APP_OBJS        = $(APP_SRCS:%=$(BUILDDIR)/%.o)

ALL_OBJS = $(APP_OBJS) $(IMGUI_CORE_OBJS) $(IMGUI_BE_OBJS)

INCLUDES = -I$(SRCDIR) -I$(IMGUIDIR) -I$(IMGUIDIR)/backends

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(ALL_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo ""
	@echo "  Build complete: $(TARGET)"
	@echo ""

# Project sources
$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

# ImGui 코어
$(BUILDDIR)/im_%.o: $(IMGUIDIR)/%.cpp | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -w -c -o $@ $<

# ImGui 백엔드
$(BUILDDIR)/im_imgui_impl_%.o: $(IMGUIDIR)/backends/imgui_impl_%.cpp | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -w -c -o $@ $<

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

clean:
	rm -rf $(BUILDDIR)

run: $(TARGET)
	./$(TARGET)
