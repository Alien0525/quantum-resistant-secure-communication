# Makefile — PQC C++ extra-credit build
# Targets macOS (Homebrew liboqs + openssl@3) and Ubuntu (apt liboqs-dev + libssl-dev)

CXX      = g++
CXXFLAGS = -std=c++17 -O2 -Wall

# ── macOS (Homebrew) ───────────────────────────────────────────────────────
BREW_OQS   ?= $(shell brew --prefix liboqs 2>/dev/null)
BREW_SSL   ?= $(shell brew --prefix openssl@3 2>/dev/null)

INC_MACOS  = -I$(BREW_OQS)/include -I$(BREW_SSL)/include
LIB_MACOS  = -L$(BREW_OQS)/lib -L$(BREW_SSL)/lib -loqs -lcrypto -lssl

# ── Linux (apt liboqs-dev + libssl-dev) ───────────────────────────────────
INC_LINUX  =
LIB_LINUX  = -loqs -lcrypto -lssl

# ── Auto-detect platform ───────────────────────────────────────────────────
UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
  INC = $(INC_MACOS)
  LIB = $(LIB_MACOS)
else
  INC = $(INC_LINUX)
  LIB = $(LIB_LINUX)
endif

TARGET = pqc_core

all: $(TARGET)

$(TARGET): pqc_core.cpp
	$(CXX) $(CXXFLAGS) $(INC) $< -o $@ $(LIB)
	@echo "\nBuild successful: ./$(TARGET)"
	@echo "Usage:"
	@echo "  ./$(TARGET) kyber    \"Your message here\""
	@echo "  ./$(TARGET) mceliece \"Your message here\""
	@echo "  ./$(TARGET) both     \"Your message here\""

clean:
	rm -f $(TARGET)

.PHONY: all clean
