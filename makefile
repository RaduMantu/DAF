.PHONY: dirs

# important directories
SRC = src
BIN = bin
OBJ = obj
INC = include

# compilation related parameters
CXX      = g++
CXXFLAGS = -std=c++20
LDFLAGS  = -lnetfilter_queue -lbpf

CLANG      = clang
LLC        = llc
CLANGFLAGS = -D__KERNEL__ -D__BPF_TRACING__ -emit-llvm -O2 -fno-stack-protector
LLCFLAGS   = -march=bpf -filetype=obj


# identify sources and create object file targets
#   main userspace app objects go into OBJ for remake caching
#   eBPF objects go straight into BIN to be used by final app
SOURCES_APP = $(wildcard $(SRC)/app/*.cpp)
OBJECTS_APP = $(patsubst $(SRC)/app/%.cpp, $(OBJ)/%.o, $(SOURCES_APP))

SOURCES_BPF = $(wildcard $(SRC)/kern/*.c)
OBJECTS_BPF = $(patsubst $(SRC)/kern/%.c, $(BIN)/%.o, $(SOURCES_BPF))

# top level rule
build: dirs $(BIN)/app-fw $(OBJECTS_BPF)

# non-persistent folder creation rule
dirs:
	@mkdir -p $(BIN) $(OBJ)

# final app binary generation rule
$(BIN)/app-fw: $(OBJECTS_APP)
	$(CXX) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# app object generation rule
$(OBJ)/%.o: $(SRC)/app/%.cpp
	$(CXX) -c -I $(INC) $(CXXFLAGS) -o $@ $<

# eBPF object generation rule
$(BIN)/%.o: $(SRC)/kern/%.c
	$(CLANG) $(CLANGFLAGS) -I $(INC) -c -o - $< | $(LLC) $(LLCFLAGS) -o $@

# clean rule
clean:
	@rm -rf $(BIN) $(OBJ)

