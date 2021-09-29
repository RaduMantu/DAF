# important directories
SRC = src
BIN = bin
OBJ = obj
INC = include

# compilation related parameters
CXX      = g++
CXXFLAGS = -std=c++20 -ggdb
LDFLAGS  = $(shell pkg-config --libs \
		   		libnetfilter_queue   \
				libbpf 				 \
				libprocps 		     \
				libcrypto			 \
				gpgme)

CLANG      = clang
LLC        = llc
CLANGFLAGS = -D__KERNEL__ -D__BPF_TRACING__ -emit-llvm -O2 -fno-stack-protector
LLCFLAGS   = -march=bpf -filetype=obj


# identify sources and create object file targets
#   main userspace app objects go into OBJ for remake caching
#   eBPF objects go straight into BIN to be used by final app
SOURCES_FW  = $(wildcard $(SRC)/firewall/*.cpp)
OBJECTS_FW  = $(patsubst $(SRC)/firewall/%.cpp, $(OBJ)/%.o, $(SOURCES_FW))

SOURCES_CTL = $(wildcard $(SRC)/controller/*.cpp)
OBJECTS_CTL = $(patsubst $(SRC)/controller/%.cpp, $(OBJ)/%.o, $(SOURCES_CTL))

SOURCES_BPF = $(wildcard $(SRC)/kern/*.c)
OBJECTS_BPF = $(patsubst $(SRC)/kern/%.c, $(BIN)/%.o, $(SOURCES_BPF))

# directive to prevent (attempted) intermediary file/directory deletion
.PRECIOUS: $(BIN)/ $(OBJ)/

# top level rule (specifies final binaries)
build: $(BIN)/app-fw $(BIN)/ctl-fw $(OBJECTS_BPF)

# non-persistent directory creation rule
%/:
	@mkdir -p $@

# final binary generation rules
$(BIN)/app-fw: $(OBJECTS_FW) | $(BIN)/
	$(CXX) -o $@ $^ $(LDFLAGS)

$(BIN)/ctl-fw: $(OBJECTS_CTL) | $(BIN)/
	$(CXX) -o $@ $^ $(LDFLAGS)

# object generation rules
$(OBJ)/%.o: $(SRC)/firewall/%.cpp | $(OBJ)/
	$(CXX) -c -I $(INC) $(CXXFLAGS) -o $@ $<

$(OBJ)/%.o: $(SRC)/controller/%.cpp | $(OBJ)/
	$(CXX) -c -I $(INC) $(CXXFLAGS) -o $@ $<

# eBPF object generation rule
$(BIN)/%.o: $(SRC)/kern/%.c | $(BIN)/
	$(CLANG) $(CLANGFLAGS) -I $(INC) -c -o - $< | $(LLC) $(LLCFLAGS) -o $@

# clean rule
clean:
	@rm -rf $(BIN) $(OBJ)


