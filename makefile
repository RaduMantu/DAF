
################################################################################
############################### CUSTOM FUNCTIONS ###############################
################################################################################

# checks if variable is defined
check-def = $(if $(strip $($1)),,$(error "$1" is not defined))

################################################################################
############################# BUILD-TIME VARIABLES #############################
################################################################################

# important directories
SRC = src
BIN = bin
OBJ = obj
INC = include
CNF = configs
CRT = certs

# make sure that base CPU frequency was provided
$(call check-def,BASE_FREQ)

# compilation related parameters
CXX      = clang++
CXXFLAGS = -std=c++20 -ggdb -O2 -DBASE_FREQ=$(BASE_FREQ)
LDFLAGS  = $(shell pkg-config --libs \
                libnetfilter_queue   \
                libbpf               \
                libprocps            \
                libcrypto            \
                liburing             \
                mount)

CLANG      = clang
LLC        = llc
CLANGFLAGS = -D__KERNEL__ -D__BPF_TRACING__ -emit-llvm -O2 -fno-stack-protector -g
LLCFLAGS   = -march=bpf -filetype=obj

# build time options
ifeq ($(ENABLE_STATS),y)
CXXFLAGS += -DENABLE_STATS
endif

ifeq ($(DISABLE_ORDERING),y)
CXXFLAGS += -DDISABLE_ORDERING
endif

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

# phony targets
.PHONY: build cert clean bear help

################################################################################
############################### TOP LEVEL RULES ################################
################################################################################

# firewall binary generation
build: $(BIN)/app-fw $(BIN)/ctl-fw $(OBJECTS_BPF)

# help message
help:
	@echo "Targets"
	@echo "  - build: generates firewall, companion app, eBPF program"
	@echo "  - bear : invokes the build target; generates compile_commands.json"
	@echo "  - clean: deletes binaries and object files"
	@echo "  - help : show this message"
	@echo ""
	@echo "Variables (env / param)"
	@echo "  - ENABLE_STATS    : records metrics; prints them on STDIN input"
	@echo "  - DISABLE_ORDERING: use hashmap instead of RB tree"
	@echo "                      disables aggregate hash matching"

# certificate generation
cert: $(CRT)/test.pem

# clean rule
clean:
	@rm -rf $(BIN) $(OBJ) $(CRT)

################################################################################
################################ MISCELLANEOUS #################################
################################################################################

# create non-persistent directory
%/:
	@mkdir -p $@

# generate compile_commands.json
bear:
	bear -- $(MAKE) build

################################################################################
############################## FIREWALL BINARIES ###############################
################################################################################

# firewall binary
$(BIN)/app-fw: $(OBJECTS_FW) | $(BIN)/
	$(CXX) -o $@ $^ $(LDFLAGS)

# configuration companion
$(BIN)/ctl-fw: $(OBJECTS_CTL) | $(BIN)/
	$(CXX) -o $@ $^ $(LDFLAGS)

# object generating targets
$(OBJ)/%.o: $(SRC)/firewall/%.cpp | $(OBJ)/
	$(CXX) -c -I $(INC) $(CXXFLAGS) -o $@ $<

$(OBJ)/%.o: $(SRC)/controller/%.cpp | $(OBJ)/
	$(CXX) -c -I $(INC) $(CXXFLAGS) -o $@ $<

# eBPF program
$(BIN)/%.o: $(SRC)/kern/%.c | $(BIN)/
	$(CLANG) $(CLANGFLAGS) -I $(INC) -c -o - $< | $(LLC) $(LLCFLAGS) -o $@

################################################################################
################################# CERTIFICATE ##################################
################################################################################

# PEM certificate generation rule (for testing only)
$(CRT)/test.pem: $(CRT)/test.key $(CRT)/test.csr | $(CRT)/
	@openssl x509              \
	    -req -days 365 -sha256 \
	    -in      $(word 2,$^)  \
	    -signkey $<            \
	    -out $@                \
	    &>/dev/null
	@rm -f $(word 2,$^)

# Certificate self-Signing Request generation rule
$(CRT)/test.csr: $(CNF)/cert.cnf | $(CRT)/
	@openssl req    \
	    -new -noenc \
	    -config $<  \
	    -out    $@  \
	    &>/dev/null

# Private Key generation rule
$(CRT)/test.key: | $(CRT)/
	@openssl genrsa -out $@ 4096 &>/dev/null

