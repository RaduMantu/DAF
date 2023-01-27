# important directories
SRC = src
BIN = bin
OBJ = obj
INC = include
CNF = configs
CRT = certs

# compilation related parameters
CXX      = clang++
CXXFLAGS = -std=c++20 -ggdb
LDFLAGS  = $(shell pkg-config --libs \
                libnetfilter_queue   \
                libbpf               \
                libprocps            \
                libcrypto)

CLANG      = clang
LLC        = llc
CLANGFLAGS = -D__KERNEL__ -D__BPF_TRACING__ -emit-llvm -O2 -fno-stack-protector -g
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

# phony targets
.PHONY: build cert clean bear

################################################################################
############################### TOP LEVEL RULES ################################
################################################################################

# firewall binary generation
build: $(BIN)/app-fw $(BIN)/ctl-fw $(OBJECTS_BPF)

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

