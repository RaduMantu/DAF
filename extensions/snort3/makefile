# important directories
SRC = src
BIN = bin
OBJ = obj
INC = include

# snort include path (e.g.: .../install/include/snort/)
SNORT_INC ?= $(error Please specify SNORT_INC)

# compilation related parameters
CXX      = clang++
CXXFLAGS = -std=c++20 -fPIC -ggdb -O2 -I $(INC) -I $(SNORT_INC)
LDFLAGS  = $(shell pkg-config --libs libcrypto)

# identify sources and create object file targets
SOURCES = $(wildcard $(SRC)/*.cpp)
OBJECTS = $(patsubst $(SRC)/%.cpp, $(OBJ)/%.o, $(SOURCES))

.PHONY: build clean
.SECONDARY:

build: $(BIN)/ips_daf.so

%/:
	@mkdir -p $@

$(BIN)/ips_daf.so: $(OBJECTS) | $(BIN)/
	$(CXX) -shared -o $@ $^ $(LDFLAGS)

$(OBJ)/%.o: $(SRC)/%.cpp | $(OBJ)/
	$(CXX) -c $(CXXFLAGS) -o $@ $<

clean:
	@rm -rf $(BIN) $(OBJ)

