EXEC = main

SRC_DIR = src
INC_DIR = includes
BUILD_DIR = build

CXX = g++
CXXFLAGS = -Wall -I$(INC_DIR)

SRCS = $(wildcard $(SRC_DIR)/*.cpp) main.cpp
OBJS = $(SRCS:%.cpp=$(BUILD_DIR)/%.o)

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(EXEC)

rebuild: clean all

.PHONY: all clean rebuild
