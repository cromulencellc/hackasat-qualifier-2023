BUILD_DIR ?= ./build
SRC_DIR ?= ./src
PRIV_DIR ?= ./priv

TARGET ?= ominous_etude

CC := gcc
CXX := g++

CPPFLAGS := -MD
CFLAGS := -Wall -Werror -O0
CXXFLAGS := -Wall -Werror -std=c++17 -O0
LDFLAGS := -std=c++17

SRCS := $(shell find $(SRC_DIR) -name "*.c")
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

$(BUILD_DIR)/$(TARGET): $(OBJS)
	$(CC) $(filter-out ./build/XXXXX.o,$(OBJS)) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o:$(SRC_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

.PHONY: clean run all $(BUILD_DIR)

all: $(BUILD_DIR)/$(TARGET)

run: $(BUILD_DIR)/$(TARGET)
	$<

clean:
	rm -rf $(BUILD_DIR)

-include $(DEPS)
