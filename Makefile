BUILD_DIR ?= ./build
TARGET ?= nif.out

CC ?= gcc
HGEN ?= ~/Desktop/projects/c/headergen/build/hgen.out

CSRC_DIR ?= ./csrc
CSRCS = $(shell find ./csrc -name *.c)

SRC_DIR ?= ./src
SRCS = $(shell find ./src -name *.c)

INC_DIR := $(shell find $(CSRC_DIR) -type d) 
INCS := $(addprefix -I,$(INC_DIR)) 

FLAGS ?= -MP

all: builddir 
	$(HGEN) -o $(CSRC_DIR) $(SRCS)
	$(CC) -lpcap -o $(BUILD_DIR)/$(TARGET) $(INCS) $(CSRCS)

.PHONY: clean builddir

clean: 
	rm -rf $(BUILD_DIR)

builddir: $(BUILD_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
