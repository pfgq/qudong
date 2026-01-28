# TearGame Kernel Module Makefile
# Supports Linux Kernel 5.10+
# Target: ARM64 (aarch64)

MODULE_NAME := teargame

# Source files
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := \
	src/main.o \
	src/command.o \
	src/memory.o \
	src/memory_safe.o \
	src/memory_batch.o \
	src/process.o \
	src/process_cache.o \
	src/touch.o \
	src/hook.o \
	src/stealth.o \
	src/auth.o \
	src/antidbg.o \
	src/file_hide.o \
	src/proc_hide.o

# Include path
ccflags-y := -I$(src)/include
ccflags-y += -DMODULE_NAME=\"$(MODULE_NAME)\"

# Optimization flags
ccflags-y += -O2 -fno-strict-aliasing
ccflags-y += -fno-common -fno-delete-null-pointer-checks

# Debug support (uncomment for debug build)
# ccflags-y += -DDEBUG -g

# Kernel build directory (override with KDIR=xxx)
KDIR ?= /lib/modules/$(shell uname -r)/build

# Cross compile support
ARCH ?= arm64
CROSS_COMPILE ?=

# Build commands
all: modules

modules:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KDIR) M=$(PWD) clean
	rm -f Module.symvers modules.order

install:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KDIR) M=$(PWD) modules_install

# Help target
help:
	@echo "TearGame Kernel Module Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make              - Build the module"
	@echo "  make clean        - Clean build files"
	@echo "  make install      - Install the module"
	@echo ""
	@echo "Variables:"
	@echo "  KDIR              - Kernel source directory"
	@echo "  ARCH              - Target architecture (default: arm64)"
	@echo "  CROSS_COMPILE     - Cross compiler prefix"
	@echo ""
	@echo "Example (Android cross-compile):"
	@echo "  make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- KDIR=/path/to/kernel"

.PHONY: all modules clean install help
