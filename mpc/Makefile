# Makefile for MPC5674F Open Flash Loader
# Author: mobilemutex

# Toolchain - PowerPC EABI GCC
# You may need to adjust this path based on your installation
CC = powerpc-eabi-gcc
LD = powerpc-eabi-ld
OBJCOPY = powerpc-eabi-objcopy
OBJDUMP = powerpc-eabi-objdump
SIZE = powerpc-eabi-size

# If using a different toolchain name (e.g., from NXP S32 Design Studio)
# CC = powerpc-eabivle-gcc
# LD = powerpc-eabivle-ld
# OBJCOPY = powerpc-eabivle-objcopy
# OBJDUMP = powerpc-eabivle-objdump
# SIZE = powerpc-eabivle-size

# Project name
PROJECT = MPC5674F

# Source files
SRCS = FlashPrg.c

# Object files
OBJS = $(SRCS:.c=.o)

# Linker script
LDSCRIPT = linker.ld

# Compiler flags for PowerPC e200z7 core
# -mcpu=e200z7 specifies the e200z7 core
# -mhard-float enables hardware floating point
# -meabi enables EABI
CFLAGS = -mcpu=e200z7 -mhard-float -meabi
CFLAGS += -O2 -g -Wall
CFLAGS += -ffunction-sections -fdata-sections
CFLAGS += -ffreestanding -nostdlib

# Linker flags
LDFLAGS = -T $(LDSCRIPT)
LDFLAGS += -nostdlib -nostartfiles
LDFLAGS += --gc-sections

# Output files
ELF = $(PROJECT).elf
BIN = $(PROJECT).bin
MAP = $(PROJECT).map

# Default target
all: $(ELF)

# Link
$(ELF): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^ -Map=$(MAP)
	$(SIZE) $@
	$(OBJDUMP) -d -S $@ > $(PROJECT).lst

# Compile
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean
clean:
	rm -f $(OBJS) $(ELF) $(BIN) $(MAP) $(PROJECT).lst

# Phony targets
.PHONY: all clean

# Info
info:
	@echo "MPC5674F Open Flash Loader Build System"
	@echo "======================================="
	@echo "Toolchain: $(CC)"
	@echo "Sources:   $(SRCS)"
	@echo "Output:    $(ELF)"
