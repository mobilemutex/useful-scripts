# CMakeLists.txt for MPC5674F Open Flash Loader
# Author: mobilemutex
#
# This CMake file is designed to work with a PowerPC EABI toolchain.
# You need to set the toolchain file or manually configure the compiler.

cmake_minimum_required(VERSION 3.16)

# Project name
project(MPC5674F_FlashLoader C ASM)

# Toolchain settings (adjust based on your installation)
# For NXP S32 Design Studio:
#   set(CMAKE_C_COMPILER powerpc-eabivle-gcc)
# For generic PowerPC EABI:
#   set(CMAKE_C_COMPILER powerpc-eabi-gcc)

# CPU flags for MPC5674F (e200z7 core)
set(CPU_FLAGS "-mcpu=e200z7 -mhard-float -meabi")

# Compiler flags
set(CMAKE_C_FLAGS "${CPU_FLAGS} -O2 -g -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffreestanding -nostdlib")

# Linker flags
set(CMAKE_EXE_LINKER_FLAGS "-T ${CMAKE_SOURCE_DIR}/linker.ld")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -nostdlib -nostartfiles")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-Map=${PROJECT_NAME}.map")

# Source files
set(SOURCES
    FlashPrg.c
)

# Create executable
add_executable(${PROJECT_NAME}.elf ${SOURCES})

# Post-build commands
add_custom_command(TARGET ${PROJECT_NAME}.elf POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} -O binary ${PROJECT_NAME}.elf ${PROJECT_NAME}.bin
    COMMAND ${CMAKE_SIZE} ${PROJECT_NAME}.elf
    COMMENT "Generating binary file and size info"
)
