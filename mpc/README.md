# MPC5674F Open Flash Loader for SEGGER J-Link

**Author:** mobilemutex  
**Date:** 2026-01-16

## Overview

This is an Open Flash Loader (OFL) for the NXP MPC5674F microcontroller, designed to work with SEGGER J-Link debug probes. The flash loader enables J-Link to program and read the internal 4MB flash memory of the MPC5674F.

## Files

| File | Description |
|------|-------------|
| `FlashOS.h` | Header file with flash loader structures and function prototypes |
| `FlashPrg.c` | Flash programming and reading implementation |
| `linker.ld` | Linker script for PowerPC e200z7 |
| `Makefile` | Build system using Make |
| `CMakeLists.txt` | Alternative build system using CMake |
| `MPC5674F.xml` | J-Link device description file |
| `dump_flash.jlink` | J-Link Commander script for dumping flash |

## Requirements

### PowerPC Toolchain

You need a PowerPC EABI cross-compiler. Options include:

1. **NXP S32 Design Studio** (recommended) - Includes `powerpc-eabivle-gcc` toolchain. Download from the NXP website.

2. **GNU PowerPC EABI Toolchain** - Generic `powerpc-eabi-gcc` toolchain that can be built from source or obtained from various sources.

3. **CodeWarrior for MPC55xx/MPC56xx** - Older NXP/Freescale IDE with PowerPC compiler.

### Toolchain Configuration

Edit the `Makefile` or `CMakeLists.txt` to match your toolchain:

```makefile
# For NXP S32 Design Studio
CC = powerpc-eabivle-gcc

# For generic PowerPC EABI
CC = powerpc-eabi-gcc
```

## Building

### Using Make

```bash
# Build the flash loader
make

# Clean build artifacts
make clean

# Show build info
make info
```

### Using CMake

```bash
mkdir build
cd build
cmake -DCMAKE_TOOLCHAIN_FILE=<path-to-toolchain-file> ..
make
```

## Output

After a successful build, you will have:

| File | Description |
|------|-------------|
| `MPC5674F.elf` | ELF executable for J-Link |
| `MPC5674F.bin` | Binary file |
| `MPC5674F.map` | Linker map file |
| `MPC5674F.lst` | Disassembly listing |

## Installation

### Step 1: Copy Files

Copy the following files to your J-Link devices folder:

**Windows:**
```
%APPDATA%\SEGGER\JLinkDevices\NXP\MPC5674F\
```

**Linux:**
```
~/.config/SEGGER/JLinkDevices/NXP/MPC5674F/
```

**macOS:**
```
~/Library/Application Support/SEGGER/JLinkDevices/NXP/MPC5674F/
```

Files to copy:
- `MPC5674F.elf`
- `MPC5674F.xml`

### Step 2: Verify Installation

1. Open J-Link Commander
2. Type `device MPC5674F`
3. The device should be recognized

## Dumping Flash Memory

The MPC5674F internal flash is memory-mapped, which means J-Link can read it directly without needing a special flash loader function. There are several methods to dump the flash contents:

### Method 1: J-Link Commander (Recommended)

Use the included `dump_flash.jlink` script:

```bash
JLinkExe -device MPC5674F -if JTAG -speed 4000 -CommandFile dump_flash.jlink
```

Or manually in J-Link Commander:

```
J-Link> device MPC5674F
J-Link> connect
J-Link> halt
J-Link> SaveBin flash_dump.bin, 0x00000000, 0x400000
J-Link> exit
```

### Method 2: J-Link Commander Interactive

```bash
JLinkExe -device MPC5674F -if JTAG -speed 4000
```

Then use these commands:

| Command | Description |
|---------|-------------|
| `SaveBin <file>, <addr>, <size>` | Save memory to binary file |
| `mem <addr>, <size>` | Display memory contents |
| `mem8 <addr>, <size>` | Display memory as bytes |
| `mem16 <addr>, <size>` | Display memory as 16-bit words |
| `mem32 <addr>, <size>` | Display memory as 32-bit words |

### Method 3: J-Flash

1. Create a new project for MPC5674F
2. Connect to target
3. Use "Target" → "Read back" → "Entire chip" or "Selected sectors"
4. Save the read data to a file

### Method 4: GDB with J-Link GDB Server

Start the GDB server:
```bash
JLinkGDBServer -device MPC5674F -if JTAG -speed 4000
```

Connect with GDB and dump memory:
```gdb
(gdb) target remote localhost:2331
(gdb) dump binary memory flash_dump.bin 0x00000000 0x00400000
```

## Flash Memory Regions

| Region | Address Range | Size | Description |
|--------|---------------|------|-------------|
| Flash_A Low | 0x0000_0000 - 0x0003_FFFF | 256 KB | 8×16KB + 2×64KB |
| Flash_A Mid | 0x0004_0000 - 0x0007_FFFF | 256 KB | 2×128KB |
| Flash_A High | 0x0008_0000 - 0x001F_FFFF | 1.5 MB | 6×256KB |
| Flash_B Low | 0x0020_0000 - 0x0023_FFFF | 256 KB | 1×256KB |
| Flash_B Mid | 0x0024_0000 - 0x0027_FFFF | 256 KB | 1×256KB |
| Flash_B High | 0x0028_0000 - 0x003F_FFFF | 1.5 MB | 6×256KB |

## Example Dump Commands

```bash
# Dump entire 4MB flash
SaveBin full_flash.bin, 0x00000000, 0x400000

# Dump Flash_A only (first 2MB)
SaveBin flash_a.bin, 0x00000000, 0x200000

# Dump Flash_B only (second 2MB)
SaveBin flash_b.bin, 0x00200000, 0x200000

# Dump first 64KB (boot sector area)
SaveBin boot_sector.bin, 0x00000000, 0x10000

# Dump SRAM (for debugging)
SaveBin sram_dump.bin, 0x40000000, 0x40000
```

## Programming Flash

### J-Link Commander

```
J-Link> device MPC5674F
J-Link> connect
J-Link> erase
J-Link> loadfile firmware.bin 0x00000000
J-Link> verifybin firmware.bin 0x00000000
```

### J-Flash

1. Create a new project
2. Select "MPC5674F" as the target device
3. Load your binary file
4. Click "Program & Verify"

## Implemented Functions

The flash loader implements the following CMSIS-style functions:

| Function | Description |
|----------|-------------|
| `Init()` | Initialize flash programming |
| `UnInit()` | De-initialize after programming |
| `EraseChip()` | Erase entire flash |
| `EraseSector()` | Erase a single sector |
| `ProgramPage()` | Program 8 bytes (double-word) |
| `Verify()` | Verify programmed data |
| `Read()` | Read flash data |

## Limitations

1. **Sector Erase**: The current implementation uses a simplified sector mapping. For production use, implement proper sector-level erase based on the actual MPC5674F sector layout.

2. **Flash Unlocking**: If flash blocks are locked, you need to implement the unlock sequence using the correct password in the LMLR/HLR registers.

3. **Dual-Core**: The MPC5674F has dual e200z7 cores. This flash loader assumes single-core operation.

## Troubleshooting

### "Device not found"

Ensure the XML file is in the correct JLinkDevices folder, check that the ELF file path in the XML is correct, and restart J-Link software after adding new device files.

### "Flash programming failed"

Verify JTAG connection to the target, check that the target is powered, ensure flash blocks are not locked, and try reducing JTAG speed.

### "Cannot read flash"

Make sure the target is halted before reading. Use the `halt` command in J-Link Commander. Check that the JTAG connection is stable.

### "Verification failed"

The flash may not have been erased before programming. Use the erase option or call EraseChip before programming.

## References

1. MPC5674F Reference Manual (Rev. 7)
2. AN4365: Qorivva MPC56xx Flash Programming Through Nexus/JTAG
3. SEGGER J-Link Device Support Kit Documentation
4. Open Flash Loader Template: https://github.com/itzandroidtab/open_flashloader_template

## License

This software is provided "as-is" for educational and development purposes.
