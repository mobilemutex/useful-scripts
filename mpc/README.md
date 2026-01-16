# MPC5674F Open Flash Loader and Debug Tools for SEGGER J-Link

**Author:** mobilemutex  
**Date:** 2026-01-16

## Overview

This package provides tools for programming and reading the internal 4MB flash memory of the NXP MPC5674F microcontroller using SEGGER J-Link debug probes. It includes an Open Flash Loader (OFL) for programming and a J-Link script for proper debug mode initialization required for reliable flash reading.

## Files

| File | Description |
|------|-------------|
| `FlashOS.h` | Header file with flash loader structures and function prototypes |
| `FlashPrg.c` | Flash programming and reading implementation |
| `linker.ld` | Linker script for PowerPC e200z7 |
| `Makefile` | Build system using Make |
| `CMakeLists.txt` | Alternative build system using CMake |
| `MPC5674F.xml` | J-Link device description file |
| `MPC5674F_Debug.JLinkScript` | J-Link script for proper debug mode entry |
| `dump_flash_full.jlink` | J-Link Commander script for dumping all flash |
| `dump_flash.jlink` | Basic J-Link Commander script |

## The Flash Reading Problem

When attempting to read flash memory on the MPC5674F, you may encounter issues where only one flash bank is readable, and other regions return repeated values like `0x3C604000`. This occurs because the processor is not properly in debug mode, and memory reads are returning instruction fetches instead of actual memory contents.

The MPC5674F uses the OnCE (On-Chip Emulation) debug interface, which requires specific initialization to enable external debug mode and halt the core properly. The included `MPC5674F_Debug.JLinkScript` handles this initialization automatically.

## Dumping Flash Memory

### Method 1: Using the J-Link Script (Recommended)

This method uses the custom J-Link script to properly initialize debug mode before reading memory.

```bash
JLinkExe -device MPC5674F -if JTAG -speed 4000 \
         -JLinkScriptFile MPC5674F_Debug.JLinkScript \
         -CommandFile dump_flash_full.jlink
```

### Method 2: Interactive with J-Link Script

```bash
JLinkExe -device MPC5674F -if JTAG -speed 4000 \
         -JLinkScriptFile MPC5674F_Debug.JLinkScript
```

Then in J-Link Commander:

```
J-Link> connect
J-Link> halt
J-Link> mem32 0x00000000 0x20
J-Link> SaveBin flash_dump.bin, 0x00000000, 0x400000
J-Link> exit
```

### Method 3: Using GDB with J-Link GDB Server

Start the GDB server with the script:

```bash
JLinkGDBServer -device MPC5674F -if JTAG -speed 4000 \
               -JLinkScriptFile MPC5674F_Debug.JLinkScript
```

Connect with GDB:

```gdb
(gdb) target remote localhost:2331
(gdb) monitor halt
(gdb) dump binary memory flash_dump.bin 0x00000000 0x00400000
```

## Flash Memory Regions

The MPC5674F has 4MB of internal flash organized into two arrays:

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

## How the J-Link Script Works

The `MPC5674F_Debug.JLinkScript` performs the following initialization sequence:

1. **JTAG Chain Configuration**: Sets up the JTAG chain parameters for the MPC5674F (5-bit IR, single device).

2. **OnCE TAP Selection**: Writes the `ACCESS_AUX_TAP_ONCE` instruction (0x11) to the JTAGC IR to enable the OnCE TAP controller.

3. **OnCE Enable**: Writes to the Enable_OnCE register to activate the OnCE module.

4. **Debug Mode Request**: Sets the OCR[DR] bit to request debug mode entry.

5. **External Debug Enable**: Sets DBCR0[EDM] to enable external debug mode, allowing the debugger to control the core.

After this initialization, the core is halted and all memory regions become accessible for reading.

## Building the Flash Loader

### Requirements

You need a PowerPC EABI cross-compiler:

1. **NXP S32 Design Studio** (recommended) - Includes `powerpc-eabivle-gcc`
2. **GNU PowerPC EABI Toolchain** - Generic `powerpc-eabi-gcc`
3. **CodeWarrior for MPC55xx/MPC56xx** - Older NXP/Freescale IDE

### Build Commands

```bash
# Edit Makefile to set your toolchain path, then:
make

# This produces MPC5674F.elf
```

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
- `MPC5674F.elf` (after building)
- `MPC5674F.xml`
- `MPC5674F_Debug.JLinkScript`

### Step 2: Verify Installation

```bash
JLinkExe -device MPC5674F -if JTAG -speed 4000 \
         -JLinkScriptFile ~/.config/SEGGER/JLinkDevices/NXP/MPC5674F/MPC5674F_Debug.JLinkScript
```

## Troubleshooting

### "Only one flash bank readable"

This is the main problem this package solves. Use the J-Link script:

```bash
JLinkExe -device MPC5674F -if JTAG -speed 4000 \
         -JLinkScriptFile MPC5674F_Debug.JLinkScript
```

### "Memory returns 0x3C604000 repeatedly"

The value `0x3C604000` is a PowerPC instruction (`lis r3, 0x4000`). This indicates the processor is not in debug mode. Use the J-Link script to properly enter debug mode.

### "Cannot connect to target"

Verify your JTAG connections. The MPC5674F uses a 14-pin OnCE connector. Ensure JCOMP is connected to VDD for JTAG compliance mode. Try reducing the JTAG speed to 1000 kHz.

### "Device not found"

Ensure the XML file is in the correct JLinkDevices folder and restart J-Link software after adding new device files.

### "Flash programming failed"

Verify JTAG connection, check that the target is powered, ensure flash blocks are not locked, and try reducing JTAG speed.

## Implemented Flash Loader Functions

| Function | Description |
|----------|-------------|
| `Init()` | Initialize flash programming |
| `UnInit()` | De-initialize after programming |
| `EraseChip()` | Erase entire flash |
| `EraseSector()` | Erase a single sector |
| `ProgramPage()` | Program 8 bytes (double-word) |
| `Verify()` | Verify programmed data |
| `Read()` | Read flash data |

## References

1. MPC5674F Reference Manual (Rev. 7)
2. AN4365: Qorivva MPC56xx Flash Programming Through Nexus/JTAG
3. e200z7 Power Architecture Core Reference Manual
4. SEGGER J-Link Script Files Documentation
5. Open Flash Loader Template: https://github.com/itzandroidtab/open_flashloader_template

## License

This software is provided "as-is" for educational and development purposes.
