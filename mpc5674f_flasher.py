#!/usr/bin/env python3
"""
MPC5674F Flash Programmer using Tigard Board

Author: mobilemutex
Date: 2026-01-15
Description: A Python-based flash programmer for the NXP MPC5674F microcontroller
             using a Tigard board (FT2232H-based) for JTAG communication.

This tool implements the OnCE (On-Chip Emulation) and Nexus protocols to:
- Enter debug mode on the MPC5674F
- Read and write memory-mapped registers
- Erase and program the internal flash memory

Requirements:
- pyftdi library (pip install pyftdi)
- Tigard board connected via USB
- MPC5674F target connected to Tigard JTAG pins

Usage:
    python mpc5674f_flasher.py firmware.bin --erase
    python mpc5674f_flasher.py firmware.bin
    python mpc5674f_flasher.py --read 0xC3F88000

References:
- AN4365: Qorivva MPC56xx Flash Programming Through Nexus/JTAG
- MPC5674F Reference Manual Rev. 7
"""

import argparse
import struct
import sys
import time
from typing import Optional

try:
    from pyftdi.ftdi import Ftdi
except ImportError:
    print("Error: pyftdi library not found. Install with: pip install pyftdi")
    sys.exit(1)


# =============================================================================
# MPC5674F Memory Map Constants
# =============================================================================

# Flash Controller Base Addresses
FLASH_A_BASE = 0xC3F88000
FLASH_B_BASE = 0xC3F8C000

# Flash Register Offsets
REG_MCR   = 0x00   # Module Configuration Register
REG_LMLR  = 0x04   # Low/Mid Address Space Block Locking Register
REG_HLR   = 0x08   # High Address Space Block Locking Register
REG_SLMLR = 0x0C   # Secondary Low/Mid Address Space Block Locking Register
REG_LSR   = 0x10   # Low Address Space Block Select Register
REG_MSR   = 0x14   # Mid Address Space Block Select Register
REG_HSR   = 0x18   # High Address Space Block Select Register
REG_AR    = 0x1C   # Address Register

# MCR Register Bit Definitions
MCR_EHV  = 1 << 0   # Enable High Voltage
MCR_ESUS = 1 << 4   # Erase Suspend
MCR_ERS  = 1 << 5   # Erase
MCR_PSUS = 1 << 8   # Program Suspend
MCR_PGM  = 1 << 9   # Program
MCR_DONE = 1 << 10  # State Machine Status (1=complete)
MCR_PEG  = 1 << 11  # Program/Erase Good

# Memory Regions
FLASH_BASE = 0x00000000
FLASH_SIZE = 0x00400000  # 4 MB
SRAM_BASE  = 0x40000000
SRAM_SIZE  = 0x00040000  # 256 KB


# =============================================================================
# JTAG TAP State Machine
# =============================================================================

class JtagState:
    """JTAG TAP Controller States"""
    RESET       = 0
    IDLE        = 1
    SELECT_DR   = 2
    CAPTURE_DR  = 3
    SHIFT_DR    = 4
    EXIT1_DR    = 5
    PAUSE_DR    = 6
    EXIT2_DR    = 7
    UPDATE_DR   = 8
    SELECT_IR   = 9
    CAPTURE_IR  = 10
    SHIFT_IR    = 11
    EXIT1_IR    = 12
    PAUSE_IR    = 13
    EXIT2_IR    = 14
    UPDATE_IR   = 15


# =============================================================================
# Low-Level JTAG Interface using FTDI MPSSE
# =============================================================================

class JtagInterface:
    """
    Low-level JTAG interface using pyftdi's MPSSE mode.
    
    This class provides direct control over the JTAG signals (TCK, TMS, TDI, TDO)
    using the FT2232H chip on the Tigard board.
    """
    
    # MPSSE Commands
    MPSSE_WRITE_NEG = 0x01  # Write TDI/DO on negative TCK edge
    MPSSE_BIT_MODE  = 0x02  # Bit mode (vs byte mode)
    MPSSE_READ_NEG  = 0x04  # Read TDO/DI on negative TCK edge
    MPSSE_LSB_FIRST = 0x08  # LSB first (vs MSB first)
    MPSSE_WRITE_TDI = 0x10  # Write TDI
    MPSSE_READ_TDO  = 0x20  # Read TDO
    MPSSE_WRITE_TMS = 0x40  # Write TMS
    
    def __init__(self, url: str = 'ftdi://0x0403:0x6010/1'):
        """
        Initialize the JTAG interface.
        
        Args:
            url: FTDI device URL (default is Tigard on interface 1)
        """
        self.url = url
        self._ftdi = None
        self._state = JtagState.RESET
        
    def connect(self) -> bool:
        """Connect to the JTAG interface and configure MPSSE mode."""
        try:
            self._ftdi = Ftdi()
            self._ftdi.open_mpsse_from_url(self.url)
            
            # Configure MPSSE for JTAG at 1 MHz
            self._ftdi.set_frequency(1e6)
            
            # Set initial GPIO directions and values
            # ADBUS0 = TCK (output)
            # ADBUS1 = TDI (output)
            # ADBUS2 = TDO (input)
            # ADBUS3 = TMS (output)
            direction = 0x0B  # TCK, TDI, TMS as outputs
            value = 0x08      # TMS high initially
            self._ftdi.write_data(bytes([0x80, value, direction]))
            
            return True
        except Exception as e:
            print(f"Error connecting to JTAG interface: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from the JTAG interface."""
        if self._ftdi:
            self._ftdi.close()
            self._ftdi = None
    
    def reset_tap(self):
        """Reset the TAP state machine by holding TMS high for 5+ clocks."""
        # Clock TMS=1 for 6 cycles to ensure TEST-LOGIC-RESET
        self._clock_tms_bits(0x3F, 6)  # 6 bits of TMS=1
        self._state = JtagState.RESET
    
    def go_idle(self):
        """Go to RUN-TEST/IDLE state from RESET."""
        if self._state == JtagState.RESET:
            self._clock_tms_bits(0x00, 1)  # TMS=0
            self._state = JtagState.IDLE
    
    def shift_ir(self, data: int, bits: int) -> int:
        """
        Shift data into the Instruction Register.
        
        Args:
            data: Data to shift in (LSB first)
            bits: Number of bits to shift
            
        Returns:
            Data shifted out from TDO
        """
        # Navigate to SHIFT-IR from IDLE
        if self._state == JtagState.IDLE:
            # IDLE -> SELECT-DR -> SELECT-IR -> CAPTURE-IR -> SHIFT-IR
            self._clock_tms_bits(0x03, 4)  # TMS: 1,1,0,0
        
        self._state = JtagState.SHIFT_IR
        
        # Shift data (last bit with TMS=1 to exit)
        result = self._shift_bits(data, bits)
        
        # EXIT1-IR -> UPDATE-IR -> IDLE
        self._clock_tms_bits(0x01, 2)  # TMS: 1,0
        self._state = JtagState.IDLE
        
        return result
    
    def shift_dr(self, data: int, bits: int) -> int:
        """
        Shift data into the Data Register.
        
        Args:
            data: Data to shift in (LSB first)
            bits: Number of bits to shift
            
        Returns:
            Data shifted out from TDO
        """
        # Navigate to SHIFT-DR from IDLE
        if self._state == JtagState.IDLE:
            # IDLE -> SELECT-DR -> CAPTURE-DR -> SHIFT-DR
            self._clock_tms_bits(0x01, 3)  # TMS: 1,0,0
        
        self._state = JtagState.SHIFT_DR
        
        # Shift data (last bit with TMS=1 to exit)
        result = self._shift_bits(data, bits)
        
        # EXIT1-DR -> UPDATE-DR -> IDLE
        self._clock_tms_bits(0x01, 2)  # TMS: 1,0
        self._state = JtagState.IDLE
        
        return result
    
    def _clock_tms_bits(self, tms_data: int, num_bits: int):
        """
        Clock TMS bits while keeping TDI low.
        
        Args:
            tms_data: TMS bit pattern (LSB first)
            num_bits: Number of bits to clock
        """
        if num_bits == 0:
            return
        
        # MPSSE command: Clock TMS bits with read
        # Command format: 0x4B, length-1, TMS bits (bit 7 = TDI value)
        cmd = bytes([
            0x4B,           # Clock TMS with read
            num_bits - 1,   # Length - 1
            tms_data & 0x7F # TMS bits, TDI=0
        ])
        self._ftdi.write_data(cmd)
        # Read and discard TDO
        self._ftdi.read_data(1)
    
    def _shift_bits(self, data: int, num_bits: int) -> int:
        """
        Shift bits in/out while in SHIFT-IR or SHIFT-DR state.
        The last bit is shifted with TMS=1 to exit the shift state.
        
        Args:
            data: Data to shift in (LSB first)
            num_bits: Number of bits to shift
            
        Returns:
            Data shifted out (LSB first)
        """
        if num_bits == 0:
            return 0
        
        result = 0
        
        # Shift all but the last bit with TMS=0
        if num_bits > 1:
            remaining_bits = num_bits - 1
            
            # Process full bytes
            full_bytes = remaining_bits // 8
            if full_bytes > 0:
                # MPSSE command: Clock data bytes in/out
                cmd = bytes([
                    0x39,                    # Clock bytes in/out, LSB first
                    (full_bytes - 1) & 0xFF, # Length low byte
                    ((full_bytes - 1) >> 8) & 0xFF  # Length high byte
                ])
                # Add data bytes
                for i in range(full_bytes):
                    cmd += bytes([(data >> (i * 8)) & 0xFF])
                
                self._ftdi.write_data(cmd)
                
                # Read result
                read_data = self._ftdi.read_data(full_bytes)
                for i, b in enumerate(read_data):
                    result |= b << (i * 8)
                
                remaining_bits -= full_bytes * 8
                data >>= full_bytes * 8
            
            # Process remaining bits (less than 8)
            if remaining_bits > 0:
                # MPSSE command: Clock bits in/out
                cmd = bytes([
                    0x3B,               # Clock bits in/out, LSB first
                    remaining_bits - 1, # Length - 1
                    data & 0xFF         # Data byte
                ])
                self._ftdi.write_data(cmd)
                
                # Read result
                read_byte = self._ftdi.read_data(1)
                if read_byte:
                    result |= (read_byte[0] >> (8 - remaining_bits)) << (full_bytes * 8)
                
                data >>= remaining_bits
        
        # Shift the last bit with TMS=1 to exit
        last_bit = data & 1
        cmd = bytes([
            0x6B,           # Clock TMS with data read
            0x00,           # 1 bit
            (last_bit << 7) | 0x01  # TDI in bit 7, TMS=1
        ])
        self._ftdi.write_data(cmd)
        
        # Read last bit
        read_byte = self._ftdi.read_data(1)
        if read_byte:
            result |= ((read_byte[0] >> 7) & 1) << (num_bits - 1)
        
        return result


# =============================================================================
# OnCE (On-Chip Emulation) Protocol
# =============================================================================

class OnCEProtocol:
    """
    OnCE protocol implementation for MPC5674F.
    
    The OnCE module provides debug control of the PowerPC e200z7 core through
    the JTAG interface. This class implements the protocol described in AN4365.
    """
    
    # JTAGC Instructions (5-bit IR)
    ACCESS_AUX_TAP_NPC  = 0b10000  # Access NPC TAP controller
    ACCESS_AUX_TAP_ONCE = 0b10001  # Access e200z7 OnCE TAP controller
    ACCESS_AUX_TAP_ETPU = 0b10010  # Access eTPU Nexus TAP controller
    ACCESS_AUX_TAP_NXDM = 0b10011  # Access eDMA_A Nexus TAP controller
    
    # OnCE Command Register (OCMD) - 10-bit register
    # Bit 0: R/W (0=write, 1=read)
    # Bit 1: GO (execute instruction)
    # Bit 2: EX (exit debug mode)
    # Bits 3-9: RS[0:6] (register select)
    
    # OnCE Register Select (RS) values
    RS_JTAG_DID    = 0b0000010  # JTAG Device ID (read-only)
    RS_CPUSCR      = 0b0010000  # CPU Scan Register
    RS_NO_REG      = 0b0010001  # No register selected (bypass)
    RS_OCR         = 0b0010010  # OnCE Control Register
    RS_EDBCR0      = 0b0101110  # External Debug Control Register 0
    RS_EDBSR0      = 0b0101111  # External Debug Status Register 0
    RS_DBSR        = 0b0110000  # Debug Status Register
    RS_DBCR0       = 0b0110001  # Debug Control Register 0
    RS_NEXUS3      = 0b1111100  # Nexus3 access
    RS_ENABLE_ONCE = 0b1111110  # Enable OnCE (and bypass)
    RS_BYPASS      = 0b1111111  # Bypass
    
    def __init__(self, jtag: JtagInterface):
        """Initialize OnCE protocol with JTAG interface."""
        self.jtag = jtag
        self._once_enabled = False
    
    def enable_once_tap(self):
        """Enable the OnCE TAP controller."""
        # Shift ACCESS_AUX_TAP_ONCE into the 5-bit JTAGC IR
        self.jtag.shift_ir(self.ACCESS_AUX_TAP_ONCE, 5)
        self._once_enabled = True
    
    def read_register(self, rs: int) -> int:
        """
        Read an OnCE register.
        
        Args:
            rs: Register select value (7 bits)
            
        Returns:
            32-bit register value
        """
        # Build OCMD: RS[6:0] in bits 9:3, R/W=1 (read) in bit 0
        ocmd = (rs << 3) | 0x01
        
        # Shift OCMD into IR
        self.jtag.shift_ir(ocmd, 10)
        
        # Read data from DR
        return self.jtag.shift_dr(0, 32)
    
    def write_register(self, rs: int, value: int):
        """
        Write an OnCE register.
        
        Args:
            rs: Register select value (7 bits)
            value: 32-bit value to write
        """
        # Build OCMD: RS[6:0] in bits 9:3, R/W=0 (write) in bit 0
        ocmd = (rs << 3) | 0x00
        
        # Shift OCMD into IR
        self.jtag.shift_ir(ocmd, 10)
        
        # Write data to DR
        self.jtag.shift_dr(value, 32)
    
    def enter_debug_mode(self) -> bool:
        """
        Enter debug mode on the CPU.
        
        Returns:
            True if debug mode was entered successfully
        """
        # Write to OCR to set DR (Debug Request) bit
        # OCR[DR] is bit 1
        self.write_register(self.RS_OCR, 0x02)
        
        # Poll DBSR for debug mode entry
        for _ in range(10):
            dbsr = self.read_register(self.RS_DBSR)
            if dbsr & 0x01:  # Check if debug mode is active
                return True
            time.sleep(0.1)
        
        return False
    
    def exit_debug_mode(self):
        """Exit debug mode and resume normal execution."""
        # Build OCMD with EX bit set
        ocmd = (self.RS_NO_REG << 3) | 0x04  # EX=1
        self.jtag.shift_ir(ocmd, 10)


# =============================================================================
# Nexus Read/Write Access Block
# =============================================================================

class NexusAccess:
    """
    Nexus R/W access block for memory operations.
    
    The Nexus module provides the ability to read and write memory without
    stopping code execution. This is faster than the OnCE method and bypasses
    the MMU and cache.
    """
    
    # Nexus Register Indices
    RWCS = 0x7  # Read/Write Access Control/Status
    RWA  = 0x9  # Read/Write Access Address
    RWD  = 0xA  # Read/Write Access Data
    
    # RWCS Register Bits
    RWCS_AC  = 1 << 31  # Access Control (1=start)
    RWCS_RW  = 1 << 30  # Read/Write (0=read, 1=write)
    RWCS_SZ_8  = 0b000 << 27  # 8-bit access
    RWCS_SZ_16 = 0b001 << 27  # 16-bit access
    RWCS_SZ_32 = 0b010 << 27  # 32-bit access
    RWCS_ERR = 1 << 1   # Error flag
    RWCS_DV  = 1 << 0   # Data Valid flag
    
    def __init__(self, once: OnCEProtocol):
        """Initialize Nexus access with OnCE protocol."""
        self.once = once
    
    def _nexus_reg_access(self, reg_idx: int, write: bool, data: int = 0) -> int:
        """
        Access a Nexus register.
        
        Args:
            reg_idx: Nexus register index (7 bits)
            write: True for write, False for read
            data: Data to write (ignored for read)
            
        Returns:
            Data read from register (0 for write)
        """
        # Select Nexus3 access in OCMD
        ocmd = (OnCEProtocol.RS_NEXUS3 << 3) | 0x00
        self.once.jtag.shift_ir(ocmd, 10)
        
        # First DR pass: Nexus register index (7 bits) + R/W (1 bit)
        dr_data = (reg_idx << 1) | (1 if write else 0)
        self.once.jtag.shift_dr(dr_data, 8)
        
        # Second DR pass: 32-bit data
        if write:
            self.once.jtag.shift_dr(data, 32)
            return 0
        else:
            return self.once.jtag.shift_dr(0, 32)
    
    def read_memory(self, address: int) -> Optional[int]:
        """
        Read a 32-bit value from memory.
        
        Args:
            address: Memory address to read
            
        Returns:
            32-bit value or None on error
        """
        # Write address to RWA
        self._nexus_reg_access(self.RWA, True, address)
        
        # Configure RWCS for read
        rwcs = self.RWCS_AC | self.RWCS_SZ_32  # Start, 32-bit, read
        self._nexus_reg_access(self.RWCS, True, rwcs)
        
        # Poll for completion
        for _ in range(10):
            status = self._nexus_reg_access(self.RWCS, False)
            if status & self.RWCS_DV:
                if status & self.RWCS_ERR:
                    return None
                return self._nexus_reg_access(self.RWD, False)
            time.sleep(0.01)
        
        return None
    
    def write_memory(self, address: int, value: int) -> bool:
        """
        Write a 32-bit value to memory.
        
        Args:
            address: Memory address to write
            value: 32-bit value to write
            
        Returns:
            True on success, False on error
        """
        # Write address to RWA
        self._nexus_reg_access(self.RWA, True, address)
        
        # Write data to RWD
        self._nexus_reg_access(self.RWD, True, value)
        
        # Configure RWCS for write
        rwcs = self.RWCS_AC | self.RWCS_RW | self.RWCS_SZ_32  # Start, write, 32-bit
        self._nexus_reg_access(self.RWCS, True, rwcs)
        
        # Poll for completion
        for _ in range(10):
            status = self._nexus_reg_access(self.RWCS, False)
            if status & self.RWCS_DV:
                return not (status & self.RWCS_ERR)
            time.sleep(0.01)
        
        return False


# =============================================================================
# Flash Programmer
# =============================================================================

class MPC5674FFlasher:
    """
    High-level flash programmer for MPC5674F.
    
    This class provides methods to erase and program the internal flash memory
    of the MPC5674F microcontroller using a Tigard board for JTAG communication.
    """
    
    def __init__(self, url: str = 'ftdi://0x0403:0x6010/1'):
        """
        Initialize the flash programmer.
        
        Args:
            url: FTDI device URL for Tigard
        """
        self.jtag = JtagInterface(url)
        self.once = OnCEProtocol(self.jtag)
        self.nexus = NexusAccess(self.once)
        self._connected = False
    
    def connect(self) -> bool:
        """Connect to the target and enter debug mode."""
        print("Connecting to Tigard...")
        
        if not self.jtag.connect():
            return False
        
        print("Resetting TAP...")
        self.jtag.reset_tap()
        self.jtag.go_idle()
        
        print("Enabling OnCE TAP...")
        self.once.enable_once_tap()
        
        print("Entering debug mode...")
        if not self.once.enter_debug_mode():
            print("Error: Failed to enter debug mode")
            return False
        
        print("Connected and in debug mode.")
        self._connected = True
        return True
    
    def disconnect(self):
        """Disconnect from the target."""
        if self._connected:
            print("Exiting debug mode...")
            self.once.exit_debug_mode()
        
        print("Disconnecting...")
        self.jtag.disconnect()
        self._connected = False
    
    def read_register(self, address: int) -> Optional[int]:
        """Read a memory-mapped register."""
        return self.nexus.read_memory(address)
    
    def write_register(self, address: int, value: int) -> bool:
        """Write a memory-mapped register."""
        return self.nexus.write_memory(address, value)
    
    def erase_flash(self, flash_base: int = FLASH_A_BASE) -> bool:
        """
        Erase the flash memory.
        
        Args:
            flash_base: Base address of flash controller registers
            
        Returns:
            True on success
        """
        print("Starting flash erase...")
        
        # Read current MCR
        mcr = self.read_register(flash_base + REG_MCR)
        if mcr is None:
            print("Error: Failed to read MCR")
            return False
        
        print(f"Current MCR: 0x{mcr:08X}")
        
        # Select all low and mid address space blocks
        if not self.write_register(flash_base + REG_LSR, 0xFFFFFFFF):
            print("Error: Failed to write LSR")
            return False
        
        if not self.write_register(flash_base + REG_MSR, 0xFFFFFFFF):
            print("Error: Failed to write MSR")
            return False
        
        # Set ERS bit
        if not self.write_register(flash_base + REG_MCR, mcr | MCR_ERS):
            print("Error: Failed to set ERS")
            return False
        
        # Write interlock (any write to flash array)
        self.write_register(FLASH_BASE, 0xFFFFFFFF)
        
        # Set EHV to start erase
        mcr = self.read_register(flash_base + REG_MCR)
        if not self.write_register(flash_base + REG_MCR, mcr | MCR_EHV):
            print("Error: Failed to set EHV")
            return False
        
        # Poll for completion
        print("Erasing (this may take several seconds)...")
        for i in range(120):  # Up to 2 minutes
            mcr = self.read_register(flash_base + REG_MCR)
            if mcr is None:
                print("Error: Failed to read MCR during erase")
                return False
            
            if mcr & MCR_DONE:
                break
            
            time.sleep(1)
            print(f"  Waiting... ({i+1}s)")
        else:
            print("Error: Erase timed out")
            return False
        
        # Check PEG
        if not (mcr & MCR_PEG):
            print("Error: Erase failed (PEG not set)")
            return False
        
        # Clear EHV
        mcr = self.read_register(flash_base + REG_MCR)
        self.write_register(flash_base + REG_MCR, mcr & ~MCR_EHV)
        
        # Clear ERS
        mcr = self.read_register(flash_base + REG_MCR)
        self.write_register(flash_base + REG_MCR, mcr & ~MCR_ERS)
        
        print("Flash erase complete.")
        return True
    
    def program_flash(self, filename: str, start_address: int = FLASH_BASE) -> bool:
        """
        Program flash memory from a binary file.
        
        Args:
            filename: Path to binary file
            start_address: Starting address in flash
            
        Returns:
            True on success
        """
        print(f"Programming flash from {filename}...")
        
        try:
            with open(filename, 'rb') as f:
                data = f.read()
        except FileNotFoundError:
            print(f"Error: File not found: {filename}")
            return False
        except IOError as e:
            print(f"Error reading file: {e}")
            return False
        
        total_size = len(data)
        print(f"File size: {total_size} bytes")
        
        if total_size > FLASH_SIZE:
            print(f"Error: File too large for flash ({total_size} > {FLASH_SIZE})")
            return False
        
        # Pad to 8-byte boundary (double-word aligned for MPC5674F)
        if total_size % 8 != 0:
            data += b'\xFF' * (8 - (total_size % 8))
        
        address = start_address
        programmed = 0
        
        # Program in 8-byte chunks (double-word)
        for i in range(0, len(data), 8):
            chunk = data[i:i+8]
            
            # Read current MCR
            mcr = self.read_register(FLASH_A_BASE + REG_MCR)
            if mcr is None:
                print(f"\nError: Failed to read MCR at address 0x{address:08X}")
                return False
            
            # Set PGM bit
            if not self.write_register(FLASH_A_BASE + REG_MCR, mcr | MCR_PGM):
                print(f"\nError: Failed to set PGM at address 0x{address:08X}")
                return False
            
            # Write interlock (first word)
            word1 = struct.unpack('<I', chunk[0:4])[0]
            self.write_register(address, word1)
            
            # Write second word
            word2 = struct.unpack('<I', chunk[4:8])[0]
            self.write_register(address + 4, word2)
            
            # Set EHV to start programming
            mcr = self.read_register(FLASH_A_BASE + REG_MCR)
            if not self.write_register(FLASH_A_BASE + REG_MCR, mcr | MCR_EHV):
                print(f"\nError: Failed to set EHV at address 0x{address:08X}")
                return False
            
            # Poll for completion
            for _ in range(100):
                mcr = self.read_register(FLASH_A_BASE + REG_MCR)
                if mcr is None:
                    print(f"\nError: Failed to read MCR during program")
                    return False
                if mcr & MCR_DONE:
                    break
                time.sleep(0.001)
            else:
                print(f"\nError: Program timed out at address 0x{address:08X}")
                return False
            
            # Check PEG
            if not (mcr & MCR_PEG):
                print(f"\nError: Program failed at address 0x{address:08X}")
                return False
            
            # Clear EHV
            mcr = self.read_register(FLASH_A_BASE + REG_MCR)
            self.write_register(FLASH_A_BASE + REG_MCR, mcr & ~MCR_EHV)
            
            # Clear PGM
            mcr = self.read_register(FLASH_A_BASE + REG_MCR)
            self.write_register(FLASH_A_BASE + REG_MCR, mcr & ~MCR_PGM)
            
            address += 8
            programmed += 8
            
            # Progress update
            if programmed % 1024 == 0:
                percent = (programmed * 100) // total_size
                print(f"\r  Progress: {percent}% ({programmed}/{total_size} bytes)", end='')
        
        print(f"\n  Programming complete: {programmed} bytes written")
        return True
    
    def verify_flash(self, filename: str, start_address: int = FLASH_BASE) -> bool:
        """
        Verify flash contents against a binary file.
        
        Args:
            filename: Path to binary file
            start_address: Starting address in flash
            
        Returns:
            True if verification passes
        """
        print(f"Verifying flash against {filename}...")
        
        try:
            with open(filename, 'rb') as f:
                data = f.read()
        except FileNotFoundError:
            print(f"Error: File not found: {filename}")
            return False
        
        total_size = len(data)
        address = start_address
        verified = 0
        errors = 0
        
        for i in range(0, total_size, 4):
            chunk = data[i:i+4]
            if len(chunk) < 4:
                chunk += b'\xFF' * (4 - len(chunk))
            
            expected = struct.unpack('<I', chunk)[0]
            actual = self.read_register(address)
            
            if actual is None:
                print(f"\nError: Failed to read address 0x{address:08X}")
                return False
            
            if actual != expected:
                if errors < 10:  # Only show first 10 errors
                    print(f"\n  Mismatch at 0x{address:08X}: expected 0x{expected:08X}, got 0x{actual:08X}")
                errors += 1
            
            address += 4
            verified += 4
            
            if verified % 1024 == 0:
                percent = (verified * 100) // total_size
                print(f"\r  Progress: {percent}% ({verified}/{total_size} bytes)", end='')
        
        print()
        
        if errors > 0:
            print(f"Verification FAILED: {errors} errors found")
            return False
        
        print("Verification PASSED")
        return True


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='MPC5674F Flash Programmer using Tigard Board',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s firmware.bin --erase      Erase flash and program firmware
  %(prog)s firmware.bin              Program firmware (without erase)
  %(prog)s firmware.bin --verify     Program and verify firmware
  %(prog)s --read 0xC3F88000         Read a single register
  %(prog)s --dump 0x00000000 256     Dump 256 bytes from address
        """
    )
    
    parser.add_argument('file', nargs='?', help='Binary file to program')
    parser.add_argument('--erase', action='store_true', help='Erase flash before programming')
    parser.add_argument('--verify', action='store_true', help='Verify after programming')
    parser.add_argument('--read', metavar='ADDR', help='Read a single 32-bit register (hex address)')
    parser.add_argument('--dump', nargs=2, metavar=('ADDR', 'SIZE'), help='Dump memory (hex address, size in bytes)')
    parser.add_argument('--url', default='ftdi://0x0403:0x6010/1', help='FTDI device URL')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.file and not args.read and not args.dump:
        parser.error('Either a file to program, --read, or --dump must be specified')
    
    flasher = MPC5674FFlasher(args.url)
    
    try:
        if not flasher.connect():
            return 1
        
        # Handle --read
        if args.read:
            try:
                address = int(args.read, 16)
            except ValueError:
                print(f"Error: Invalid address: {args.read}")
                return 1
            
            value = flasher.read_register(address)
            if value is not None:
                print(f"0x{address:08X}: 0x{value:08X}")
            else:
                print(f"Error: Failed to read address 0x{address:08X}")
                return 1
            return 0
        
        # Handle --dump
        if args.dump:
            try:
                address = int(args.dump[0], 16)
                size = int(args.dump[1])
            except ValueError:
                print(f"Error: Invalid address or size")
                return 1
            
            print(f"Dumping {size} bytes from 0x{address:08X}:")
            for offset in range(0, size, 16):
                line = f"0x{address + offset:08X}:"
                for i in range(0, 16, 4):
                    if offset + i < size:
                        value = flasher.read_register(address + offset + i)
                        if value is not None:
                            line += f" {value:08X}"
                        else:
                            line += " ????????"
                print(line)
            return 0
        
        # Handle programming
        if args.file:
            if args.erase:
                if not flasher.erase_flash():
                    return 1
            
            if not flasher.program_flash(args.file):
                return 1
            
            if args.verify:
                if not flasher.verify_flash(args.file):
                    return 1
        
        return 0
        
    finally:
        flasher.disconnect()


if __name__ == '__main__':
    sys.exit(main())
