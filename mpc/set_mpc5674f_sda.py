# Set MPC5674F SDA Base Pointers
# Author: mobilemutex
#
# This script sets the r13 (_SDA_BASE_) and r2 (_SDA2_BASE_) register values
# for PowerPC EABI firmware on the MPC5674F microcontroller.
#
# In PowerPC EABI:
# - r13 (_SDA_BASE_) points to the small data area for read-write data
# - r2 (_SDA2_BASE_) points to the small data area for read-only data
#
# These are global pointers set once at startup and preserved across all calls.
# Setting them properly eliminates "unaff_r13" references in decompilation.
#
# Usage:
# 1. Find _SDA_BASE_ and _SDA2_BASE_ in your firmware (usually in .sdata section)
# 2. Run this script and enter the addresses
# 3. Re-analyze the program
#
# @category MPC5674F
# @author mobilemutex

from ghidra.program.model.lang import Register
from java.math import BigInteger

def find_symbol_address(name):
    """Find a symbol by name and return its address."""
    symbols = currentProgram.getSymbolTable().getSymbols(name)
    if symbols.hasNext():
        return symbols.next().getAddress()
    return None

def parse_hex(s):
    """Parse a hex string to long."""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    return long(s, 16)

def main():
    print("=== MPC5674F SDA Base Pointer Configuration ===")
    print("")
    print("In PowerPC EABI, r13 and r2 are global base pointers:")
    print("  r13 = _SDA_BASE_  (small read-write data area)")
    print("  r2  = _SDA2_BASE_ (small read-only data area)")
    print("")
    
    # Try to find symbols automatically
    sda_base = find_symbol_address("_SDA_BASE_")
    sda2_base = find_symbol_address("_SDA2_BASE_")
    
    if sda_base:
        print("Found _SDA_BASE_ at: " + str(sda_base))
    if sda2_base:
        print("Found _SDA2_BASE_ at: " + str(sda2_base))
    
    # Default values based on typical MPC5674F layout
    default_sda = str(sda_base) if sda_base else "0x40008000"
    default_sda2 = str(sda2_base) if sda2_base else "0x00020000"
    
    # Prompt user
    sda_input = askString("SDA Base", 
        "Enter _SDA_BASE_ address for r13 (hex):", default_sda)
    sda2_input = askString("SDA2 Base",
        "Enter _SDA2_BASE_ address for r2 (hex):", default_sda2)
    
    sda_value = parse_hex(sda_input)
    sda2_value = parse_hex(sda2_input)
    
    print("")
    print("Setting register assumptions:")
    print("  r13 = 0x%x (_SDA_BASE_)" % sda_value)
    print("  r2  = 0x%x (_SDA2_BASE_)" % sda2_value)
    
    # Get registers
    r13 = currentProgram.getLanguage().getRegister("r13")
    r2 = currentProgram.getLanguage().getRegister("r2")
    
    if not r13 or not r2:
        print("ERROR: Could not find r13 or r2 registers!")
        return
    
    # Set register values for all functions
    context = currentProgram.getProgramContext()
    functions = currentProgram.getFunctionManager().getFunctions(True)
    count = 0
    
    while functions.hasNext():
        if monitor.isCancelled():
            break
        func = functions.next()
        entry = func.getEntryPoint()
        
        # Set r13 assumption
        context.setValue(r13, entry, entry, BigInteger.valueOf(sda_value))
        
        # Set r2 assumption
        context.setValue(r2, entry, entry, BigInteger.valueOf(sda2_value))
        
        count += 1
    
    print("")
    print("Set SDA assumptions for %d functions." % count)
    print("")
    print("IMPORTANT: Re-analyze the program now:")
    print("  1. Analysis -> Auto Analyze...")
    print("  2. Enable 'Decompiler Parameter ID'")
    print("  3. Click 'Analyze'")
    print("")
    print("After re-analysis, 'unaff_r13' references should resolve properly.")

if __name__ == "__main__":
    main()
