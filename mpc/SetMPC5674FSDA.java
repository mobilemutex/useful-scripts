/* ###
 * SetMPC5674FSDA.java - Set Small Data Area (SDA) base pointers for MPC5674F
 * Author: mobilemutex
 *
 * This script sets the r13 (_SDA_BASE_) and r2 (_SDA2_BASE_) register values
 * for PowerPC EABI firmware. These registers are global pointers that are
 * set once at program initialization and remain constant throughout execution.
 *
 * In PowerPC EABI:
 * - r13 (_SDA_BASE_) points to the small data area for read-write data
 * - r2 (_SDA2_BASE_) points to the small data area for read-only data
 *
 * The linker typically places these symbols in the firmware, and the startup
 * code loads them into r13 and r2 before calling main().
 *
 * Usage:
 * 1. Find the _SDA_BASE_ and _SDA2_BASE_ symbols in your firmware
 * 2. Run this script and enter the addresses when prompted
 * 3. Re-analyze the program for improved decompilation
 *
 * Licensed under the Apache License, Version 2.0
 * ###
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import java.math.BigInteger;

public class SetMPC5674FSDA extends GhidraScript {

    @Override
    protected void run() throws Exception {
        
        println("=== MPC5674F SDA Base Pointer Configuration ===");
        println("");
        println("In PowerPC EABI, r13 and r2 are global base pointers:");
        println("  r13 = _SDA_BASE_  (small read-write data area)");
        println("  r2  = _SDA2_BASE_ (small read-only data area)");
        println("");
        
        // Try to find _SDA_BASE_ symbol automatically
        Address sdaBase = findSymbolAddress("_SDA_BASE_");
        Address sda2Base = findSymbolAddress("_SDA2_BASE_");
        
        if (sdaBase != null) {
            println("Found _SDA_BASE_ at: " + sdaBase.toString());
        }
        if (sda2Base != null) {
            println("Found _SDA2_BASE_ at: " + sda2Base.toString());
        }
        
        // Prompt user for values
        String sdaInput = askString("SDA Base", 
            "Enter _SDA_BASE_ address for r13 (hex, e.g., 0x40008000):",
            sdaBase != null ? sdaBase.toString() : "0x40008000");
        
        String sda2Input = askString("SDA2 Base",
            "Enter _SDA2_BASE_ address for r2 (hex, e.g., 0x00020000):",
            sda2Base != null ? sda2Base.toString() : "0x00020000");
        
        long sdaValue = parseAddress(sdaInput);
        long sda2Value = parseAddress(sda2Input);
        
        println("");
        println("Setting register assumptions:");
        println("  r13 = 0x" + Long.toHexString(sdaValue) + " (_SDA_BASE_)");
        println("  r2  = 0x" + Long.toHexString(sda2Value) + " (_SDA2_BASE_)");
        
        // Get registers
        Register r13 = currentProgram.getLanguage().getRegister("r13");
        Register r2 = currentProgram.getLanguage().getRegister("r2");
        
        if (r13 == null || r2 == null) {
            printerr("Could not find r13 or r2 registers!");
            return;
        }
        
        // Set register values at program entry points
        int count = 0;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            Address entryPoint = func.getEntryPoint();
            
            // Set r13 assumption
            currentProgram.getProgramContext().setValue(
                r13, entryPoint, entryPoint, BigInteger.valueOf(sdaValue));
            
            // Set r2 assumption  
            currentProgram.getProgramContext().setValue(
                r2, entryPoint, entryPoint, BigInteger.valueOf(sda2Value));
            
            count++;
        }
        
        println("");
        println("Set SDA assumptions for " + count + " functions.");
        println("");
        println("IMPORTANT: You should now re-analyze the program:");
        println("  1. Go to Analysis -> Auto Analyze...");
        println("  2. Enable 'Decompiler Parameter ID'");
        println("  3. Click 'Analyze'");
        println("");
        println("After re-analysis, accesses like 'unaff_r13 + offset' should");
        println("resolve to proper global variable references.");
    }
    
    private Address findSymbolAddress(String name) {
        SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(name);
        if (symbols.hasNext()) {
            return symbols.next().getAddress();
        }
        return null;
    }
    
    private long parseAddress(String input) throws Exception {
        input = input.trim();
        if (input.startsWith("0x") || input.startsWith("0X")) {
            return Long.parseLong(input.substring(2), 16);
        }
        return Long.parseLong(input, 16);
    }
}
