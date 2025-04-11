//Creates detailed memory map with bit-level labels for MCF5272 ColdFire processor
//@author Assistant
//@category Memory
//@keybinding 
//@menupath Tools[MCF5272 Memory Map Enhanced]
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import java.util.HashMap;
import java.util.Map;

public class MCF5272MemoryMapEnhancedScript extends GhidraScript {

    private static final long DEFAULT_MBAR = 0x10000000L;
    
    // Memory region definitions
    private static class MemoryRegion {
        String name;
        long address;
        long size;
        String comment;
        boolean read;
        boolean write;
        boolean execute;
        
        MemoryRegion(String name, long address, long size, String comment, 
                    boolean read, boolean write, boolean execute) {
            this.name = name;
            this.address = address;
            this.size = size;
            this.comment = comment;
            this.read = read;
            this.write = write;
            this.execute = execute;
        }
    }
    
    // Register bit field definition
    private static class RegisterField {
        String name;
        long offset;
        int bitStart;
        int bitEnd;
        String description;
        
        RegisterField(String name, long offset, int bitStart, int bitEnd, String description) {
            this.name = name;
            this.offset = offset;
            this.bitStart = bitStart;
            this.bitEnd = bitEnd;
            this.description = description;
        }
    }
    
    @Override
    public void run() throws Exception {
        long mbarAddr = askLong("MBAR Address", 
            "Enter Module Base Address Register (MBAR) value:",
            DEFAULT_MBAR);
        
        String[] choices = {"Core memory only", 
                           "Core + Basic MMIO", 
                           "All regions + Bit-level labels"};
        String choice = askChoice("Memory Regions", 
            "Select which memory regions to create:", choices, choices[2]);
        
        Memory memory = currentProgram.getMemory();
        
        try {
            createCoreMemoryRegions(memory);
            
            if (!choice.equals(choices[0])) {
                createMMIORegions(memory, mbarAddr);
            }
            
            if (choice.equals(choices[2])) {
                createPeripheralRegions(memory, mbarAddr);
                createDetailedLabels(mbarAddr);
            } else {
                createBasicLabels(mbarAddr);
            }
            
            println("MCF5272 enhanced memory map created successfully!");
            println("MBAR base address: 0x" + Long.toHexString(mbarAddr));
            
        } catch (Exception e) {
            printerr("Error creating memory map: " + e.getMessage());
            throw e;
        }
    }
    
    private void createCoreMemoryRegions(Memory memory) throws Exception {
        MemoryRegion[] coreRegions = {
            new MemoryRegion("ROM", 0x00000000L, 0x4000, "On-chip ROM (16KB)", true, false, true),
            new MemoryRegion("SRAM", 0x20000000L, 0x1000, "On-chip SRAM (4KB)", true, true, false)
        };
        
        for (MemoryRegion region : coreRegions) {
            createMemoryBlock(memory, region);
        }
    }
    
    private void createMMIORegions(Memory memory, long mbarAddr) throws Exception {
        MemoryRegion[] mmioRegions = {
            new MemoryRegion("SIM", mbarAddr + 0x0000, 0x40, "System Integration Module", true, true, false),
            new MemoryRegion("INT_CTRL", mbarAddr + 0x0020, 0x20, "Interrupt Controller", true, true, false),
            new MemoryRegion("CHIP_SEL", mbarAddr + 0x0040, 0x40, "Chip Select Module", true, true, false),
            new MemoryRegion("GPIO", mbarAddr + 0x0080, 0x20, "General Purpose I/O", true, true, false),
            new MemoryRegion("QSPI", mbarAddr + 0x00A0, 0x20, "Queued SPI", true, true, false),
            new MemoryRegion("PWM", mbarAddr + 0x00C0, 0x20, "Pulse Width Modulation", true, true, false),
            new MemoryRegion("DMA", mbarAddr + 0x00E0, 0x20, "DMA Controller", true, true, false),
            new MemoryRegion("UART0", mbarAddr + 0x0100, 0x40, "UART0 Controller", true, true, false),
            new MemoryRegion("UART1", mbarAddr + 0x0140, 0x40, "UART1 Controller", true, true, false),
            new MemoryRegion("SDRAM_CTRL", mbarAddr + 0x0180, 0x20, "SDRAM Controller", true, true, false),
            new MemoryRegion("TIMER", mbarAddr + 0x0200, 0x40, "Timer Module", true, true, false),
            new MemoryRegion("PLIC", mbarAddr + 0x0300, 0x100, "Physical Layer Interface Controller", true, true, false)
        };
        
        for (MemoryRegion region : mmioRegions) {
            createMemoryBlock(memory, region);
        }
    }
    
    private void createPeripheralRegions(Memory memory, long mbarAddr) throws Exception {
        MemoryRegion[] peripheralRegions = {
            new MemoryRegion("ETHERNET", mbarAddr + 0x0840, 0x400, "Ethernet Controller", true, true, false),
            new MemoryRegion("USB", mbarAddr + 0x1000, 0x400, "USB Controller", true, true, false)
        };
        
        for (MemoryRegion region : peripheralRegions) {
            createMemoryBlock(memory, region);
        }
    }
    
    private void createMemoryBlock(Memory memory, MemoryRegion region) throws Exception {
        try {
            Address startAddr = toAddr(region.address);
            
            if (memory.getBlock(startAddr) != null) {
                println("Block at " + startAddr + " already exists, skipping " + region.name);
                return;
            }
            
            MemoryBlock block = memory.createUninitializedBlock(
                region.name, startAddr, region.size, false);
            
            block.setComment(region.comment);
            block.setRead(region.read);
            block.setWrite(region.write);
            block.setExecute(region.execute);
            
            println("Created memory block: " + region.name + " at " + startAddr + 
                   " (size: 0x" + Long.toHexString(region.size) + ")");
            
        } catch (MemoryConflictException e) {
            println("Memory conflict creating " + region.name + ": " + e.getMessage());
        } catch (Exception e) {
            printerr("Failed to create " + region.name + ": " + e.getMessage());
            throw e;
        }
    }
    
    private void createBasicLabels(long mbarAddr) throws Exception {
        createLabel(toAddr(mbarAddr), "MBAR_BASE", true);
        createLabel(toAddr(mbarAddr + 0x0000), "SIM_BASE", true);
        createLabel(toAddr(mbarAddr + 0x0020), "INT_CTRL_BASE", true);
        createLabel(toAddr(mbarAddr + 0x0100), "UART0_BASE", true);
        createLabel(toAddr(mbarAddr + 0x0140), "UART1_BASE", true);
        createLabel(toAddr(mbarAddr + 0x0840), "ETHERNET_BASE", true);
        createLabel(toAddr(mbarAddr + 0x1000), "USB_BASE", true);
        createLabel(toAddr(0x00000000L), "ROM_BASE", true);
        createLabel(toAddr(0x20000000L), "SRAM_BASE", true);
    }
    
    private void createDetailedLabels(long mbarAddr) throws Exception {
        // Create basic labels first
        createBasicLabels(mbarAddr);
        
        // Create detailed register and bit field labels
        createSIMRegisterLabels(mbarAddr);
        createInterruptControllerLabels(mbarAddr);
        createUARTRegisterLabels(mbarAddr);
        createTimerRegisterLabels(mbarAddr);
        createGPIORegisterLabels(mbarAddr);
        createPWMRegisterLabels(mbarAddr);
        createEthernetRegisterLabels(mbarAddr);
        createUSBRegisterLabels(mbarAddr);
        
        println("Created detailed register and bit field labels");
    }
    
    private void createSIMRegisterLabels(long mbarAddr) throws Exception {
        // System Integration Module registers
        createLabel(toAddr(mbarAddr + 0x0000), "MBAR", true);
        createLabel(toAddr(mbarAddr + 0x0004), "SCR", true);      // System Configuration Register
        createLabel(toAddr(mbarAddr + 0x0006), "SPR", true);      // System Protection Register
        createLabel(toAddr(mbarAddr + 0x0008), "PMR", true);      // Power Management Register
        createLabel(toAddr(mbarAddr + 0x000E), "ALPR", true);     // Activate Low-Power Register
        createLabel(toAddr(mbarAddr + 0x0010), "DIR", true);      // Device Identification Register
        
        // Watchdog registers
        createLabel(toAddr(mbarAddr + 0x0014), "WRRR", true);     // Watchdog Reset Reference Register
        createLabel(toAddr(mbarAddr + 0x0016), "WIRR", true);     // Watchdog Interrupt Reference Register
        createLabel(toAddr(mbarAddr + 0x0018), "WCR", true);      // Watchdog Counter Register
        createLabel(toAddr(mbarAddr + 0x001A), "WER", true);      // Watchdog Event Register
        
        // System Configuration Register (SCR) bit fields
        createLabel(toAddr(mbarAddr + 0x0004), "SCR_RSTSRC", true);    // Reset Source bits [15:12]
        createLabel(toAddr(mbarAddr + 0x0004), "SCR_BUSLOCK", true);   // Bus Lock bit [11]
        createLabel(toAddr(mbarAddr + 0x0004), "SCR_PRIALLOC", true);  // Priority Allocation bit [10]
    }
    
    private void createInterruptControllerLabels(long mbarAddr) throws Exception {
        // Interrupt Controller registers
        createLabel(toAddr(mbarAddr + 0x0020), "ICR1", true);     // Interrupt Control Register 1
        createLabel(toAddr(mbarAddr + 0x0024), "ICR2", true);     // Interrupt Control Register 2
        createLabel(toAddr(mbarAddr + 0x0028), "ICR3", true);     // Interrupt Control Register 3
        createLabel(toAddr(mbarAddr + 0x002C), "ICR4", true);     // Interrupt Control Register 4
        createLabel(toAddr(mbarAddr + 0x0030), "ISR", true);      // Interrupt Source Register
        createLabel(toAddr(mbarAddr + 0x0034), "PITR", true);     // Programmable Interrupt Transition Register
        createLabel(toAddr(mbarAddr + 0x0038), "PIWR", true);     // Programmable Interrupt Wakeup Register
        createLabel(toAddr(mbarAddr + 0x003C), "PIVR", true);     // Programmable Interrupt Vector Register
        
        // ICR1 bit fields (example for Timer interrupts)
        createLabel(toAddr(mbarAddr + 0x0020), "ICR1_TMR0IL", true);   // Timer 0 Interrupt Level
        createLabel(toAddr(mbarAddr + 0x0020), "ICR1_TMR1IL", true);   // Timer 1 Interrupt Level
        createLabel(toAddr(mbarAddr + 0x0020), "ICR1_TMR2IL", true);   // Timer 2 Interrupt Level
        createLabel(toAddr(mbarAddr + 0x0020), "ICR1_TMR3IL", true);   // Timer 3 Interrupt Level
    }
    
    private void createUARTRegisterLabels(long mbarAddr) throws Exception {
        // UART0 registers
        createLabel(toAddr(mbarAddr + 0x0100), "UART0_UMR1", true);   // UART Mode Register 1
        createLabel(toAddr(mbarAddr + 0x0100), "UART0_UMR2", true);   // UART Mode Register 2 (same offset)
        createLabel(toAddr(mbarAddr + 0x0104), "UART0_USR", true);    // UART Status Register
        createLabel(toAddr(mbarAddr + 0x0104), "UART0_UCSR", true);   // UART Clock Select Register
        createLabel(toAddr(mbarAddr + 0x0108), "UART0_UCR", true);    // UART Command Register
        createLabel(toAddr(mbarAddr + 0x010C), "UART0_URB", true);    // UART Receiver Buffer
        createLabel(toAddr(mbarAddr + 0x010C), "UART0_UTB", true);    // UART Transmitter Buffer
        createLabel(toAddr(mbarAddr + 0x0110), "UART0_UIPCR", true);  // UART Input Port Change Register
        createLabel(toAddr(mbarAddr + 0x0110), "UART0_UACR", true);   // UART Auxiliary Control Register
        createLabel(toAddr(mbarAddr + 0x0114), "UART0_UISR", true);   // UART Interrupt Status Register
        createLabel(toAddr(mbarAddr + 0x0114), "UART0_UIMR", true);   // UART Interrupt Mask Register
        createLabel(toAddr(mbarAddr + 0x0118), "UART0_UDU", true);    // UART Divider Upper Register
        createLabel(toAddr(mbarAddr + 0x011C), "UART0_UDL", true);    // UART Divider Lower Register
        
        // UART1 registers (similar structure at offset 0x0140)
        createLabel(toAddr(mbarAddr + 0x0140), "UART1_UMR1", true);
        createLabel(toAddr(mbarAddr + 0x0144), "UART1_USR", true);
        createLabel(toAddr(mbarAddr + 0x0148), "UART1_UCR", true);
        createLabel(toAddr(mbarAddr + 0x014C), "UART1_URB", true);
        createLabel(toAddr(mbarAddr + 0x0150), "UART1_UIPCR", true);
        createLabel(toAddr(mbarAddr + 0x0154), "UART1_UISR", true);
        
        // UART Status Register (USR) bit fields
        createLabel(toAddr(mbarAddr + 0x0104), "USR_RB", true);       // Received Break
        createLabel(toAddr(mbarAddr + 0x0104), "USR_FE", true);       // Framing Error
        createLabel(toAddr(mbarAddr + 0x0104), "USR_PE", true);       // Parity Error
        createLabel(toAddr(mbarAddr + 0x0104), "USR_OE", true);       // Overrun Error
        createLabel(toAddr(mbarAddr + 0x0104), "USR_TXEMP", true);    // Transmitter Empty
        createLabel(toAddr(mbarAddr + 0x0104), "USR_TXRDY", true);    // Transmitter Ready
        createLabel(toAddr(mbarAddr + 0x0104), "USR_FFULL", true);    // FIFO Full
        createLabel(toAddr(mbarAddr + 0x0104), "USR_RXRDY", true);    // Receiver Ready
    }
    
    private void createTimerRegisterLabels(long mbarAddr) throws Exception {
        // Timer Module registers
        for (int i = 0; i < 4; i++) {
            long timerBase = mbarAddr + 0x0200 + (i * 0x10);
            createLabel(toAddr(timerBase + 0x00), "TMR" + i, true);        // Timer Mode Register
            createLabel(toAddr(timerBase + 0x04), "TRR" + i, true);        // Timer Reference Register
            createLabel(toAddr(timerBase + 0x08), "TCAP" + i, true);       // Timer Capture Register
            createLabel(toAddr(timerBase + 0x0C), "TCN" + i, true);        // Timer Counter Register
            createLabel(toAddr(timerBase + 0x11), "TER" + i, true);        // Timer Event Register
        }
        
        // Timer Mode Register (TMR) bit fields for Timer 0
        createLabel(toAddr(mbarAddr + 0x0200), "TMR0_PS", true);          // Prescaler Select
        createLabel(toAddr(mbarAddr + 0x0200), "TMR0_CE", true);          // Capture Edge
        createLabel(toAddr(mbarAddr + 0x0200), "TMR0_OM", true);          // Output Mode
        createLabel(toAddr(mbarAddr + 0x0200), "TMR0_ORI", true);         // Output Reference Interrupt
        createLabel(toAddr(mbarAddr + 0x0200), "TMR0_FRR", true);         // Free Run/Restart
        createLabel(toAddr(mbarAddr + 0x0200), "TMR0_CLK", true);         // Clock Source
        createLabel(toAddr(mbarAddr + 0x0200), "TMR0_TEN", true);         // Timer Enable
        createLabel(toAddr(mbarAddr + 0x0200), "TMR0_RST", true);         // Timer Reset
    }
    
    private void createGPIORegisterLabels(long mbarAddr) throws Exception {
        // GPIO registers
        createLabel(toAddr(mbarAddr + 0x0080), "PACNT", true);        // Port A Control Register
        createLabel(toAddr(mbarAddr + 0x0084), "PADDR", true);        // Port A Data Direction Register
        createLabel(toAddr(mbarAddr + 0x0086), "PADAT", true);        // Port A Data Register
        createLabel(toAddr(mbarAddr + 0x0088), "PBCNT", true);        // Port B Control Register
        createLabel(toAddr(mbarAddr + 0x008C), "PBDDR", true);        // Port B Data Direction Register
        createLabel(toAddr(mbarAddr + 0x008E), "PBDAT", true);        // Port B Data Register
        createLabel(toAddr(mbarAddr + 0x0094), "PCDDR", true);        // Port C Data Direction Register
        createLabel(toAddr(mbarAddr + 0x0096), "PCDAT", true);        // Port C Data Register
        createLabel(toAddr(mbarAddr + 0x0098), "PDCNT", true);        // Port D Control Register
        
        // Port A Control Register (PACNT) bit fields
        createLabel(toAddr(mbarAddr + 0x0080), "PACNT_IPA", true);       // Interrupt Port A
        createLabel(toAddr(mbarAddr + 0x0080), "PACNT_DREQ0", true);     // DMA Request 0 Enable
        createLabel(toAddr(mbarAddr + 0x0080), "PACNT_WP", true);        // Write Protect
        createLabel(toAddr(mbarAddr + 0x0080), "PACNT_DMAREQ", true);    // DMA Request Select
    }
    
    private void createPWMRegisterLabels(long mbarAddr) throws Exception {
        // PWM registers
        for (int i = 0; i < 3; i++) {
            long pwmBase = mbarAddr + 0x00C0 + (i * 0x04);
            createLabel(toAddr(pwmBase), "PWCR" + i, true);           // PWM Control Register
            createLabel(toAddr(pwmBase + 0x02), "PWWD" + i, true);    // PWM Width Register
        }
        
        // PWM Control Register (PWCR) bit fields
        createLabel(toAddr(mbarAddr + 0x00C0), "PWCR0_EN", true);        // PWM Enable
        createLabel(toAddr(mbarAddr + 0x00C0), "PWCR0_REPEAT", true);    // Repeat Mode
        createLabel(toAddr(mbarAddr + 0x00C0), "PWCR0_LOAD", true);      // Load Enable
        createLabel(toAddr(mbarAddr + 0x00C0), "PWCR0_PRESCALE", true);  // Prescaler
    }
    
    private void createEthernetRegisterLabels(long mbarAddr) throws Exception {
        // Ethernet Controller registers
        createLabel(toAddr(mbarAddr + 0x0840), "ECR", true);          // Ethernet Control Register
        createLabel(toAddr(mbarAddr + 0x0844), "EIR", true);          // Ethernet Interrupt Register
        createLabel(toAddr(mbarAddr + 0x0848), "EIMR", true);         // Ethernet Interrupt Mask Register
        createLabel(toAddr(mbarAddr + 0x084C), "IVSR", true);         // Interrupt Vector Status Register
        createLabel(toAddr(mbarAddr + 0x0850), "RDAR", true);         // Receive Descriptor Active Register
        createLabel(toAddr(mbarAddr + 0x0854), "TDAR", true);         // Transmit Descriptor Active Register
        createLabel(toAddr(mbarAddr + 0x0880), "MMFR", true);         // MII Management Frame Register
        createLabel(toAddr(mbarAddr + 0x0884), "MSCR", true);         // MII Speed Control Register
        createLabel(toAddr(mbarAddr + 0x08C4), "RCR", true);          // Receive Control Register
        createLabel(toAddr(mbarAddr + 0x08C8), "MFLR", true);         // Maximum Frame Length Register
        createLabel(toAddr(mbarAddr + 0x08CC), "TCR", true);          // Transmit Control Register
        
        // Ethernet Control Register (ECR) bit fields
        createLabel(toAddr(mbarAddr + 0x0840), "ECR_RESET", true);       // Ethernet Reset
        createLabel(toAddr(mbarAddr + 0x0840), "ECR_ETHEREN", true);     // Ethernet Enable
        createLabel(toAddr(mbarAddr + 0x0840), "ECR_MAGICEN", true);     // Magic Packet Enable
        createLabel(toAddr(mbarAddr + 0x0840), "ECR_SLEEP", true);       // Sleep Mode Enable
        createLabel(toAddr(mbarAddr + 0x0840), "ECR_EN1588", true);      // Enhanced Descriptor Enable
    }
    
    private void createUSBRegisterLabels(long mbarAddr) throws Exception {
        // USB Controller registers
        createLabel(toAddr(mbarAddr + 0x1000), "FNR", true);          // Frame Number Register
        createLabel(toAddr(mbarAddr + 0x1004), "FNMR", true);         // Frame Number Match Register
        createLabel(toAddr(mbarAddr + 0x1008), "RFMR", true);         // Real-time Frame Monitor Register
        createLabel(toAddr(mbarAddr + 0x100C), "RFMMR", true);        // Real-time Frame Monitor Match Register
        createLabel(toAddr(mbarAddr + 0x1010), "FAR", true);          // Function Address Register
        createLabel(toAddr(mbarAddr + 0x1014), "ASR", true);          // Alternate Settings Register
        createLabel(toAddr(mbarAddr + 0x1018), "DRR1", true);         // Device Request Data 1 Register
        createLabel(toAddr(mbarAddr + 0x101C), "DRR2", true);         // Device Request Data 2 Register
        createLabel(toAddr(mbarAddr + 0x1020), "SPECR", true);        // Specification Number Register
        
        // Endpoint registers
        for (int i = 0; i <= 7; i++) {
            long epBase = mbarAddr + 0x1030 + (i * 0x10);
            createLabel(toAddr(epBase + 0x00), "EP" + i + "SR", true);    // Endpoint Status Register
            createLabel(toAddr(epBase + 0x04), "EP" + i + "CR", true);    // Endpoint Control Register
            createLabel(toAddr(epBase + 0x08), "EP" + i + "ISR", true);   // Endpoint Interrupt Status Register
            createLabel(toAddr(epBase + 0x0C), "EP" + i + "IMR", true);   // Endpoint Interrupt Mask Register
            createLabel(toAddr(epBase + 0x10), "EP" + i + "DR", true);    // Endpoint Data Register
            createLabel(toAddr(epBase + 0x14), "EP" + i + "DPR", true);   // Endpoint Data Present Register
        }
    }
}
