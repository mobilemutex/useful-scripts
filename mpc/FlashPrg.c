/*
 * MPC5674F Open Flash Loader
 * 
 * Copyright (c) 2026, mobilemutex
 * All rights reserved.
 *
 * This flash loader implements the CMSIS-style flash algorithm interface
 * for the NXP MPC5674F microcontroller's internal flash memory.
 *
 * Flash Memory Organization:
 * - Flash_A: 2 MB (0x00000000 - 0x001FFFFF)
 *   - Low:  256 KB (8x16KB + 2x64KB)
 *   - Mid:  256 KB (2x128KB)
 *   - High: 1.5 MB (6x256KB)
 * - Flash_B: 2 MB (0x00200000 - 0x003FFFFF)
 *   - Low:  256 KB (1x256KB)
 *   - Mid:  256 KB (1x256KB)
 *   - High: 1.5 MB (6x256KB)
 */

#include "FlashOS.h"

/*
 * MPC5674F Flash Controller Register Definitions
 */

/* Flash_A Controller Base Address */
#define FLASH_A_BASE    0xC3F88000UL

/* Flash_B Controller Base Address */
#define FLASH_B_BASE    0xC3F8C000UL

/* Flash Controller Register Offsets */
#define FLASH_MCR       0x00    /* Module Configuration Register */
#define FLASH_LMLR      0x04    /* Low/Mid Address Space Block Locking Register */
#define FLASH_HLR       0x08    /* High Address Space Block Locking Register */
#define FLASH_SLMLR     0x0C    /* Secondary Low/Mid Address Space Block Locking Register */
#define FLASH_LSR       0x10    /* Low Address Space Block Select Register */
#define FLASH_MSR       0x14    /* Mid Address Space Block Select Register */
#define FLASH_HSR       0x18    /* High Address Space Block Select Register */
#define FLASH_AR        0x1C    /* Address Register */

/* MCR Register Bit Definitions */
#define MCR_EHV         (1UL << 0)   /* Enable High Voltage */
#define MCR_ESUS        (1UL << 4)   /* Erase Suspend */
#define MCR_ERS         (1UL << 5)   /* Erase */
#define MCR_PSUS        (1UL << 8)   /* Program Suspend */
#define MCR_PGM         (1UL << 9)   /* Program */
#define MCR_DONE        (1UL << 10)  /* State Machine Status */
#define MCR_PEG         (1UL << 11)  /* Program/Erase Good */

/* Memory-mapped register access macros */
#define REG32(base, offset) (*(volatile U32*)((base) + (offset)))

/* Flash array boundaries */
#define FLASH_A_START   0x00000000UL
#define FLASH_A_END     0x001FFFFFUL
#define FLASH_B_START   0x00200000UL
#define FLASH_B_END     0x003FFFFFUL

/* Timeout values */
#define TIMEOUT_ERASE   100000000UL
#define TIMEOUT_PROGRAM 10000000UL

/*
 * Flash Device Structure
 * 
 * This structure describes the flash memory layout to J-Link.
 * It must be placed in a specific section for the flash loader to work.
 */
__attribute__((section(".rodata.FlashDevice")))
__attribute__((used))
const struct FlashDevice FlashDevice = {
    0x0101,                     /* AlgoVer - must be 0x0101 */
    "MPC5674F Internal Flash",  /* Name */
    ONCHIP,                     /* Type - on-chip flash */
    0x00000000,                 /* BaseAddr */
    0x00400000,                 /* TotalSize - 4 MB */
    8,                          /* PageSize - 8 bytes (double-word) */
    0,                          /* Reserved */
    0xFF,                       /* ErasedVal */
    100,                        /* TimeoutProg - 100 ms per page */
    10000,                      /* TimeoutErase - 10 seconds per sector */
    /* Sector layout - simplified to uniform 256KB sectors */
    {
        { 0x00040000, 0x00000000 },  /* 16 x 256 KB sectors */
        { 0xFFFFFFFF, 0xFFFFFFFF }   /* End of list marker */
    }
};

/*
 * Get the flash controller base address for a given flash address
 */
static U32 GetFlashBase(U32 addr)
{
    if (addr <= FLASH_A_END) {
        return FLASH_A_BASE;
    } else {
        return FLASH_B_BASE;
    }
}

/*
 * Wait for flash operation to complete
 * Returns: 0 on success, 1 on timeout
 */
static int WaitForDone(U32 flashBase, U32 timeout)
{
    volatile U32 mcr;
    
    while (timeout > 0) {
        mcr = REG32(flashBase, FLASH_MCR);
        if (mcr & MCR_DONE) {
            return 0;  /* Success */
        }
        timeout--;
    }
    
    return 1;  /* Timeout */
}

/*
 * Init - Initialize flash programming
 * 
 * Parameters:
 *   Addr - Base address of the flash
 *   Freq - Clock frequency in Hz
 *   Func - Function code (1=Erase, 2=Program, 3=Verify)
 * 
 * Returns: 0 on success
 */
int Init(U32 Addr, U32 Freq, U32 Func)
{
    /* No special initialization required for internal flash */
    /* The flash controller is always accessible */
    
    (void)Addr;
    (void)Freq;
    (void)Func;
    
    return 0;
}

/*
 * UnInit - De-initialize after flash programming
 * 
 * Parameters:
 *   Func - Function code (1=Erase, 2=Program, 3=Verify)
 * 
 * Returns: 0 on success
 */
int UnInit(U32 Func)
{
    /* No special de-initialization required */
    
    (void)Func;
    
    return 0;
}

/*
 * EraseChip - Erase the entire flash
 * 
 * Returns: 0 on success, 1 on error
 */
int EraseChip(void)
{
    volatile U32 mcr;
    
    /* Erase Flash_A */
    /* Select all blocks */
    REG32(FLASH_A_BASE, FLASH_LSR) = 0xFFFFFFFF;
    REG32(FLASH_A_BASE, FLASH_MSR) = 0xFFFFFFFF;
    REG32(FLASH_A_BASE, FLASH_HSR) = 0xFFFFFFFF;
    
    /* Set erase mode */
    mcr = REG32(FLASH_A_BASE, FLASH_MCR);
    REG32(FLASH_A_BASE, FLASH_MCR) = mcr | MCR_ERS;
    
    /* Write interlock (any write to flash array) */
    *(volatile U32*)FLASH_A_START = 0xFFFFFFFF;
    
    /* Start erase */
    mcr = REG32(FLASH_A_BASE, FLASH_MCR);
    REG32(FLASH_A_BASE, FLASH_MCR) = mcr | MCR_EHV;
    
    /* Wait for completion */
    if (WaitForDone(FLASH_A_BASE, TIMEOUT_ERASE)) {
        return 1;  /* Timeout */
    }
    
    /* Check result */
    mcr = REG32(FLASH_A_BASE, FLASH_MCR);
    if (!(mcr & MCR_PEG)) {
        return 1;  /* Erase failed */
    }
    
    /* Clear EHV and ERS */
    REG32(FLASH_A_BASE, FLASH_MCR) = mcr & ~MCR_EHV;
    mcr = REG32(FLASH_A_BASE, FLASH_MCR);
    REG32(FLASH_A_BASE, FLASH_MCR) = mcr & ~MCR_ERS;
    
    /* Erase Flash_B */
    REG32(FLASH_B_BASE, FLASH_LSR) = 0xFFFFFFFF;
    REG32(FLASH_B_BASE, FLASH_MSR) = 0xFFFFFFFF;
    REG32(FLASH_B_BASE, FLASH_HSR) = 0xFFFFFFFF;
    
    mcr = REG32(FLASH_B_BASE, FLASH_MCR);
    REG32(FLASH_B_BASE, FLASH_MCR) = mcr | MCR_ERS;
    
    *(volatile U32*)FLASH_B_START = 0xFFFFFFFF;
    
    mcr = REG32(FLASH_B_BASE, FLASH_MCR);
    REG32(FLASH_B_BASE, FLASH_MCR) = mcr | MCR_EHV;
    
    if (WaitForDone(FLASH_B_BASE, TIMEOUT_ERASE)) {
        return 1;
    }
    
    mcr = REG32(FLASH_B_BASE, FLASH_MCR);
    if (!(mcr & MCR_PEG)) {
        return 1;
    }
    
    REG32(FLASH_B_BASE, FLASH_MCR) = mcr & ~MCR_EHV;
    mcr = REG32(FLASH_B_BASE, FLASH_MCR);
    REG32(FLASH_B_BASE, FLASH_MCR) = mcr & ~MCR_ERS;
    
    return 0;
}

/*
 * EraseSector - Erase a single flash sector
 * 
 * Parameters:
 *   Addr - Address within the sector to erase
 * 
 * Returns: 0 on success, 1 on error
 * 
 * Note: This simplified implementation erases based on 256KB blocks.
 *       A production implementation should handle the actual sector
 *       layout of the MPC5674F flash.
 */
int EraseSector(U32 Addr)
{
    U32 flashBase;
    U32 blockSelect;
    U32 blockOffset;
    volatile U32 mcr;
    
    /* Determine which flash controller to use */
    flashBase = GetFlashBase(Addr);
    
    /* Calculate block offset within the flash array */
    if (Addr <= FLASH_A_END) {
        blockOffset = Addr;
    } else {
        blockOffset = Addr - FLASH_B_START;
    }
    
    /* Determine which block select register and bit to use */
    /* Simplified: assume 256KB blocks in high address space */
    blockSelect = 1UL << (blockOffset / 0x40000);
    
    /* Clear all block selects first */
    REG32(flashBase, FLASH_LSR) = 0;
    REG32(flashBase, FLASH_MSR) = 0;
    REG32(flashBase, FLASH_HSR) = 0;
    
    /* Select the appropriate block */
    if (blockOffset < 0x40000) {
        REG32(flashBase, FLASH_LSR) = blockSelect;
    } else if (blockOffset < 0x80000) {
        REG32(flashBase, FLASH_MSR) = blockSelect;
    } else {
        REG32(flashBase, FLASH_HSR) = blockSelect;
    }
    
    /* Set erase mode */
    mcr = REG32(flashBase, FLASH_MCR);
    REG32(flashBase, FLASH_MCR) = mcr | MCR_ERS;
    
    /* Write interlock */
    *(volatile U32*)Addr = 0xFFFFFFFF;
    
    /* Start erase */
    mcr = REG32(flashBase, FLASH_MCR);
    REG32(flashBase, FLASH_MCR) = mcr | MCR_EHV;
    
    /* Wait for completion */
    if (WaitForDone(flashBase, TIMEOUT_ERASE)) {
        return 1;
    }
    
    /* Check result */
    mcr = REG32(flashBase, FLASH_MCR);
    if (!(mcr & MCR_PEG)) {
        return 1;
    }
    
    /* Clear EHV and ERS */
    REG32(flashBase, FLASH_MCR) = mcr & ~MCR_EHV;
    mcr = REG32(flashBase, FLASH_MCR);
    REG32(flashBase, FLASH_MCR) = mcr & ~MCR_ERS;
    
    return 0;
}

/*
 * ProgramPage - Program a page of flash
 * 
 * Parameters:
 *   Addr - Destination address (must be 8-byte aligned)
 *   Sz   - Number of bytes to program (must be multiple of 8)
 *   pBuf - Pointer to source data
 * 
 * Returns: 0 on success, 1 on error
 */
int ProgramPage(U32 Addr, U32 Sz, U8 *pBuf)
{
    U32 flashBase;
    U32 i;
    volatile U32 mcr;
    U32 *pSrc = (U32*)pBuf;
    
    /* Determine which flash controller to use */
    flashBase = GetFlashBase(Addr);
    
    /* Program 8 bytes (double-word) at a time */
    for (i = 0; i < Sz; i += 8) {
        /* Set program mode */
        mcr = REG32(flashBase, FLASH_MCR);
        REG32(flashBase, FLASH_MCR) = mcr | MCR_PGM;
        
        /* Write data (interlock write + second word) */
        *(volatile U32*)(Addr + i) = *pSrc++;
        *(volatile U32*)(Addr + i + 4) = *pSrc++;
        
        /* Start programming */
        mcr = REG32(flashBase, FLASH_MCR);
        REG32(flashBase, FLASH_MCR) = mcr | MCR_EHV;
        
        /* Wait for completion */
        if (WaitForDone(flashBase, TIMEOUT_PROGRAM)) {
            return 1;
        }
        
        /* Check result */
        mcr = REG32(flashBase, FLASH_MCR);
        if (!(mcr & MCR_PEG)) {
            return 1;
        }
        
        /* Clear EHV and PGM */
        REG32(flashBase, FLASH_MCR) = mcr & ~MCR_EHV;
        mcr = REG32(flashBase, FLASH_MCR);
        REG32(flashBase, FLASH_MCR) = mcr & ~MCR_PGM;
    }
    
    return 0;
}

/*
 * Verify - Verify programmed data
 * 
 * Parameters:
 *   Addr - Start address to verify
 *   Sz   - Number of bytes to verify
 *   pBuf - Pointer to expected data
 * 
 * Returns: Address of first mismatch, or Addr+Sz if successful
 */
U32 Verify(U32 Addr, U32 Sz, U8 *pBuf)
{
    U32 i;
    
    for (i = 0; i < Sz; i++) {
        if (*(volatile U8*)(Addr + i) != pBuf[i]) {
            return Addr + i;  /* Return address of mismatch */
        }
    }
    
    return Addr + Sz;  /* Success - return end address */
}

/*
 * Read - Read data from flash
 * 
 * Parameters:
 *   Addr - Start address to read from
 *   Sz   - Number of bytes to read
 *   pBuf - Pointer to destination buffer
 * 
 * Returns: 0 on success
 * 
 * Note: For memory-mapped flash, J-Link can read directly.
 *       This function is provided for completeness and can be called
 *       by a debugger script if needed.
 */
int Read(U32 Addr, U32 Sz, U8 *pBuf)
{
    U32 i;
    
    for (i = 0; i < Sz; i++) {
        pBuf[i] = *(volatile U8*)(Addr + i);
    }
    
    return 0;
}
