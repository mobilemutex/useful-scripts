/*
 * Linker script for MPC5674F Open Flash Loader
 * Author: mobilemutex
 *
 * This flash loader runs from internal SRAM at 0x40000000
 * The MPC5674F has 256KB of internal SRAM
 */

MEMORY
{
    /* Internal SRAM - use a portion for the flash loader */
    RAM (rwx) : ORIGIN = 0x40000000, LENGTH = 64K
}

/* Entry point */
ENTRY(Init)

SECTIONS
{
    /* Code section - must be first */
    .PrgCode : {
        . = ALIGN(4);
        *(.text)
        *(.text*)
        *(.rodata)
        *(.rodata*)
        . = ALIGN(4);
    } > RAM

    /* Data section */
    .PrgData : {
        . = ALIGN(4);
        *(.data)
        *(.data*)
        . = ALIGN(4);
    } > RAM

    /* BSS section */
    .bss : {
        . = ALIGN(4);
        __bss_start__ = .;
        *(.bss)
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        __bss_end__ = .;
    } > RAM

    /* Device descriptor - must be last */
    .DevDscr : {
        . = ALIGN(4);
        KEEP(*(.rodata.FlashDevice))
        KEEP(*(FlashDevice))
        . = ALIGN(4);
    } > RAM

    /* Stack */
    .stack : {
        . = ALIGN(8);
        . = . + 512;  /* 512 bytes stack */
        __stack_top__ = .;
    } > RAM

    /* Discard unwanted sections */
    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.ARM.*)
    }
}
