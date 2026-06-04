/* kernel.ld — Protheus OS linker script (RISC-V rv32ima, QEMU virt) */
ENTRY(boot)

SECTIONS {
    . = 0x80200000;

    .text : {
        KEEP(*(.text.boot))
        *(.text .text.*)
    }

    .rodata : ALIGN(4) { *(.rodata .rodata.*) }

    .data : ALIGN(4) { *(.data .data.*) }

    /* Shell binary embedded by objcopy */
    .shell : ALIGN(4) {
        _binary_shell_bin_start = .;
        KEEP(*(.shell))
        _binary_shell_bin_end = .;
        _binary_shell_bin_size = _binary_shell_bin_end - _binary_shell_bin_start;
    }

    __kernel_base = 0x80200000;

    .bss : ALIGN(4) {
        __bss = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    . = ALIGN(4096);
    __stack_top = . + 128K;

    __free_ram = __stack_top;
    __free_ram_end = 0x88000000;   /* 128 MiB QEMU virt RAM */
}
