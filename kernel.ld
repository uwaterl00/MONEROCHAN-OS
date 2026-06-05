/* kernel.ld — Protheus OS linker script
 *
 * Target: RISC-V rv32ima, QEMU "virt" machine.
 *
 * Memory map (QEMU virt):
 *   0x00001000  ROM  (OpenSBI / BIOS reset vector)
 *   0x80000000  RAM  start (OpenSBI loads and runs from here)
 *   0x80200000  RAM  where OpenSBI jumps to the next-stage payload (us)
 *   0x88000000  RAM  end   (128 MiB total: 0x80000000 + 0x08000000)
 *
 * We place the kernel at 0x80200000 and use everything above the stack
 * as the physical page allocator heap.
 */

ENTRY(boot)   /* reset entry point: the boot() function in kernel.c */

SECTIONS {

    /* ── Kernel load address ──────────────────────────────────────────── */
    /* 0x80200000 is where OpenSBI jumps after firmware initialisation.   */
    . = 0x80200000;

    /* ── .text : executable code ─────────────────────────────────────── */
    .text : {
        /* boot() must be the very first bytes at 0x80200000 so OpenSBI   */
        /* jumps directly into our reset stub.                            */
        KEEP(*(.text.boot))

        /* All other code sections follow immediately after.              */
        *(.text .text.*)
    }

    /* ── .rodata : read-only data (string literals, const arrays) ─────── */
    .rodata : ALIGN(4) {
        *(.rodata .rodata.*)
    }

    /* ── .data : initialised read-write global/static variables ────────── */
    .data : ALIGN(4) {
        *(.data .data.*)
    }

    /* ── .shell : embedded fallback shell binary ────────────────────────
     * The Makefile uses llvm-objcopy to rename the shell.bin .data section
     * to .shell, then links it here.  The kernel references the generated
     * _binary_shell_bin_start / _binary_shell_bin_size symbols.          */
    .shell : ALIGN(4) {
        _binary_shell_bin_start = .;   /* C symbol: start of shell binary */
        KEEP(*(.shell))
        _binary_shell_bin_end   = .;   /* C symbol: one-past-end          */
        /* Size computed as a linker expression so kernel.c can use it    */
        _binary_shell_bin_size  = _binary_shell_bin_end - _binary_shell_bin_start;
    }

    /* ── .disk : embedded initial disk image (TAR with service binaries)
     * The Makefile embeds disk.img here via objcopy.                     */
    .disk : ALIGN(512) {
        _binary_disk_img_start = .;    /* start of embedded disk image    */
        KEEP(*(.disk))
        _binary_disk_img_end   = .;    /* end   of embedded disk image    */
    }

    /* ── Symbols used by the kernel for memory management ────────────── */
    /* Physical address of the first kernel instruction (used for         */
    /* identity-mapping the kernel region in every process page table).   */
    __kernel_base = 0x80200000;

    /* ── .bss : uninitialised (zero) globals ────────────────────────────
     * kernel_main() clears this range with memset() before use.         */
    .bss : ALIGN(4) {
        __bss = .;          /* start of BSS: kernel_main zeroes from here */
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;      /* end   of BSS                               */
    }

    /* ── Stack and heap layout ──────────────────────────────────────────
     * Align to a page boundary, then carve 128 KiB for the boot/idle
     * kernel stack.  Everything above __stack_top is the physical page
     * allocator heap used by alloc_pages().                             */
    . = ALIGN(4096);
    __stack_top   = . + 128K;       /* top of 128 KiB kernel stack        */
    __free_ram    = __stack_top;    /* heap starts immediately after stack */
    __free_ram_end = 0x88000000;    /* heap ends at top of QEMU virt RAM   */
}
