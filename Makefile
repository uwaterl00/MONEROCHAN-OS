# Protheus OS — Build System
#
# Author:  m26steph@uwaterloo.ca
# Credits: Nicolae Carabut (Dispatch Labs) — architectural inspiration
#
# Requirements:
#   riscv64-unknown-elf-gcc  (or clang --target=riscv32-unknown-elf)
#   qemu-system-riscv32
#   llvm-objcopy (or riscv64-unknown-elf-objcopy)

CC      := clang
CFLAGS  := --target=riscv32-unknown-elf -march=rv32ima -mabi=ilp32   \
            -fno-stack-protector -ffreestanding -nostdlib              \
            -Wall -Wextra -Wno-unused-parameter                        \
            -Ikernel -Icrypto -Iservices

LD      := ld.lld
LDFLAGS := -m elf32lriscv -T kernel/kernel.ld --gc-sections

OBJCOPY := llvm-objcopy
QEMU    := qemu-system-riscv32

# ── Sources ─────────────────────────────────────────────────────────────
KERNEL_SRC := kernel/kernel.c kernel/common.c
SHELL_SRC  := shell/shell.c   # tiny built-in shell binary (see shell/shell.c)

SVC_CRYPTO  := services/crypto/crypto_service.c
SVC_KV      := services/kv_store/kv_store.c
SVC_NET     := services/network/network_service.c
SVC_MONO    := services/monerod/monerod.c

# ── Targets ──────────────────────────────────────────────────────────────
.PHONY: all clean run qemu-debug

all: protheus.elf

# Build each service as a flat binary embedded into the disk image
build/crypto_service.bin: $(SVC_CRYPTO)
	@mkdir -p build
	$(CC) $(CFLAGS) -o build/crypto_service.elf $^ $(LDFLAGS)
	$(OBJCOPY) -O binary build/crypto_service.elf $@

build/kv_store.bin: $(SVC_KV)
	@mkdir -p build
	$(CC) $(CFLAGS) -o build/kv_store.elf $^ $(LDFLAGS)
	$(OBJCOPY) -O binary build/kv_store.elf $@

build/network_service.bin: $(SVC_NET)
	@mkdir -p build
	$(CC) $(CFLAGS) -o build/network_service.elf $^ $(LDFLAGS)
	$(OBJCOPY) -O binary build/network_service.elf $@

build/monerod.bin: $(SVC_MONO)
	@mkdir -p build
	$(CC) $(CFLAGS) -o build/monerod.elf $^ $(LDFLAGS)
	$(OBJCOPY) -O binary build/monerod.elf $@

# Pack service binaries into a ustar disk image
disk.img: build/crypto_service.bin build/kv_store.bin \
           build/network_service.bin build/monerod.bin
	tar --format=ustar \
	    -cf $@                                   \
	    --transform 's|build/||'                 \
	    build/crypto_service.bin                 \
	    build/kv_store.bin                       \
	    build/network_service.bin                \
	    build/monerod.bin

# Shell binary (fallback when no monerod image on disk)
build/shell.bin: shell/shell.c
	@mkdir -p build
	$(CC) $(CFLAGS) -o build/shell.elf $^ $(LDFLAGS)
	$(OBJCOPY) -O binary build/shell.elf $@

# Kernel — shell binary linked in via objcopy, disk image via -b binary
protheus.elf: $(KERNEL_SRC) build/shell.bin disk.img kernel/kernel.ld
	$(OBJCOPY) -I binary -O elf32-littleriscv               \
	    --rename-section .data=.shell                        \
	    build/shell.bin build/shell.o
	$(OBJCOPY) -I binary -O elf32-littleriscv               \
	    --rename-section .data=.disk                         \
	    disk.img build/disk.o
	$(CC) $(CFLAGS) -c kernel/kernel.c -o build/kernel.o
	$(CC) $(CFLAGS) -c kernel/common.c -o build/common.o
	$(LD) $(LDFLAGS) -o $@                                  \
	    build/kernel.o build/common.o build/shell.o build/disk.o

clean:
	rm -rf build protheus.elf disk.img

run: protheus.elf disk.img
	$(QEMU) -machine virt -bios default           \
	        -kernel protheus.elf                  \
	        -drive id=drive0,file=disk.img,if=none,format=raw \
	        -device virtio-blk-device,drive=drive0 \
	        -nographic

qemu-debug: protheus.elf disk.img
	$(QEMU) -machine virt -bios default           \
	        -kernel protheus.elf                  \
	        -drive id=drive0,file=disk.img,if=none,format=raw \
	        -device virtio-blk-device,drive=drive0 \
	        -nographic                            \
	        -s -S
