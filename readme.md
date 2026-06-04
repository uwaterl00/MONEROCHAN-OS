# Protheus OS

**A freestanding RISC-V microkernel with capability-gated IPC for blockchain workloads.**

> Author: m26steph@uwaterloo.ca  
> Credits: Nicolae Carabut (Dispatch Labs) — architectural inspiration  
---

## Architecture

```
seL4 / Genode (long-term target)
│
├── kernel/          ← RISC-V rv32ima microkernel (SV32 paging, VirtIO-blk, TAR fs)
│   ├── common.{h,c} ← freestanding types, string, printf
│   ├── kernel.{h,c} ← scheduler, page tables, IPC, syscalls, boot
│   └── kernel.ld    ← linker script (QEMU virt, 0x80200000)
│
├── crypto/
│   ├── sha256.h     ← FIPS 180-4, header-only (lives in crypto_service only)
│   └── ed25519.h    ← Ed25519 stub (replace with Monocypher/SUPERCOP ref10)
│
└── services/
    ├── crypto/      ← crypto_service  (CAP_LOG only — key material stays here)
    ├── kv_store/    ← kv_store        (CAP_LOG only — FNV-1a hash table)
    ├── network/     ← network_service (CAP_LOG | CAP_TIMER — untrusted relay)
    └── monerod/     ← monerod         (CAP_ALL — orchestrator, sole inter-service router)
```

### IPC / Capability model

Every cross-service call is mediated by the kernel via `do_ipc_call`.  
The caller blocks; the target becomes runnable; on return the reply is copied back.

| Service          | Capabilities                              |
|------------------|-------------------------------------------|
| crypto_service   | `CAP_LOG`                                 |
| kv_store         | `CAP_LOG`                                 |
| network_service  | `CAP_LOG \| CAP_TIMER`                    |
| monerod          | `CAP_CRYPTO \| CAP_KVSTORE \| CAP_NETWORK \| CAP_TIMER \| CAP_LOG` |

An attacker who achieves RCE in `network_service` cannot reach `crypto_service` — there is no capability route.

### Data flow

```
network_service ──(raw block/TX)──► monerod
monerod ──(SHA-256 / Ed25519)─────► crypto_service
monerod ──(store block/mempool)───► kv_store
monerod ──(broadcast signed TX)───► network_service
```

### MLIR compilation path (planned)

```
Lean 4 source
  └─ Lean IR
       └─ MLIR (custom high-level dialect)
            └─ MLIR lowering passes
                 └─ LLVM IR
                      └─ riscv32 machine code
```

This path enables formal proofs in Lean 4 to be compiled to the same binary running on this kernel, bridging formal verification with the capability-enforced isolation layer.

---

## Build & Run

```bash
# Prerequisites (Debian/Ubuntu example)
sudo apt install clang lld qemu-system-riscv

# Build
make

# Run under QEMU
make run

# GDB debug
make qemu-debug   # then: riscv32-elf-gdb protheus.elf -ex "target remote :1234"
```

---

## Production TODOs

- Replace `ed25519.h` stub with [Monocypher](https://monocypher.org/) (CC0, audited).
- Replace `network_service` stub block/TX with real Monero P2P wire protocol (Boost.Serialization / levin).
- Port to seL4 + Genode for formally-verified microkernel guarantees.
- Integrate Zig stdlib's generated (Coq-derived) crypto for post-quantum primitives.
- Add a hardware entropy source (RISC-V TRNG extension or TPM) for key seeding.
- Persistent kv_store: flush to VirtIO disk via a dedicated file in the TAR image.
