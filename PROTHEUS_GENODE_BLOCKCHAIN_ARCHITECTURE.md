# Protheus OS - Genode Integration Architecture
## Building a Microkernel-Based Blockchain Operating System

**Date:** 2026-06-04  
**Framework:** Genode OS Framework  
**Primary Use Case:** Privacy-Focused Blockchain Infrastructure (Monero)

**Author:** m26steph@uwaterloo.ca  
**Based on ideas from:** Nicolae Carabut at Dispatch Labs (past donor)  
**License:** The Free License (https://github.com/codemodify/TheFreeLicense)

---

## Executive Summary

This document provides a complete architectural redesign of Protheus OS, transforming it from a Linux Kernel-based system to a Genode OS Framework-based microkernel platform. The new architecture leverages Genode's capability-based security model to create isolated user-space services for blockchain operations, particularly suited for Monero deployment.

**Key Benefits:**
- Fine-grained capability-based security model
- Isolation between blockchain components
- Reduced attack surface vs. Linux
- Better support for specialized services (crypto, networking, storage)
- Deterministic, auditable component interactions

---

## Architecture Overview

### 1. System Layers

```
┌─────────────────────────────────────────────────────┐
│ Applications Layer                                   │
│ ├─ Monero Daemon (monerod)                          │
│ ├─ Wallet Services                                  │
│ ├─ RPC Gateway                                      │
│ └─ Management Console                               │
├─────────────────────────────────────────────────────┤
│ Service Layer (Capability-Based Isolation)          │
│ ├─ P2P Network Service                              │
│ ├─ Blockchain Consensus Engine                      │
│ ├─ LMDB Storage Server                              │
│ ├─ Cryptography Service (libsodium)                 │
│ ├─ RPC/Protocol Handler                             │
│ └─ Key Management Service                           │
├─────────────────────────────────────────────────────┤
│ Core Platform Layer                                 │
│ ├─ VFS (Virtual File System)                        │
│ ├─ Terminal/Console                                 │
│ ├─ Network Stack (NIC Bridge)                       │
│ ├─ Block I/O Multiplexer                            │
│ └─ Platform Driver Manager                          │
├─────────────────────────────────────────────────────┤
│ Genode Core / Microkernel                           │
│ ├─ Process/Thread Management                        │
│ ├─ Capability Management                            │
│ ├─ Interrupt Handling                               │
│ └─ Memory Management & Protection                   │
├─────────────────────────────────────────────────────┤
│ Hardware Abstraction (HAL)                          │
│ ├─ CPU drivers (x86_64, ARM, RISC-V)               │
│ ├─ Memory Management                                │
│ ├─ Device I/O (PCI, I2C, SPI)                      │
│ └─ Platform-specific code                           │
└─────────────────────────────────────────────────────┘
```

### 2. Component Hierarchy & Capabilities

The system follows a parent-child component tree with explicit capability delegation:

```
init (root)
 │
 ├─ logger          [Logging service for all components]
 │
 ├─ platform_drv    [Platform driver - manages hardware]
 │
 ├─ nic_drv         [Network interface driver]
 │   └─ nic_bridge   [NIC multiplexer]
 │
 ├─ block_drv       [Block device driver]
 │   └─ block_session[Storage session provider]
 │
 ├─ vfs_server      [Virtual File System server]
 │   ├─ ram_fs      [RAM filesystem]
 │   ├─ log_fs      [Log filesystem]
 │   └─ ext2_fs     [Optional persistent filesystem]
 │
 ├─ crypto_service  [Cryptography service]
 │   └─ libsodium   [Linked in-process]
 │
 ├─ kv_store        [LMDB key-value store server]
 │   └─ [vfs_server dependency]
 │
 ├─ network_service [P2P networking]
 │   ├─ [nic_bridge dependency]
 │   └─ [logger dependency]
 │
 ├─ consensus_engine[Blockchain validation]
 │   ├─ [crypto_service dependency]
 │   ├─ [kv_store dependency]
 │   └─ [logger dependency]
 │
 ├─ monerod         [Monero daemon - top-level]
 │   ├─ [network_service dependency]
 │   ├─ [consensus_engine dependency]
 │   ├─ [kv_store dependency]
 │   ├─ [crypto_service dependency]
 │   └─ [logger dependency]
 │
 ├─ rpc_gateway     [RPC server]
 │   └─ [monerod service dependency]
 │
 └─ admin_console   [Management interface]
     └─ [monerod service dependency]
```

---

## Detailed Component Specifications

### 2.1 Blockchain Core Components

#### Monero Daemon (monerod)

**Role:** Main blockchain node  
**Language:** C++ (leveraging existing Monero codebase)  
**Resources:**
- CPU quota: 2-4 cores
- Memory: 2-4 GB (dynamic)
- Storage: Access to block chain DB via KV store service

**Config:**
```xml
<start name="monerod" caps="200">
  <resource name="RAM" quantum="2G"/>
  <resource name="CPU" quantum="75"/>
  
  <config>
    <vfs>
      <dir name="dev">
        <log/>
      </dir>
    </vfs>
    <libc stdout="/dev/log" stderr="/dev/log"/>
  </config>
  
  <route>
    <service name="Nic">           <child name="nic_bridge"/>   </service>
    <service name="Terminal">      <child name="terminal"/>     </service>
    <service name="Report">        <child name="report_rom"/>   </service>
    <service name="ROM">           <parent/>                    </service>
    <service name="CPU">           <parent/>                    </service>
    <service name="PD">            <parent/>                    </service>
    <service name="IO_MEM">        <parent/>                    </service>
    <service name="IO_PORT">       <parent/>                    </service>
    <service name="IRQ">           <parent/>                    </service>
    <service name="SIGNAL">        <parent/>                    </service>
    <service name="CAP">           <parent/>                    </service>
  </route>
</start>
```

#### Cryptography Service

**Role:** Centralized crypto operations (signatures, hashing, key derivation)  
**Implementation:** libsodium + custom Monero crypto functions  
**Security Model:** Isolated from main daemon, all crypto requests go through RPC

**API Interface:**
```cpp
struct crypto_request {
  enum op_type {
    HASH_KECCAK,
    SIGN_RING,
    VERIFY_SIGNATURE,
    KEY_DERIVE,
    ENCRYPT_CHACHA,
    DECRYPT_CHACHA
  } operation;
  
  std::vector<uint8_t> input;
  std::vector<uint8_t> key;
  // Additional fields per operation
};

struct crypto_response {
  int status;
  std::vector<uint8_t> output;
  uint64_t processing_time_us;
};
```

#### Consensus Engine

**Role:** Block validation, chain verification, fork detection  
**Features:**
- Parallel block validation
- Double-spend detection
- Orphan block management
- Fork consensus resolution

**State Management:**
- Chain height tracking
- Best chain pointer
- Pending transaction pool
- Block validity cache

#### P2P Network Service

**Role:** Manage peer connections, gossip protocol  
**Functions:**
- Connection pooling
- Message routing
- Peer scoring
- DDoS mitigation
- Latency measurement

```cpp
class P2PService {
  void connect_peer(const std::string& address, uint16_t port);
  void broadcast_transaction(const std::string& tx_hash);
  void broadcast_block(const std::string& block_hash);
  std::vector<PeerInfo> get_peer_list();
  void ban_peer(const std::string& peer_id, uint64_t duration_sec);
};
```

#### Key-Value Store Server (LMDB)

**Role:** Persistent storage backend  
**Technology:** Lightning Memory-Mapped Database (LMDB)  
**Databases:**
- blockchain (blocks)
- transactions (tx_pool, historical)
- accounts (balances, nonces)
- metadata (sync state, checkpoints)

**VFS Integration:**
```
/kv/
├─ blockchain/
├─ transactions/
├─ accounts/
└─ metadata/
```

---

## 2.2 Protheus Template System (Redesigned)

The template system is restructured to support Genode component composition:

```
/Templates/
├─ System/
│   ├─ Boot/
│   │   └─ genode-init.xml
│   ├─ Kernel/
│   │   ├─ core.config
│   │   └─ hypervisor.config (optional)
│   ├─ Drivers/
│   │   ├─ platform_drv.config
│   │   ├─ nic_drv.config
│   │   └─ block_drv.config
│   ├─ Core/
│   │   ├─ logger.config
│   │   └─ rom_server.config
│   └─ Network/
│       ├─ nic_bridge.config
│       └─ firewall.config
│
├─ Services/
│   ├─ Crypto/
│   │   ├─ libsodium.config
│   │   └─ monero_crypto_service.config
│   ├─ Storage/
│   │   ├─ vfs.config
│   │   ├─ lmdb_server.config
│   │   └─ block_cache.config
│   ├─ Network/
│   │   └─ p2p_service.config
│   └─ Blockchain/
│       ├─ consensus_engine.config
│       └─ transaction_pool.config
│
├─ Applications/
│   ├─ monerod.config
│   ├─ wallet.config
│   ├─ rpc_gateway.config
│   └─ monitor.config
│
└─ Overlays/
    ├─ Development/  (verbose logging, debug ports)
    ├─ Production/   (minimal logging, hardened)
    └─ TestNet/      (testnet parameters)
```

### Template Inheritance & Composition

Templates use XML include mechanism for composition:

```xml
<!-- monerod.config -->
<config>
  <include path="/Templates/System/Boot/genode-init.xml"/>
  <include path="/Templates/Services/Crypto/libsodium.config"/>
  <include path="/Templates/Services/Storage/lmdb_server.config"/>
  <include path="/Templates/Services/Network/p2p_service.config"/>
  
  <start name="monerod" ...>
    <!-- Monero-specific configuration -->
  </start>
</config>
```

---

## 3. Data Flow Architecture

### 3.1 Transaction Flow

```
┌─────────────┐
│   Wallet    │ (External or in-app)
└──────┬──────┘
       │ broadcast_transaction()
       │
       ▼
┌─────────────────────────┐
│  RPC Gateway            │
│  - Validates format     │
│  - Rate limiting        │
└──────┬──────────────────┘
       │ submit(tx)
       │
       ▼
┌─────────────────────────┐
│  Monero Daemon          │
│  - Signature check      │
│  - Double-spend check   │
│  - Fee calculation      │
└──────┬──────────────────┘
       │ add_to_mempool()
       │
       ▼
┌─────────────────────────┐
│  Transaction Pool       │
│  Service                │
└──────┬──────────────────┘
       │ relay_to_peers()
       │
       ▼
┌─────────────────────────┐
│  P2P Network Service    │
│  - Broadcast to peers   │
│  - Handle responses     │
└─────────────────────────┘
```

### 3.2 Block Processing Flow

```
┌──────────────────┐
│  P2P Network     │ receives block announcement
└────────┬─────────┘
         │ fetch_block()
         │
         ▼
┌──────────────────────────┐
│ Consensus Engine         │
│ - Validate header        │
│ - Check PoW              │
│ - Verify transactions    │
└────────┬─────────────────┘
         │
         ├─ Fetch missing transactions from pool
         │ (via mempool queries)
         │
         ├─ Verify signatures (via Crypto Service)
         │
         └─ Check double-spends (via KV Store queries)
         │
         ▼
    [VALID]  or  [INVALID]
         │              │
         │              └─> Reject, ban peer
         │
         ▼
┌──────────────────────────┐
│  KV Store Server         │
│  - Write block           │
│  - Update chain state    │
│  - Remove confirmed TXs  │
└──────────────────────────┘
```

---

## 4. Security Model

### 4.1 Capability-Based Access Control

Every component has explicit capabilities:

```cpp
// Each service publishes capabilities
struct ServiceCapabilities {
  Cap network_access;      // Can access nic_bridge
  Cap storage_access;      // Can access vfs_server
  Cap crypto_access;       // Can call crypto_service
  Cap logging_access;      // Can write to logger
};

// Parent grants specific capabilities to children
void init::grant_capabilities(Child* child, const ServiceCapabilities& caps) {
  child->grant_cap(caps.network_access);
  child->grant_cap(caps.storage_access);
  // etc.
}
```

### 4.2 Isolation Boundaries

```
┌─────────────────────────────────────────────────┐
│ monerod (Capability Domain)                      │
├─────────────────────────────────────────────────┤
│ Can call:                                        │
│ - crypto_service (read-only crypto ops)        │
│ - kv_store (read-write blockchain DB)          │
│ - network_service (peer management)            │
│ - rpc_gateway (RPC interface)                   │
│                                                  │
│ Cannot:                                          │
│ - Access raw block devices                      │
│ - Bypass signature checks                       │
│ - Access network without routing service       │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│ crypto_service (Capability Domain)              │
├─────────────────────────────────────────────────┤
│ Can call:                                        │
│ - logger (output results)                       │
│                                                  │
│ Cannot:                                          │
│ - Access network                                │
│ - Access storage                                │
│ - Call any other service                        │
│ (Prevents key exfiltration)                     │
└─────────────────────────────────────────────────┘
```

### 4.3 Threat Model Coverage

| Threat | Mitigation | Location |
|--------|-----------|----------|
| Memory corruption in app | Process boundary, MMU protection | Genode core |
| Unauthorized network access | Nic_bridge capability filtering | Network layer |
| Cryptographic key theft | Isolated crypto_service, no persistent keys | Service isolation |
| Chain reorganization attack | Consensus engine, immutable block DB | Consensus engine |
| P2P poisoning | Peer scoring in network_service | P2P layer |
| Storage corruption | LMDB transactions, journaling | KV store |

---

## 5. Deployment Configurations

### 5.1 Production Configuration

**Minimal footprint, maximum security:**

```xml
<init>
  <!-- Core only -->
  <start name="logger"/>
  <start name="platform_drv"/>
  <start name="nic_drv"/>
  <start name="block_drv"/>
  
  <!-- Services -->
  <start name="vfs_server"/> 
  <start name="crypto_service"/>
  <start name="kv_store"/>
  <start name="network_service"/>
  <start name="consensus_engine"/>
  
  <!-- Application -->
  <start name="monerod">
    <config>
      <network>
        <port>18080</port>
        <bind-address>0.0.0.0</bind-address>
      </network>
      <blockchain>
        <db-path>/db/blockchain</db-path>
        <sync-mode>full</sync-mode>
      </blockchain>
    </config>
  </start>
</init>
```

**Resource allocation:**
- CPU: 4-8 cores
- RAM: 4-8 GB
- Storage: 100+ GB (full blockchain)
- Network: 1+ Mbps

### 5.2 Development Configuration

**Includes debugging, monitoring, detailed logging:**

```xml
<init>
  <!-- All of production, plus: -->
  <start name="terminal">
    <config>
      <keyboard layout="en"/>
      <font size="12"/>
    </config>
  </start>
  
  <start name="gdb_monitor"/>
  
  <start name="monitor">
    <!-- Real-time CPU, memory, network stats -->
  </start>
  
  <start name="monerod">
    <config>
      <logging level="debug"/>
      <profiling enabled="true"/>
      <gdb-port>1234</gdb-port>
    </config>
  </start>
</init>
```

### 5.3 Testnet Configuration

```xml
<init>
  <!-- Same as production, but: -->
  <start name="monerod">
    <config>
      <blockchain>
        <network>testnet</network>
        <genesis-hash>...</genesis-hash>
        <difficulty-target>120</difficulty-target>
      </blockchain>
      <p2p>
        <seed-nodes>
          <node address="testnet-node1.example.com" port="28080"/>
        </seed-nodes>
      </p2p>
    </config>
  </start>
</init>
```

---

## 6. Integration with Protheus Template System

### 6.1 Template Application Workflow

1. **Select Base Configuration**
   ```bash
   protheus init --framework genode --base-config production
   ```

2. **Load Blockchain Stack Template**
   ```bash
   protheus template load /Templates/Services/Blockchain/*
   protheus template load /Templates/Applications/monerod.config
   ```

3. **Apply Overlay (e.g., Hardened)**
   ```bash
   protheus overlay apply Production
   ```

4. **Generate Integrated Config**
   ```bash
   protheus generate-config --output /boot/genode.config
   ```

5. **Build System Image**
   ```bash
   protheus build --target x86_64 --image-type iso
   ```

### 6.2 Runtime Template Modifications

**Without reboot - update service config:**
```bash
protheus template update crypto_service --key performance.threads --value 4
protheus apply-config
```

**With validation:**
```bash
protheus validate-config /Templates/Services/*/
protheus apply-config --with-rollback
```

---

## 7. Build & Compilation

### 7.1 Build System Integration

**Leverage Genode's build system:**

```bash
# Download Genode
git clone https://github.com/genodelabs/genode.git
cd genode

# Create Protheus-specific build directory
mkdir -p build/protheus_x86_64

# Build Genode core + services
make -C build/protheus_x86_64 \
  BOARD=pc \
  KERNEL=nova \
  deps

# Build Monero integration layer
make -C build/protheus_x86_64 \
  target=monero_genode

# Create system image
make -C build/protheus_x86_64 \
  system-image.iso
```

### 7.2 Cross-Compilation Targets

Support for multiple platforms:

```
x86_64:      (QEMU, VirtualBox, Bare Metal) - Primary
ARM (v7/v8): (RaspberryPi, Orange Pi, etc.)
RISC-V:      (HiFive Unleashed, QEMU)
```

---

## 8. Monitoring & Management

### 8.1 System Monitoring Service

```cpp
class SystemMonitor {
  struct ComponentMetrics {
    std::string name;
    uint64_t cpu_time_ms;
    uint64_t memory_bytes;
    uint64_t network_bytes_in;
    uint64_t network_bytes_out;
    uint32_t capability_count;
  };
  
  std::vector<ComponentMetrics> get_all_metrics();
  void set_resource_limits(const std::string& component, Limits);
};
```

### 8.2 Log Aggregation

Central logger collects logs from all services:

```
Logger (Central)
├─ platform_drv logs
├─ nic_drv logs
├─ crypto_service logs
├─ monerod logs
└─ network_service logs

Output to:
- /var/log/system.log (rotating)
- /dev/ttyS0 (serial console)
- Remote syslog server (optional)
```

### 8.3 Admin Console

Web-based or CLI management:

```bash
# Via CLI
protheus admin show-stats
protheus admin restart-service crypto_service
protheus admin set-capability monerod network.bandwidth=100Mbps
protheus admin show-logs --service monerod --follow

# Via Web Interface (optional)
# http://localhost:19000/admin/
```

---

## 9. Blockchain-Specific Optimizations

### 9.1 LMDB Configuration

**Tuned for blockchain workloads:**

```cpp
struct LmdbConfig {
  static constexpr size_t MAP_SIZE = 100UL << 30;  // 100 GB
  static constexpr uint32_t MAX_READERS = 128;
  static constexpr uint32_t MAX_DBS = 32;
  
  // Batch writes for better throughput
  static constexpr bool BATCH_WRITES = true;
  static constexpr size_t BATCH_SIZE = 10000;  // 10k TXs
};
```

### 9.2 Cryptography Acceleration

If hardware supports:

```cpp
#ifdef HAVE_AES_NI
  use_hardware_aes_ni();
#endif

#ifdef HAVE_AVX2
  use_simd_hashing();
#endif

#ifdef HAVE_AVX512
  use_avx512_crypto();
#endif
```

### 9.3 Network Optimizations

```cpp
// P2P service tuning
struct NetworkConfig {
  static constexpr uint32_t CONNECTION_POOL_SIZE = 32;
  static constexpr uint64_t PEER_GRACE_PERIOD_MS = 3600000;  // 1 hour
  static constexpr uint32_t MAX_BLOCK_SIZE = 500000;  // Monero mainnet
};
```

---

## 10. Migration Path from Linux to Genode

### Phase 1: Parallel Development (Weeks 1-4)
- Set up Genode build environment
- Port critical libraries (libsodium, LMDB)
- Create basic service skeleton

### Phase 2: Core Services (Weeks 5-8)
- Implement crypto_service
- Implement kv_store with LMDB
- Implement network_service

### Phase 3: Integration (Weeks 9-12)
- Port consensus engine
- Integrate with monerod
- Testing & benchmarking

### Phase 4: Hardening (Weeks 13-16)
- Security audit
- Performance optimization
- Production deployment

---

## 11. Example Configurations

### 11.1 Single-Node Full Node

```xml
<?xml version="1.0"?>
<config>
  <parent-provides>
    <service name="CPU"/>
    <service name="IO_MEM"/>
    <service name="IO_PORT"/>
    <service name="IRQ"/>
    <service name="PD"/>
    <service name="RM"/>
    <service name="LOG"/>
    <service name="SIGNAL"/>
  </parent-provides>

  <start name="timer">
    <resource name="CPU" quantum="5"/>
    <resource name="RAM" quantum="1M"/>
  </start>

  <start name="logger">
    <resource name="CPU" quantum="5"/>
    <resource name="RAM" quantum="5M"/>
  </start>

  <start name="platform_drv">
    <resource name="CPU" quantum="10"/>
    <resource name="RAM" quantum="10M"/>
  </start>

  <start name="nic_drv" caps="100">
    <resource name="CPU" quantum="10"/>
    <resource name="RAM" quantum="50M"/>
  </start>

  <start name="vfs_server">
    <resource name="CPU" quantum="10"/>
    <resource name="RAM" quantum="100M"/>
    <config>
      <vfs>
        <dir name="fs">
          <fs label="root"/>
        </dir>
        <dir name="log"> <log/> </dir>
      </vfs>
      <policy label="monerod" root="/fs"/>
    </config>
  </start>

  <start name="crypto_service" caps="100">
    <resource name="CPU" quantum="50"/>
    <resource name="RAM" quantum="256M"/>
    <config>
      <libsodium version="1.0.18"/>
    </config>
  </start>

  <start name="kv_store" caps="100">
    <resource name="CPU" quantum="100"/>
    <resource name="RAM" quantum="2G"/>
    <config>
      <lmdb>
        <database name="blockchain" flags="readonly-on-secondary"/>
        <database name="transactions"/>
        <database name="accounts"/>
      </lmdb>
    </config>
  </start>

  <start name="network_service" caps="150">
    <resource name="CPU" quantum="100"/>
    <resource name="RAM" quantum="512M"/>
    <config>
      <p2p>
        <listen-port>18080</listen-port>
        <max-peers>32</max-peers>
      </p2p>
    </config>
  </start>

  <start name="monerod" caps="200">
    <resource name="CPU" quantum="200"/>
    <resource name="RAM" quantum="4G"/>
    <config>
      <blockchain>
        <sync-mode>full</sync-mode>
        <verify-signatures>true</verify-signatures>
        <prune-mode>disabled</prune-mode>
      </blockchain>
      <logging>
        <level>info</level>
        <output>/var/log/monerod.log</output>
      </logging>
    </config>
    <route>
      <service name="Nic">       <child name="network_service"/> </service>
      <service name="File_system"> <child name="vfs_server"/>     </service>
      <service name="Crypto">    <child name="crypto_service"/>  </service>
      <service name="Kv_store">  <child name="kv_store"/>        </service>
      <service name="LOG">       <child name="logger"/>          </service>
    </route>
  </start>

  <start name="rpc_gateway" caps="100">
    <resource name="CPU" quantum="50"/>
    <resource name="RAM" quantum="256M"/>
    <config>
      <rpc>
        <listen-address>127.0.0.1</listen-address>
        <listen-port>18081</listen-port>
        <max-clients>10</max-clients>
      </rpc>
    </config>
  </start>
</config>
```

---

## 12. Testing Strategy

### Unit Tests
```bash
protheus test --type unit --component crypto_service
protheus test --type unit --component kv_store
```

### Integration Tests
```bash
protheus test --type integration --config production
protheus test --type integration --scenario "block-sync"
```

### Performance Tests
```bash
protheus bench --metric cpu --service monerod
protheus bench --metric memory --workload "process-1000-blocks"
protheus bench --metric network --scenario "p2p-broadcast"
```

---

## 13. Conclusion & Next Steps

This architecture provides:

1. **Security**: Capability-based isolation between components
2. **Performance**: Specialized services optimized for blockchain workloads
3. **Auditability**: Deterministic component interactions, clear dependencies
4. **Flexibility**: Template system allows configuration without recompilation
5. **Reliability**: Fault isolation prevents cascade failures

**Immediate next steps:**
1. Set up Genode build environment
2. Port libsodium and LMDB to Genode
3. Create service framework
4. Implement crypto_service proof-of-concept
5. Iterative integration with Monero daemon

---

**Author:** m26steph@uwaterloo.ca  
**Based on ideas from:** Nicolae Carabut at Dispatch Labs (past donor)  
**License:** The Free License (https://github.com/codemodify/TheFreeLicense)  
**Repository:** [GitHub - Protheus Genode Integration]
