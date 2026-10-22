# LACPForge Pro v1.0.0 — Architecture & Engineering Manual

## 1\. Executive Summary: The Link Aggregation Standard

The **Link Aggregation Control Protocol (LACP \- IEEE 802.1AX-2020 & IEEE 802.3ad)** is the vendor-neutral standard for bundling multiple full-duplex physical Ethernet links into a single logical channel (Port-Channel / Trunk / Bond):

1. **Bandwidth Multiplication**: Aggregates throughput across physical links (e.g. 8x 100GbE QSFP28 links form an 800 Gbps logical bundle).  
2. **Sub-Second Hardware Failover**: Rapidly redistributes traffic across surviving member links when an optical transceiver or fiber link fails (\<50ms with ASIC fast-failover).  
3. **Multi-Chassis Clustering (MLAG / vPC / EVPN ESI)**: Extends link aggregation across dual switch chasses, providing active-active dual-homed server connections without Spanning Tree port blocking.

       \[Switch A (vPC / MLAG)\]      \[Switch B (vPC / MLAG)\]

                  \\                    /

      100GbE Link 1 \\                / 100GbE Link 2

        (Actor Port 1)\\            / (Actor Port 2\)

                        \\        /

                    \+----------------+

                    |  Server / PD   |

                    |  Dual-Port NIC |

                    |  (Bond0 / ae0) |

                    \+----------------+

                 Aggregate: 200 Gbps LACP

---

## 2\. Protocol Specification & LACPDU Frame Structure

### 2.1 Ethernet Encapsulation

- **Destination Multicast MAC**: `01:80:C2:00:00:02` (Slow Protocols Multicast).  
- **EtherType**: `0x8809` (Slow Protocols).  
- **Subtype**: `0x01` (LACP) or `0x02` (Marker Protocol).  
- **Version**: `0x01` (or `0x02` in 802.1AX-2014).

### 2.2 TLV Format (Type-Length-Value)

- **TLV 1: Actor Information (Type 0x01, Length 0x14 / 20 bytes)**:  
  - Actor System Priority (2 bytes): Default 32768 (Lower value \= higher priority in determining which ports are active).  
  - Actor System MAC Address (6 bytes): Switch chassis MAC or shared virtual MLAG System ID.  
  - Actor Operational Key (2 bytes): Identifies links eligible for aggregation into the same bundle.  
  - Actor Port Priority (2 bytes): Determines active link selection when member count exceeds max-bundle limit.  
  - Actor Port Number (2 bytes): Local interface index.  
  - Actor State Byte (1 byte bitmask).  
  - Reserved (3 bytes null).  
- **TLV 2: Partner Information (Type 0x02, Length 0x14 / 20 bytes)**:  
  - Mirrored partner system priority, MAC, key, port priority, port number, and partner state byte.  
- **TLV 3: Collector Information (Type 0x03, Length 0x10 / 16 bytes)**:  
  - Max Delay (2 bytes in tens of microseconds) \+ 12 bytes reserved.  
- **TLV 0: Terminator (Type 0x00, Length 0x00)**.

### 2.3 LACP State Byte Decoding (The 8-Bit State Machine)

- **Bit 0: LACP\_Activity**: 1 \= Active (proactively sends LACPDUs), 0 \= Passive (only responds).  
- **Bit 1: LACP\_Timeout**: 1 \= Short (1 second heartbeat), 0 \= Long (30 second heartbeat).  
- **Bit 2: Aggregation**: 1 \= Link is aggregatable, 0 \= Individual port only.  
- **Bit 3: Synchronization**: 1 \= Link is IN\_SYNC (matched operational key & system ID), 0 \= OUT\_OF\_SYNC.  
- **Bit 4: Collecting**: 1 \= Receiving frame collector is active (ingress frames accepted).  
- **Bit 5: Distributing**: 1 \= Transmitting frame distributor is active (egress frames forwarded).  
- **Bit 6: Defaulted**: 1 \= Actor is using preconfigured default partner parameters.  
- **Bit 7: Expired**: 1 \= Actor timer has expired (waiting for partner LACPDU before dropping).

---

## 3\. Operational Headaches & Catastrophic Aggregation Failures

1. **Passive / Passive Negotiation Deadlocks**:  
   - If both the server and switch are left in default LACP Passive mode, neither side ever sends an initial LACPDU. The port-channel never forms, causing complete link isolation.  
   - *Mitigation*: Enforce **LACP Active mode** on all switch interfaces.  
2. **Unidirectional Blackholing (Collecting / Distributing Desync)**:  
   - If a fiber strand breaks unidirectionally, one switch might set Collecting=1 Distributing=1 while the peer drops to Collecting=0. Traffic sent towards the broken switch is silently discarded.  
   - *Mitigation*: Validate symmetrical state synchronization (0x3D / 0x3F) and short heartbeat timeouts.  
3. **Hash Polarization & Microburst Bottlenecks**:  
   - In multi-tier leaf-spine fabrics, if both spine and leaf switches use 2-tuple L2 MAC hashing, all traffic between two endpoints hashes to the exact same physical cable across every hop, causing 100% saturation on link \#1 while links \#2–\#8 sit idle.  
   - *Mitigation*: Enforce **5-tuple L3+L4 resilient hashing** (Src/Dst IP \+ TCP/UDP Port).  
4. **Degraded Bundle Oversubscription**:  
   - In an 8x 100GbE bundle (800 Gbps), if 7 cables fail and `min-links` is unset, the port-channel stays up at 100 Gbps (12.5% capacity), causing severe buffer exhaustion and silent packet drops.  
   - *Mitigation*: Enforce `lacp min-links` thresholds to tear down degraded bundles and trigger routing failover.  
5. **Multi-Chassis MLAG / vPC Split-Brain**:  
   - If peer switches in a vPC pair advertise different LACP System MAC addresses, the downstream dual-homed server sees two conflicting switches and suspends one leg.  
   - *Mitigation*: Align virtual LACP System MAC and System Priority.

---

## 4\. 10-Point Zero-Trust Link Aggregation Security Rubric

1. **LACP Active Mode Enforcement (12 pts)**: Prevents passive/passive negotiation deadlocks.  
2. **Collecting & Distributing State Synchronization (12 pts)**: Verifies 0x3D/0x3F state to prevent blackholing.  
3. **5-Tuple L3+L4 Hash Load Balancing (10 pts)**: Eliminates hash polarization and microburst bottlenecks.  
4. **LACP Rate Fast / Short Timeout Timer (10 pts)**: Enables 1-second heartbeats for fast failover.  
5. **Minimum Active Links (Min-Links) Protection (10 pts)**: Shuts down degraded bundles to force routing failover.  
6. **Multi-Chassis LACP System ID & MAC Consistency (10 pts)**: Prevents MLAG/vPC split-brain collisions.  
7. **Port-Channel Member Speed & MTU Homogeneity (10 pts)**: Ensures identical 9216B MTU and line rates.  
8. **Individual Port Suspension & Fallback Isolation (9 pts)**: Suspends unbundled ports to prevent loops.  
9. **Control Plane Policing (CoPP) for 01:80:C2:00:00:02 (9 pts)**: Throttles LACPDU flood attacks.  
10. **LACP Member Flap Damping & Dampening Timers (8 pts)**: Prevents dirty fiber from flapping the bundle.