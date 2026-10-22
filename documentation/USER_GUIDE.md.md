# LACPForge Pro v1.0.0 — User Guide & NetDevOps Manual

## 1\. Web Studio Quickstart

1. Open `source-code/index.html` in any modern web browser.  
2. Select an industry preset from the top bar:  
   - **800G Data Center Backbone Bundle**: 8x 100GbE QSFP28, LACP Active, Short Timeout, Min-Links 4, 5-tuple L3+L4 hash, Collecting/Distributing in-sync (0x3D), MLAG aligned, CoPP enabled, and individual ports suspended (Grade A+).  
   - **Enterprise Hypervisor Team**: 4x 25GbE SFP28, LACP Active, Short Timeout, Min-Links 2, L3+L4 hash, suspend individual, MLAG aligned, and flap damping active (Grade A).  
   - **Vulnerable Unhardened Bundle**: LACP Passive mode, Long 30s timeout, Min-Links 1, L2 MAC-only hash polarization, unbundled fallback to individual forwarding, no CoPP, and asymmetric collecting state (Grade F).  
3. Review the **Port-Channel Telemetry & Dimensioning Metrics**:  
   - Model aggregate bundle throughput (e.g. 800 Gbps), degraded N-1 capacity (700 Gbps), hardware failover latency (\<50ms), and hash polarization risk.  
4. Review the **10-Point Zero-Trust Link Aggregation Security Scorecard**:  
   - Check compliance across Active mode, state synchronization, 5-tuple hashing, short timeouts, min-links, MLAG alignment, and CoPP rate-limiting.  
5. Review the **IEEE 802.1AX Binary LACPDU Hex Dissector**:  
   - Inspect the Wireshark-style hex dump with decoded Actor/Partner states, System Priorities, and Operational Keys.  
6. Export synthesized production configurations for **Cisco IOS-XE / NX-OS**, **Arista EOS**, **Juniper Junos (`ae0`)**, **Linux (`bond0`)**, and **Prometheus Alert Rules**.

---

## 2\. DevSecOps CLI Tool (`lacpforge-cli.py`)

The standalone Python CLI runs on Python 3.8+ with zero external dependencies.

### 2.1 Encoding IEEE 802.1AX LACPDU Binary Frames

python3 build/lacpforge-cli.py encode \\

  \--actor-mac "00:1a:2b:3c:4d:5e" \\

  \--partner-mac "00:aa:bb:cc:dd:ee" \\

  \--key 10 \\

  \--active

Output:

\=== IEEE 802.1AX LACPDU Frame Encoded (124 Bytes) \===

0000   01 80 c2 00 00 02 00 1a 2b 3c 4d 5e 88 09 01 01    |........+\<M^....|

0010   01 14 80 00 00 1a 2b 3c 4d 5e 00 0a 80 00 00 01    |......+\<M^......|

0020   3f 00 00 00 02 14 80 00 00 aa bb cc dd ee 00 0a    |?...............|

0030   80 00 00 01 3f 00 00 00 03 10 00 00 00 00 00 00    |....?...........|

0040   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    |................|

0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    |................|

0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    |................|

0070   00 00 00 00 00 00 00 00 00 00 00 00                |............|

### 2.2 Sizing Port-Channels & Hash Polarization Analysis

python3 build/lacpforge-cli.py bundle-calc \\

  \--speed 100G \\

  \--members 8 \\

  \--min-links 4 \\

  \--hash L3\_L4

Output:

\=== Port-Channel Dimensioning: 8x 100G Bundle \===

Total Aggregate Bandwidth:    800 Gbps (1600 Gbps Bidirectional Full-Duplex)

Degraded (N-1 Link Failure):  700 Gbps (87.5% capacity)

Minimum Links SLA Threshold:  4 active links

Hash Load Balancing Policy:   L3\_L4 \-\> Polarization Risk: Low (Zero Polarization)

LACP Failover Detection Time: \< 50 ms (Short Timeout \+ BFD/ASIC Hardware Failover)

### 2.3 Generating Wireshark PCAP Capture Files

python3 build/lacpforge-cli.py pcap-dump \-o lacp\_frame.pcap

Generates a standard `.pcap` capture file ready to open in Wireshark or tcpdump.

### 2.4 Running Zero-Trust CI/CD Audits

\# Validating production Data Center Backbone configuration (Exits code 0\)

python3 build/lacpforge-cli.py audit \-c build/presets/datacenter-backbone-bundle.json \--strict

\# Validating vulnerable configuration (Exits code 1\)

python3 build/lacpforge-cli.py audit \-c build/presets/vulnerable-unhardened-bundle.json \--strict

---

## 3\. GitHub Actions CI/CD Pipeline Gate

Add this workflow to your infrastructure repository (`.github/workflows/lacp-audit.yml`):

name: LACP & Link Aggregation Zero-Trust Gate

on:

  pull\_request:

    paths:

      \- 'switch-configs/\*\*'

      \- 'ansible/roles/portchannel/\*\*'

      \- 'layer2/\*\*'

jobs:

  lacp-audit:

    runs-on: ubuntu-latest

    steps:

      \- name: Checkout Code

        uses: actions/checkout@v4

      \- name: Set up Python

        uses: actions/setup-python@v5

        with:

          python-version: '3.11'

      \- name: Run LACPForge Strict Audit Gate

        run: |

          python3 build/lacpforge-cli.py audit \-c build/presets/datacenter-backbone-bundle.json \--strict