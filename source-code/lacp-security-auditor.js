/**
 * LACPForge Pro - 10-Point Zero-Trust Link Aggregation Security Auditor
 * Evaluates IEEE 802.1AX & IEEE 802.3ad against negotiation deadlocks,
 * hash polarization, and multi-chassis split-brain vulnerabilities.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.LACPSecurityAuditor = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function auditLACPSecurity(cfg) {
    const findings = [];
    let totalScore = 0;

    // Check 1: LACP Active Mode Enforcement (12 pts)
    if (cfg.actorActivityActive) {
      findings.push({
        id: 'LACP_ACTIVE_MODE',
        name: 'LACP Active Mode Enforcement',
        score: 12,
        maxScore: 12,
        status: 'PASS',
        description: 'LACP Active mode enabled. The switch proactively initiates LACPDU heartbeats, preventing passive/passive negotiation deadlocks where port-channels fail to bundle.',
        remediation: null
      });
      totalScore += 12;
    } else {
      findings.push({
        id: 'LACP_ACTIVE_MODE',
        name: 'LACP Active Mode Enforcement',
        score: 0,
        maxScore: 12,
        status: 'FAIL',
        description: 'CRITICAL NEGOTIATION DEADLOCK: LACP Passive mode configured! If the remote partner is also passive, neither side will transmit LACPDUs, leaving links unbundled.',
        remediation: 'Configure "channel-group <id> mode active" on all member interfaces.'
      });
    }

    // Check 2: LACP State Synchronization & Collecting/Distributing Verification (12 pts)
    const isActorSync = cfg.actorCollecting && cfg.actorDistributing && cfg.actorInSync;
    const isPartnerSync = cfg.partnerCollecting && cfg.partnerDistributing && cfg.partnerInSync;
    if (isActorSync && isPartnerSync) {
      findings.push({
        id: 'LACP_STATE_SYNC',
        name: 'Collecting & Distributing State Synchronization',
        score: 12,
        maxScore: 12,
        status: 'PASS',
        description: 'Both Actor and Partner are in full IN_SYNC, Collecting, and Distributing states (0x3D/0x3F). Bidirectional forwarding active with zero blackholing.',
        remediation: null
      });
      totalScore += 12;
    } else {
      findings.push({
        id: 'LACP_STATE_SYNC',
        name: 'Collecting & Distributing State Synchronization',
        score: 2,
        maxScore: 12,
        status: 'FAIL',
        description: 'CRITICAL TRAFFIC BLACKHOLE: Asymmetric LACP states detected! One side is not collecting or distributing, resulting in silent unidirectional packet drops.',
        remediation: 'Verify physical link layer health and ensure LACP operational keys match across both ends.'
      });
      totalScore += 2;
    }

    // Check 3: 5-Tuple Resilient Hash Algorithm (10 pts)
    if (cfg.hashAlgorithm === 'L3_L4') {
      findings.push({
        id: 'HASH_ALGORITHM',
        name: '5-Tuple L3+L4 Hash Load Balancing',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: 'L3+L4 hash algorithm active (Src/Dst IP + TCP/UDP Port). Eliminates hash polarization and spreads traffic evenly across all member links.',
        remediation: null
      });
      totalScore += 10;
    } else if (cfg.hashAlgorithm === 'L2_L3') {
      findings.push({
        id: 'HASH_ALGORITHM',
        name: 'L2+L3 Hash Load Balancing',
        score: 6,
        maxScore: 10,
        status: 'WARN',
        description: 'L2+L3 hashing configured. Spreads routed traffic across IPs, but multiple parallel connections between same host pairs will polarize onto a single member link.',
        remediation: 'Upgrade load-balancing policy to 5-tuple L3+L4 (port-channel load-balance src-dst-ip-port).'
      });
      totalScore += 6;
    } else {
      findings.push({
        id: 'HASH_ALGORITHM',
        name: 'L2 MAC-Only Hash Load Balancing',
        score: 0,
        maxScore: 10,
        status: 'FAIL',
        description: 'CRITICAL POLARIZATION RISK: Legacy L2 MAC-only hashing active! In any routed environment, all traffic shares default gateway MACs and saturates link #1 while others sit at 0%.',
        remediation: 'Immediately configure 5-tuple L3+L4 hash load-balancing on all switches.'
      });
    }

    // Check 4: LACP Rate Fast / Short Timeout Configuration (10 pts)
    if (cfg.actorTimeoutShort) {
      findings.push({
        id: 'LACP_TIMEOUT',
        name: 'LACP Rate Fast / Short Timeout Timer (1s Heartbeat)',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: 'Short timeout (1 second transmission interval) active. Failed member links detected in 3 seconds (or <50ms with ASIC offload), preventing long TCP freezes.',
        remediation: null
      });
      totalScore += 10;
    } else {
      findings.push({
        id: 'LACP_TIMEOUT',
        name: 'LACP Rate Fast / Short Timeout Timer (1s Heartbeat)',
        score: 3,
        maxScore: 10,
        status: 'WARN',
        description: 'LACP Long timeout active (30 second transmission interval). A severed optical strand takes up to 90 seconds (3 * 30s) to detect, causing prolonged application downtime.',
        remediation: 'Configure "lacp rate fast" or "lacp timeout short" on high-availability fabric links.'
      });
      totalScore += 3;
    }

    // Check 5: Minimum Active Links Threshold (Min-Links Sizing) (10 pts)
    const minLinks = parseInt(cfg.minLinks, 10) || 1;
    const memberCount = parseInt(cfg.memberLinks, 10) || 8;
    if (minLinks >= 2 && minLinks <= memberCount) {
      findings.push({
        id: 'MIN_LINKS',
        name: 'Minimum Active Links (Min-Links) Protection',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: `Min-links threshold set to ${minLinks}. Shuts down the port-channel if capacity degrades below SLA requirements, triggering upstream ECMP rerouting.`,
        remediation: null
      });
      totalScore += 10;
    } else {
      findings.push({
        id: 'MIN_LINKS',
        name: 'Minimum Active Links (Min-Links) Protection',
        score: 3,
        maxScore: 10,
        status: 'WARN',
        description: 'Min-links threshold set to 1 (or unset). If 7 out of 8 links fail, the bundle stays up with 12.5% bandwidth, causing massive packet drops from oversubscription.',
        remediation: 'Configure "lacp min-links <N/2>" to bring down degraded bundles and trigger routing failover.'
      });
      totalScore += 3;
    }

    // Check 6: Multi-Chassis LACP (vPC / MLAG / EVPN ESI) System ID Alignment (10 pts)
    if (cfg.mlagAligned) {
      findings.push({
        id: 'MLAG_ALIGNMENT',
        name: 'Multi-Chassis LACP System ID & MAC Consistency',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: 'LACP System Priority and virtual System MAC aligned across peer switches in vPC/MLAG pair. Downstream servers see a unified single logical switch.',
        remediation: null
      });
      totalScore += 10;
    } else {
      findings.push({
        id: 'MLAG_ALIGNMENT',
        name: 'Multi-Chassis LACP System ID & MAC Consistency',
        score: 2,
        maxScore: 10,
        status: 'FAIL',
        description: 'LACP System MAC mismatch in Multi-Chassis MLAG/vPC pair! Downstream servers detect competing systems and suspend one of the member links.',
        remediation: 'Configure identical LACP System MAC and System Priority on both MLAG/vPC peer switches.'
      });
      totalScore += 2;
    }

    // Check 7: LACP Member Homogeneity (Speed, Duplex, MTU) (10 pts)
    if (cfg.memberHomogeneity) {
      findings.push({
        id: 'MEMBER_HOMOGENEITY',
        name: 'Port-Channel Member Speed & MTU Homogeneity',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: 'All member ports verified with identical physical speed, full-duplex negotiation, and Jumbo MTU (9216 bytes). Zero out-of-order packet reassembly issues.',
        remediation: null
      });
      totalScore += 10;
    } else {
      findings.push({
        id: 'MEMBER_HOMOGENEITY',
        name: 'Port-Channel Member Speed & MTU Homogeneity',
        score: 2,
        maxScore: 10,
        status: 'FAIL',
        description: 'Heterogeneous port-channel members! Mixing links of different speeds (e.g. 10G and 25G) or mismatched MTUs causes packet drops and erratic latency.',
        remediation: 'Ensure all member interfaces match exactly in transceiver speed, duplex, and MTU.'
      });
      totalScore += 2;
    }

    // Check 8: Individual Port Suspension / Fallback Protection (9 pts)
    if (cfg.suspendIndividual) {
      findings.push({
        id: 'SUSPEND_INDIVIDUAL',
        name: 'Individual Port Suspension & Fallback Isolation',
        score: 9,
        maxScore: 9,
        status: 'PASS',
        description: 'Individual port suspension enabled (lacp suspend-individual). Unbundled member ports placed in suspended state, preventing Spanning Tree loop flapping.',
        remediation: null
      });
      totalScore += 9;
    } else {
      findings.push({
        id: 'SUSPEND_INDIVIDUAL',
        name: 'Individual Port Suspension & Fallback Isolation',
        score: 3,
        maxScore: 9,
        status: 'WARN',
        description: 'Unbundled ports fall back to individual standalone forwarding. Can trigger bridging loops and duplicate broadcast forwarding if peer server unbundles.',
        remediation: 'Enable "lacp suspend-individual" or configure strict port-channel membership.'
      });
      totalScore += 3;
    }

    // Check 9: Control Plane Policing (CoPP) for Slow Protocols Multicast MAC (9 pts)
    if (cfg.coppSlowProtocols) {
      findings.push({
        id: 'COPP_SLOW_PROTOCOLS',
        name: 'Control Plane Policing (CoPP) for 01:80:C2:00:00:02',
        score: 9,
        maxScore: 9,
        status: 'PASS',
        description: 'Hardware rate-limiting active on Slow Protocols Multicast MAC (EtherType 0x8809). Protects switch CPU from high-volume LACPDU flood attacks.',
        remediation: null
      });
      totalScore += 9;
    } else {
      findings.push({
        id: 'COPP_SLOW_PROTOCOLS',
        name: 'Control Plane Policing (CoPP) for 01:80:C2:00:00:02',
        score: 0,
        maxScore: 9,
        status: 'FAIL',
        description: 'No CoPP rate-limiting for Slow Protocols! Malicious hosts sending bursts of forged LACPDUs can saturate switch CPU and disrupt neighbor bundles.',
        remediation: 'Configure CoPP policy capping EtherType 0x8809 to <= 300 pps.'
      });
    }

    // Check 10: LACP Flap Damping & Dampening Timers (8 pts)
    if (cfg.flapDampingEnabled) {
      findings.push({
        id: 'FLAP_DAMPING',
        name: 'LACP Member Flap Damping & Dampening Timers',
        score: 8,
        maxScore: 8,
        status: 'PASS',
        description: 'Flap dampening configured. Dampens member links with degraded optics or dirty fiber patches from continuously resetting the port-channel state machine.',
        remediation: null
      });
      totalScore += 8;
    } else {
      findings.push({
        id: 'FLAP_DAMPING',
        name: 'LACP Member Flap Damping & Dampening Timers',
        score: 3,
        maxScore: 8,
        status: 'WARN',
        description: 'No flap dampening on member links. A bouncing optical transceiver can flap the entire port-channel and trigger routing reconvergence every few seconds.',
        remediation: 'Configure interface carrier-delay or link dampening timers on member physical ports.'
      });
      totalScore += 3;
    }

    // Grading Scale
    let grade = 'F';
    if (totalScore >= 95) grade = 'A+';
    else if (totalScore >= 90) grade = 'A';
    else if (totalScore >= 80) grade = 'B';
    else if (totalScore >= 70) grade = 'C';
    else if (totalScore >= 60) grade = 'D';

    const passed = totalScore >= 80;
    let summary = '';
    if (grade === 'A+' || grade === 'A') {
      summary = 'Production-grade Zero-Trust Link Aggregation architecture with LACP Active mode, 5-tuple L3+L4 hash balancing, short timeout failover, and CoPP rate-limiting.';
    } else if (grade === 'B') {
      summary = 'Acceptable operational baseline, but minor gaps exist in flap dampening, min-links threshold, or individual port fallback.';
    } else {
      summary = 'Critical Link Aggregation hazard! Passive/passive negotiation deadlocks, L2 MAC polarization, or missing state synchronization risk silent traffic blackholing.';
    }

    return {
      totalScore,
      maxScore: 100,
      grade,
      passed,
      summary,
      findings
    };
  }

  return {
    auditLACPSecurity
  };
}));
