/**
 * LACPForge Pro - IEEE 802.1AX & IEEE 802.3ad Protocol Engine
 * Models LACPDU Binary Frames, Actor/Partner States, and Link Aggregation Sizing.
 * Compatible with Node.js and Browser environments.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.LACPProtocolEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Slow Protocols Multicast MAC (IEEE 802.3 Annex 43B / IEEE 802.1AX)
  const LACP_MULTICAST_MAC = '01:80:c2:00:00:02';
  const ETHERTYPE_SLOW_PROTOCOLS = 0x8809;
  const SUBTYPE_LACP = 0x01;
  const SUBTYPE_MARKER = 0x02;

  // LACP State Flags (1 byte bitmask)
  const STATE_FLAGS = {
    ACTIVITY:        0x01, // Bit 0: 1 = Active, 0 = Passive
    TIMEOUT:         0x02, // Bit 1: 1 = Short (1s), 0 = Long (30s)
    AGGREGATION:     0x04, // Bit 2: 1 = Aggregatable, 0 = Individual
    SYNCHRONIZATION: 0x08, // Bit 3: 1 = IN_SYNC, 0 = OUT_OF_SYNC
    COLLECTING:      0x10, // Bit 4: 1 = Collecting enabled
    DISTRIBUTING:    0x20, // Bit 5: 1 = Distributing enabled
    DEFAULTED:       0x40, // Bit 6: 1 = Using partner default values
    EXPIRED:         0x80  // Bit 7: 1 = Expired timer
  };

  // Standard Member Link Speeds
  const LINK_SPEEDS = {
    '1G':   { name: '1 Gbps 1000BASE-T',  speedGbps: 1 },
    '10G':  { name: '10 Gbps SFP+',       speedGbps: 10 },
    '25G':  { name: '25 Gbps SFP28',      speedGbps: 25 },
    '40G':  { name: '40 Gbps QSFP+',      speedGbps: 40 },
    '100G': { name: '100 Gbps QSFP28',    speedGbps: 100 },
    '400G': { name: '400 Gbps QSFP-DD',   speedGbps: 400 }
  };

  // Helper: Parse MAC string to array of 6 bytes
  function parseMac(macStr) {
    const cleaned = (macStr || '00:00:00:00:00:00').replace(/[:-]/g, '');
    const bytes = [];
    for (let i = 0; i < 12; i += 2) {
      bytes.push(parseInt(cleaned.substr(i, 2), 16) || 0);
    }
    while (bytes.length < 6) bytes.push(0);
    return bytes.slice(0, 6);
  }

  // Construct LACP State Byte from configuration flags
  function buildStateByte(cfg, isPartner) {
    let state = 0;
    const prefix = isPartner ? 'partner' : 'actor';

    if (cfg[`${prefix}ActivityActive`])   state |= STATE_FLAGS.ACTIVITY;
    if (cfg[`${prefix}TimeoutShort`])     state |= STATE_FLAGS.TIMEOUT;
    if (cfg[`${prefix}Aggregatable`])     state |= STATE_FLAGS.AGGREGATION;
    if (cfg[`${prefix}InSync`])           state |= STATE_FLAGS.SYNCHRONIZATION;
    if (cfg[`${prefix}Collecting`])       state |= STATE_FLAGS.COLLECTING;
    if (cfg[`${prefix}Distributing`])     state |= STATE_FLAGS.DISTRIBUTING;
    if (cfg[`${prefix}Defaulted`])        state |= STATE_FLAGS.DEFAULTED;
    if (cfg[`${prefix}Expired`])          state |= STATE_FLAGS.EXPIRED;

    return state;
  }

  // Decode LACP State Byte into human-readable flags
  function decodeStateByte(stateByte) {
    return {
      active:        (stateByte & STATE_FLAGS.ACTIVITY) !== 0,
      shortTimeout:  (stateByte & STATE_FLAGS.TIMEOUT) !== 0,
      aggregatable:  (stateByte & STATE_FLAGS.AGGREGATION) !== 0,
      inSync:        (stateByte & STATE_FLAGS.SYNCHRONIZATION) !== 0,
      collecting:    (stateByte & STATE_FLAGS.COLLECTING) !== 0,
      distributing:  (stateByte & STATE_FLAGS.DISTRIBUTING) !== 0,
      defaulted:     (stateByte & STATE_FLAGS.DEFAULTED) !== 0,
      expired:       (stateByte & STATE_FLAGS.EXPIRED) !== 0,
      hex: '0x' + stateByte.toString(16).padStart(2, '0').toUpperCase()
    };
  }

  // Encode Complete Binary IEEE 802.1AX LACPDU Frame
  function encodeLACPDU(config) {
    const cfg = config || {};
    const dstMac = parseMac(LACP_MULTICAST_MAC);
    const srcMac = parseMac(cfg.srcMac || '00:1a:2b:3c:4d:5e');
    const ethertypeBytes = [(ETHERTYPE_SLOW_PROTOCOLS >> 8) & 0xff, ETHERTYPE_SLOW_PROTOCOLS & 0xff];

    const lacpPayload = [];

    // LACP Header
    lacpPayload.push(SUBTYPE_LACP); // Subtype: 0x01
    lacpPayload.push(0x01);         // Version Number: 0x01

    // --- TLV 1: Actor Information (Type 0x01, Length 0x14 / 20 bytes) ---
    lacpPayload.push(0x01, 0x14);
    const actorSysPrio = parseInt(cfg.actorSysPriority, 10) || 32768;
    lacpPayload.push((actorSysPrio >> 8) & 0xff, actorSysPrio & 0xff);
    lacpPayload.push(...parseMac(cfg.actorSysMac || '00:1a:2b:3c:4d:5e'));
    const actorKey = parseInt(cfg.actorKey, 10) || 1;
    lacpPayload.push((actorKey >> 8) & 0xff, actorKey & 0xff);
    const actorPortPrio = parseInt(cfg.actorPortPriority, 10) || 32768;
    lacpPayload.push((actorPortPrio >> 8) & 0xff, actorPortPrio & 0xff);
    const actorPortNum = parseInt(cfg.actorPortNum, 10) || 1;
    lacpPayload.push((actorPortNum >> 8) & 0xff, actorPortNum & 0xff);
    const actorState = buildStateByte(cfg, false);
    lacpPayload.push(actorState);
    lacpPayload.push(0x00, 0x00, 0x00); // 3-byte Reserved

    // --- TLV 2: Partner Information (Type 0x02, Length 0x14 / 20 bytes) ---
    lacpPayload.push(0x02, 0x14);
    const partnerSysPrio = parseInt(cfg.partnerSysPriority, 10) || 32768;
    lacpPayload.push((partnerSysPrio >> 8) & 0xff, partnerSysPrio & 0xff);
    lacpPayload.push(...parseMac(cfg.partnerSysMac || '00:aa:bb:cc:dd:ee'));
    const partnerKey = parseInt(cfg.partnerKey, 10) || 1;
    lacpPayload.push((partnerKey >> 8) & 0xff, partnerKey & 0xff);
    const partnerPortPrio = parseInt(cfg.partnerPortPriority, 10) || 32768;
    lacpPayload.push((partnerPortPrio >> 8) & 0xff, partnerPortPrio & 0xff);
    const partnerPortNum = parseInt(cfg.partnerPortNum, 10) || 1;
    lacpPayload.push((partnerPortNum >> 8) & 0xff, partnerPortNum & 0xff);
    const partnerState = buildStateByte(cfg, true);
    lacpPayload.push(partnerState);
    lacpPayload.push(0x00, 0x00, 0x00); // 3-byte Reserved

    // --- TLV 3: Collector Information (Type 0x03, Length 0x10 / 16 bytes) ---
    lacpPayload.push(0x03, 0x10);
    const maxDelay = parseInt(cfg.collectorMaxDelay, 10) || 0; // tens of microseconds
    lacpPayload.push((maxDelay >> 8) & 0xff, maxDelay & 0xff);
    // 12 bytes Reserved padding for Collector TLV
    for (let i = 0; i < 12; i++) lacpPayload.push(0x00);

    // --- TLV 0: Terminator Information (Type 0x00, Length 0x00) ---
    lacpPayload.push(0x00, 0x00);

    // Pad to standard 110-byte LACPDU frame payload (giving 124 bytes total Ethernet frame)
    while (lacpPayload.length < 110) {
      lacpPayload.push(0x00);
    }

    const fullFrame = [...dstMac, ...srcMac, ...ethertypeBytes, ...lacpPayload];

    return {
      frameBytes: fullFrame,
      totalLength: fullFrame.length,
      payloadLength: lacpPayload.length,
      actorStateHex: '0x' + actorState.toString(16).padStart(2, '0').toUpperCase(),
      partnerStateHex: '0x' + partnerState.toString(16).padStart(2, '0').toUpperCase(),
      hexString: fullFrame.map(b => b.toString(16).padStart(2, '0')).join('')
    };
  }

  // Format Frame to Wireshark-Style Hex Dump
  function formatHexDump(bytes) {
    const lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const offset = i.toString(16).padStart(4, '0');
      const hexPart = chunk.map(b => b.toString(16).padStart(2, '0')).join(' ');
      const paddedHex = hexPart.padEnd(48, ' ');
      const asciiPart = chunk.map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');
      lines.push(`${offset}   ${paddedHex}   |${asciiPart}|`);
    }
    return lines.join('\n');
  }

  // Port-Channel Bandwidth & Hash Dimensioning Engine
  function calculatePortChannelSizing(params) {
    const linkSpeedKey = params.linkSpeed || '100G';
    const linkInfo = LINK_SPEEDS[linkSpeedKey] || LINK_SPEEDS['100G'];
    const memberCount = parseInt(params.memberLinks, 10) || 8;
    const minLinks = parseInt(params.minLinks, 10) || 1;
    const hashAlgorithm = params.hashAlgorithm || 'L3_L4'; // L2, L2_L3, L3_L4

    const totalThroughputGbps = memberCount * linkInfo.speedGbps;
    const degradedThroughputGbps = (memberCount > 1 ? (memberCount - 1) : 1) * linkInfo.speedGbps;

    // Failover timer: Short timeout = 1s detection (<50ms ASIC hardware failover); Long timeout = 30s detection (90s dead timer)
    const failoverDetectionMs = params.actorTimeoutShort ? 50 : 90000;

    let hashDistributionQuality = 'Optimal (Zero Polarization)';
    let polarizationRisk = 'Low';
    if (hashAlgorithm === 'L2') {
      hashDistributionQuality = 'Poor (Severe Polarization on Routed Flows)';
      polarizationRisk = 'Critical';
    } else if (hashAlgorithm === 'L2_L3') {
      hashDistributionQuality = 'Moderate (Subject to ECMP Hash Collisions)';
      polarizationRisk = 'Medium';
    }

    return {
      memberCount,
      linkSpeedName: linkInfo.name,
      totalThroughputGbps,
      degradedThroughputGbps,
      minLinks,
      hashAlgorithm,
      hashDistributionQuality,
      polarizationRisk,
      failoverDetectionMs
    };
  }

  return {
    LACP_MULTICAST_MAC,
    ETHERTYPE_SLOW_PROTOCOLS,
    STATE_FLAGS,
    LINK_SPEEDS,
    buildStateByte,
    decodeStateByte,
    encodeLACPDU,
    formatHexDump,
    calculatePortChannelSizing
  };
}));
