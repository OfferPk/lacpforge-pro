/**
 * LACPForge Pro - Web Application Controller
 */

(function () {
  'use strict';

  const PRESETS = {
    backbone: {
      name: '800G Data Center Backbone Bundle (Grade A+)',
      linkSpeed: '100G',
      memberLinks: 8,
      minLinks: 4,
      hashAlgorithm: 'L3_L4',
      actorSysPriority: 32768,
      actorKey: 10,
      actorSysMac: '00:1a:2b:3c:4d:5e',
      srcMac: '00:1a:2b:3c:4d:5e',
      partnerSysPriority: 32768,
      partnerKey: 10,
      partnerSysMac: '00:aa:bb:cc:dd:ee',
      actorPortNum: 1,
      actorActivityActive: true,
      actorTimeoutShort: true,
      actorAggregatable: true,
      actorInSync: true,
      actorCollecting: true,
      actorDistributing: true,
      actorDefaulted: false,
      actorExpired: false,
      partnerActivityActive: true,
      partnerTimeoutShort: true,
      partnerAggregatable: true,
      partnerInSync: true,
      partnerCollecting: true,
      partnerDistributing: true,
      partnerDefaulted: false,
      partnerExpired: false,
      mlagAligned: true,
      memberHomogeneity: true,
      suspendIndividual: true,
      coppSlowProtocols: true,
      flapDampingEnabled: true
    },
    hypervisor: {
      name: 'Enterprise Hypervisor Team (Grade A)',
      linkSpeed: '25G',
      memberLinks: 4,
      minLinks: 2,
      hashAlgorithm: 'L3_L4',
      actorSysPriority: 32768,
      actorKey: 5,
      actorSysMac: '00:22:33:44:55:66',
      srcMac: '00:22:33:44:55:66',
      partnerSysPriority: 32768,
      partnerKey: 5,
      partnerSysMac: '00:50:56:aa:bb:cc',
      actorPortNum: 1,
      actorActivityActive: true,
      actorTimeoutShort: true,
      actorAggregatable: true,
      actorInSync: true,
      actorCollecting: true,
      actorDistributing: true,
      actorDefaulted: false,
      actorExpired: false,
      partnerActivityActive: true,
      partnerTimeoutShort: true,
      partnerAggregatable: true,
      partnerInSync: true,
      partnerCollecting: true,
      partnerDistributing: true,
      partnerDefaulted: false,
      partnerExpired: false,
      mlagAligned: true,
      memberHomogeneity: true,
      suspendIndividual: true,
      coppSlowProtocols: true,
      flapDampingEnabled: true
    },
    vulnerable: {
      name: 'Vulnerable Unhardened Bundle (Grade F)',
      linkSpeed: '10G',
      memberLinks: 4,
      minLinks: 1, // Single link degradation
      hashAlgorithm: 'L2', // Legacy MAC-only polarization!
      actorSysPriority: 32768,
      actorKey: 1,
      actorSysMac: '00:11:22:33:44:55',
      srcMac: '00:11:22:33:44:55',
      partnerSysPriority: 32768,
      partnerKey: 1,
      partnerSysMac: '00:99:88:77:66:55',
      actorPortNum: 1,
      actorActivityActive: false, // PASSIVE mode! Deadlock risk!
      actorTimeoutShort: false, // 30s Long timeout (90s dead timer)
      actorAggregatable: true,
      actorInSync: false, // OUT OF SYNC!
      actorCollecting: false, // Asymmetric blackhole!
      actorDistributing: false,
      actorDefaulted: true,
      actorExpired: false,
      partnerActivityActive: false, // PASSIVE!
      partnerTimeoutShort: false,
      partnerAggregatable: true,
      partnerInSync: false,
      partnerCollecting: false,
      partnerDistributing: false,
      partnerDefaulted: true,
      partnerExpired: false,
      mlagAligned: false, // MLAG System MAC mismatch!
      memberHomogeneity: false, // Speed mismatch!
      suspendIndividual: false, // Loops on unbundled fallback!
      coppSlowProtocols: false, // Flood target!
      flapDampingEnabled: false
    }
  };

  let activeTab = 'cisco';

  // DOM Elements
  const elActorSysPrio = document.getElementById('input-actor-sys-prio');
  const elActorKey = document.getElementById('input-actor-key');
  const elActorSysMac = document.getElementById('input-actor-sys-mac');
  const elSrcMac = document.getElementById('input-src-mac');
  const elPartnerSysPrio = document.getElementById('input-partner-sys-prio');
  const elPartnerKey = document.getElementById('input-partner-key');
  const elPartnerSysMac = document.getElementById('input-partner-sys-mac');
  const elPortNum = document.getElementById('input-port-num');

  const elLinkSpeed = document.getElementById('select-link-speed');
  const elMemberLinks = document.getElementById('input-member-links');
  const elHashAlgo = document.getElementById('select-hash-algo');
  const elMinLinks = document.getElementById('input-min-links');

  const elChkActorActive = document.getElementById('chk-actor-active');
  const elChkShortTimeout = document.getElementById('chk-short-timeout');
  const elChkActorCollecting = document.getElementById('chk-actor-collecting');
  const elChkPartnerCollecting = document.getElementById('chk-partner-collecting');
  const elChkMlagAligned = document.getElementById('chk-mlag-aligned');
  const elChkMemberHomogeneity = document.getElementById('chk-member-homogeneity');
  const elChkSuspendIndividual = document.getElementById('chk-suspend-individual');
  const elChkCoppSlow = document.getElementById('chk-copp-slow');
  const elChkFlapDamping = document.getElementById('chk-flap-damping');

  const elValThroughput = document.getElementById('val-throughput');
  const elValN1Throughput = document.getElementById('val-n1-throughput');
  const elValFailoverLat = document.getElementById('val-failover-lat');
  const elValHashPolarization = document.getElementById('val-hash-polarization');

  const elBadgeLacpState = document.getElementById('badge-lacp-state');
  const elBadgeBundleCapacity = document.getElementById('badge-bundle-capacity');
  const elScoreBanner = document.getElementById('score-banner');
  const elScoreGrade = document.getElementById('score-grade');
  const elScoreTitle = document.getElementById('score-title');
  const elScoreSummary = document.getElementById('score-summary');
  const elFindingsContainer = document.getElementById('findings-container');

  const elBadgeWireframeDesc = document.getElementById('badge-wireframe-desc');
  const elPacketHexDump = document.getElementById('packet-hex-dump');
  const elSynthOutput = document.getElementById('synth-output');
  const elBtnCopy = document.getElementById('btn-copy-config');

  function getFormConfig() {
    return {
      actorSysPriority: parseInt(elActorSysPrio.value, 10) || 32768,
      actorKey: parseInt(elActorKey.value, 10) || 10,
      actorSysMac: elActorSysMac.value.trim(),
      srcMac: elSrcMac.value.trim(),
      partnerSysPriority: parseInt(elPartnerSysPrio.value, 10) || 32768,
      partnerKey: parseInt(elPartnerKey.value, 10) || 10,
      partnerSysMac: elPartnerSysMac.value.trim(),
      actorPortNum: parseInt(elPortNum.value, 10) || 1,
      linkSpeed: elLinkSpeed.value,
      memberLinks: parseInt(elMemberLinks.value, 10) || 8,
      hashAlgorithm: elHashAlgo.value,
      minLinks: parseInt(elMinLinks.value, 10) || 4,
      actorActivityActive: elChkActorActive.checked,
      actorTimeoutShort: elChkShortTimeout.checked,
      actorAggregatable: true,
      actorInSync: elChkActorCollecting.checked,
      actorCollecting: elChkActorCollecting.checked,
      actorDistributing: elChkActorCollecting.checked,
      actorDefaulted: false,
      actorExpired: false,
      partnerActivityActive: elChkActorActive.checked,
      partnerTimeoutShort: elChkShortTimeout.checked,
      partnerAggregatable: true,
      partnerInSync: elChkPartnerCollecting.checked,
      partnerCollecting: elChkPartnerCollecting.checked,
      partnerDistributing: elChkPartnerCollecting.checked,
      partnerDefaulted: false,
      partnerExpired: false,
      mlagAligned: elChkMlagAligned.checked,
      memberHomogeneity: elChkMemberHomogeneity.checked,
      suspendIndividual: elChkSuspendIndividual.checked,
      coppSlowProtocols: elChkCoppSlow.checked,
      flapDampingEnabled: elChkFlapDamping.checked
    };
  }

  function applyPreset(presetKey) {
    const p = PRESETS[presetKey];
    if (!p) return;

    elActorSysPrio.value = p.actorSysPriority;
    elActorKey.value = p.actorKey;
    elActorSysMac.value = p.actorSysMac;
    elSrcMac.value = p.srcMac;
    elPartnerSysPrio.value = p.partnerSysPriority;
    elPartnerKey.value = p.partnerKey;
    elPartnerSysMac.value = p.partnerSysMac;
    elPortNum.value = p.actorPortNum;
    elLinkSpeed.value = p.linkSpeed;
    elMemberLinks.value = p.memberLinks;
    elHashAlgo.value = p.hashAlgorithm;
    elMinLinks.value = p.minLinks;

    elChkActorActive.checked = p.actorActivityActive;
    elChkShortTimeout.checked = p.actorTimeoutShort;
    elChkActorCollecting.checked = p.actorCollecting;
    elChkPartnerCollecting.checked = p.partnerCollecting;
    elChkMlagAligned.checked = p.mlagAligned;
    elChkMemberHomogeneity.checked = p.memberHomogeneity;
    elChkSuspendIndividual.checked = p.suspendIndividual;
    elChkCoppSlow.checked = p.coppSlowProtocols;
    elChkFlapDamping.checked = p.flapDampingEnabled;

    document.querySelectorAll('.btn-preset').forEach(b => b.classList.remove('active'));
    const btn = document.getElementById(`btn-preset-${presetKey}`);
    if (btn) btn.classList.add('active');

    updateAll();
  }

  function updateAll() {
    const cfg = getFormConfig();

    // 1. Sizing Calculations
    const sizing = LACPProtocolEngine.calculatePortChannelSizing(cfg);
    elValThroughput.textContent = `${sizing.totalThroughputGbps} Gbps`;
    elValN1Throughput.textContent = `${sizing.degradedThroughputGbps} Gbps`;
    elValFailoverLat.textContent = sizing.failoverDetectionMs < 1000 ? '< 50 ms' : '90,000 ms';
    elValHashPolarization.textContent = sizing.polarizationRisk;
    elValHashPolarization.style.color = sizing.polarizationRisk === 'Critical' ? '#f43f5e' : (sizing.polarizationRisk === 'Medium' ? '#fbbf24' : '#34d399');

    elBadgeBundleCapacity.textContent = `${sizing.totalThroughputGbps} Gbps (${sizing.memberCount}x ${cfg.linkSpeed})`;

    // 2. Binary LACPDU Encoding & Hex Dissector
    const encoded = LACPProtocolEngine.encodeLACPDU(cfg);
    elBadgeLacpState.textContent = `Actor: ${encoded.actorStateHex} | Partner: ${encoded.partnerStateHex}`;
    elValFrameSize.textContent = `${encoded.totalLength} Bytes`;
    elBadgeWireframeDesc.textContent = `${encoded.totalLength} Bytes (Payload: ${encoded.payloadLength}B)`;

    const hexDump = LACPProtocolEngine.formatHexDump(encoded.frameBytes);
    elPacketHexDump.textContent = hexDump;

    // 3. 10-Point Zero-Trust Audit
    const audit = LACPSecurityAuditor.auditLACPSecurity(cfg);
    elScoreGrade.textContent = audit.grade;
    elScoreTitle.textContent = `${audit.totalScore} / ${audit.maxScore} Points (${audit.passed ? 'Passed' : 'Failed'})`;
    elScoreSummary.textContent = audit.summary;
    elScoreBanner.className = `score-badge-large ${audit.passed ? 'grade-A' : 'grade-F'}`;

    elFindingsContainer.innerHTML = '';
    audit.findings.forEach(f => {
      const item = document.createElement('div');
      item.className = `finding-item ${f.status.toLowerCase()}`;
      item.innerHTML = `
        <div class="finding-title">
          <span>${f.name}</span>
          <span style="font-family: var(--font-mono);">${f.score}/${f.maxScore} pts</span>
        </div>
        <div class="finding-desc">${f.description}</div>
        ${f.remediation ? `<div class="finding-remediation">Remediation: ${f.remediation}</div>` : ''}
      `;
      elFindingsContainer.appendChild(item);
    });

    // 4. Configuration Synthesizer Output
    renderSynthesizer(cfg);
  }

  function renderSynthesizer(cfg) {
    let code = '';
    if (activeTab === 'cisco') {
      code = LACPConfigSynthesizer.generateCisco(cfg);
    } else if (activeTab === 'arista') {
      code = LACPConfigSynthesizer.generateArista(cfg);
    } else if (activeTab === 'junos') {
      code = LACPConfigSynthesizer.generateJunos(cfg);
    } else if (activeTab === 'linux') {
      code = LACPConfigSynthesizer.generateLinux(cfg);
    } else if (activeTab === 'prom') {
      code = LACPConfigSynthesizer.generatePrometheus(cfg);
    }
    elSynthOutput.textContent = code;
  }

  // Event Listeners
  document.getElementById('btn-preset-backbone').addEventListener('click', () => applyPreset('backbone'));
  document.getElementById('btn-preset-hypervisor').addEventListener('click', () => applyPreset('hypervisor'));
  document.getElementById('btn-preset-vulnerable').addEventListener('click', () => applyPreset('vulnerable'));
  document.getElementById('btn-recalculate').addEventListener('click', updateAll);

  [elActorSysPrio, elActorKey, elActorSysMac, elSrcMac, elPartnerSysPrio, elPartnerKey,
   elPartnerSysMac, elPortNum, elLinkSpeed, elMemberLinks, elHashAlgo, elMinLinks,
   elChkActorActive, elChkShortTimeout, elChkActorCollecting, elChkPartnerCollecting,
   elChkMlagAligned, elChkMemberHomogeneity, elChkSuspendIndividual, elChkCoppSlow,
   elChkFlapDamping
  ].forEach(input => {
    input.addEventListener('input', updateAll);
    input.addEventListener('change', updateAll);
  });

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      e.target.classList.add('active');
      activeTab = e.target.getAttribute('data-tab');
      renderSynthesizer(getFormConfig());
    });
  });

  elBtnCopy.addEventListener('click', () => {
    navigator.clipboard.writeText(elSynthOutput.textContent).then(() => {
      elBtnCopy.textContent = 'Copied!';
      setTimeout(() => { elBtnCopy.textContent = 'Copy Config'; }, 2000);
    });
  });

  // Initialize
  applyPreset('backbone');
})();
