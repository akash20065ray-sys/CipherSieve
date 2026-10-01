/**
 * CipherSieve - Real-Time SOC Dashboard Logic
 * - Real-time WebSocket telemetry handler (Live packets, new flows, sniffer telemetry)
 * - Live canvas discrete impulse pulse-train oscilloscope
 * - Tri-Mode Ingestion Deck:
 *   1. Automated Attack Presets
 *   2. Manual Packet Forge Playground
 *   3. Real-World PCAP Dataset Replay & Upload
 *   4. Live Network Card Sniffer (Wi-Fi, Ethernet, Loopback)
 * - 3-Stage Forensic Flow Inspector (Packet -> 13 Features -> Model -> Evidence)
 */

let ws = null;
let currentFlows = [];
let isThreatActive = false;

// Oscilloscope state
const canvas = document.getElementById("oscilloscopeCanvas");
const ctx = canvas.getContext("2d");
let waveOffset = 0;
let waveFrequency = 0.05;
let waveAmplitude = 25;
let waveColor = "#10b981"; // Green by default

// Physical Packet Pulse Train Buffer
let packetPulses = [];
const MAX_PULSES = 60;

// Initialize
document.addEventListener("DOMContentLoaded", () => {
  initWebSocket();
  startOscilloscope();
  initModelSelector();
  loadNetworkInterfaces();
  loadInitialMockThreats();
});

function initWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/stream`;

  try {
    ws = new WebSocket(wsUrl);
    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === "NEW_FLOW") {
        if (msg.data && msg.data.packets) {
          msg.data.packets.forEach(p => {
            pushPacketPulse(p.size, p.direction, msg.data.is_threat);
          });
        }
        handleNewFlow(msg.data, msg.stats);
      } else if (msg.type === "PACKET_PULSE") {
        if (msg.data) {
          pushPacketPulse(msg.data.size, msg.data.direction || 1, false);
        }
      } else if (msg.type === "HEARTBEAT") {
        updateStats(msg.stats);
        if (msg.sniffer) updateSnifferHUD(msg.sniffer);
      } else if (msg.type === "SNIFFER_STATE") {
        if (msg.data) updateSnifferHUD(msg.data);
      }
    };
    ws.onclose = () => {
      setTimeout(initWebSocket, 2000);
    };
  } catch (e) {
    console.warn("WebSocket fallback mode active");
  }
}

function updateStats(stats) {
  if (!stats) return;
  const elFlows = document.getElementById("valFlows");
  const elThreats = document.getElementById("valThreats");
  const elLat = document.getElementById("valLatency");
  const elMode = document.getElementById("valIngestMode");

  if (elFlows) elFlows.textContent = Number(stats.total_flows).toLocaleString();
  if (elThreats) elThreats.textContent = stats.threats_detected;
  if (elLat) elLat.textContent = `${stats.last_latency_ms}ms`;
  if (elMode && stats.ingest_mode) elMode.textContent = stats.ingest_mode;
}

function updateSnifferHUD(sniffer) {
  if (!sniffer) return;
  const countEl = document.getElementById("livePktCount");
  const flowEl = document.getElementById("liveFlowCount");
  const rateEl = document.getElementById("liveRate");
  const dotEl = document.getElementById("liveStatusDot");
  const textEl = document.getElementById("liveStatusText");
  const btnStart = document.getElementById("btnStartLive");
  const btnStop = document.getElementById("btnStopLive");

  if (countEl) countEl.textContent = Number(sniffer.packets_captured || 0).toLocaleString();
  if (flowEl) flowEl.textContent = Number(sniffer.active_flows || 0).toLocaleString();
  if (rateEl) rateEl.textContent = `${sniffer.pps || 0} pps (${sniffer.kbps || 0} Kbps)`;

  if (sniffer.is_running) {
    if (dotEl) dotEl.className = "dot dot-pulsing-green";
    if (textEl) textEl.textContent = `Active [${sniffer.capture_mode}] on ${sniffer.active_interface}`;
    if (btnStart) { btnStart.classList.add("disabled"); btnStart.disabled = true; }
    if (btnStop) { btnStop.classList.remove("disabled"); btnStop.disabled = false; }
  } else {
    if (dotEl) dotEl.className = "dot dot-gray";
    if (textEl) textEl.textContent = "Sniffer Idle";
    if (btnStart) { btnStart.classList.remove("disabled"); btnStart.disabled = false; }
    if (btnStop) { btnStop.classList.add("disabled"); btnStop.disabled = true; }
  }
}

function initModelSelector() {
  const sel = document.getElementById("modelSelector");
  if (!sel) return;
  sel.addEventListener("change", async (e) => {
    const formData = new FormData();
    formData.append("model_name", e.target.value);
    try {
      await fetch("/api/model/switch", { method: "POST", body: formData });
      showNotification(`Switched active inference model to: ${e.target.value}`);
    } catch (err) {
      console.error(err);
    }
  });
}

function pushPacketPulse(size, direction, isThreat) {
  packetPulses.push({
    size: size,
    direction: direction, // 1 = Upload, -1 = Download
    isThreat: isThreat,
    alpha: 1.0,
    x: canvas.width - 20
  });
  if (packetPulses.length > MAX_PULSES) {
    packetPulses.shift();
  }
}

// Generate background pulse dynamics when idle
setInterval(() => {
  if (!isThreatActive) {
    if (Math.random() < 0.35) {
      const isDown = Math.random() > 0.3;
      const sz = isDown ? (Math.random() > 0.5 ? 1420 : 512) : 64;
      pushPacketPulse(sz, isDown ? -1 : 1, false);
    }
  }
}, 120);

// Discrete Packet Impulse Graph
function startOscilloscope() {
  function draw() {
    ctx.fillStyle = "#0f172a";
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Grid
    ctx.strokeStyle = "rgba(255, 255, 255, 0.05)";
    ctx.lineWidth = 1;
    for (let x = 0; x < canvas.width; x += 35) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, canvas.height);
      ctx.stroke();
    }

    // Zero-Line Axis
    const midY = canvas.height / 2;
    ctx.strokeStyle = "rgba(255, 255, 255, 0.15)";
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(0, midY);
    ctx.lineTo(canvas.width, midY);
    ctx.stroke();
    ctx.setLineDash([]);

    // Axis Labels
    ctx.fillStyle = "rgba(255, 255, 255, 0.3)";
    ctx.font = "9px 'JetBrains Mono', monospace";
    ctx.fillText("▲ UPSTREAM (TX)", 10, 14);
    ctx.fillText("▼ DOWNSTREAM (RX)", 10, canvas.height - 6);

    // Pulses
    for (let i = 0; i < packetPulses.length; i++) {
      const p = packetPulses[i];
      p.x -= isThreatActive ? 3.5 : 1.8;

      const maxH = (midY - 15);
      const h = (p.size / 1500) * maxH;
      const yEnd = p.direction === 1 ? (midY - h) : (midY + h);
      const color = p.isThreat ? "#ef4444" : "#10b981";

      ctx.strokeStyle = color;
      ctx.lineWidth = p.size > 1000 ? 3 : 2;
      ctx.shadowBlur = 6;
      ctx.shadowColor = color;

      ctx.beginPath();
      ctx.moveTo(p.x, midY);
      ctx.lineTo(p.x, yEnd);
      ctx.stroke();

      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(p.x, yEnd, 2, 0, Math.PI * 2);
      ctx.fill();

      ctx.shadowBlur = 0;
    }

    packetPulses = packetPulses.filter(p => p.x > -10);
    requestAnimationFrame(draw);
  }
  draw();
}

// Ingestion Tab Switcher
function switchSimTab(mode) {
  const tabs = {
    auto: { tab: document.getElementById("tabAuto"), panel: document.getElementById("panelAuto") },
    manual: { tab: document.getElementById("tabManual"), panel: document.getElementById("panelManual") },
    pcap: { tab: document.getElementById("tabPcap"), panel: document.getElementById("panelPcap") },
    live: { tab: document.getElementById("tabLive"), panel: document.getElementById("panelLive") }
  };

  Object.keys(tabs).forEach(k => {
    if (tabs[k].tab && tabs[k].panel) {
      if (k === mode) {
        tabs[k].tab.classList.add("active");
        tabs[k].panel.classList.remove("hidden");
      } else {
        tabs[k].tab.classList.remove("active");
        tabs[k].panel.classList.add("hidden");
      }
    }
  });

  const modeMap = { auto: "SYNTHETIC", manual: "SYNTHETIC", pcap: "PCAP", live: "LIVE" };
  const targetMode = modeMap[mode] || "SYNTHETIC";
  const formData = new FormData();
  formData.append("mode", targetMode);
  fetch("/api/ingest/mode", { method: "POST", body: formData }).catch(console.error);

  const elMode = document.getElementById("valIngestMode");
  if (elMode) elMode.textContent = targetMode;
}

function updateSliderLabels() {
  const sz = document.getElementById("rngSize").value;
  const dl = document.getElementById("rngDelay").value;
  const rt = document.getElementById("rngRatio").value;

  document.getElementById("lblSize").textContent = `${sz} B`;
  document.getElementById("lblDelay").textContent = `${dl} ms`;
  document.getElementById("lblRatio").textContent = `${rt}% Upload`;
}

// Mode A: Run 1-Click Preset
async function runPreset(scenario) {
  const evasionChecked = document.getElementById("checkEvasion").checked;
  const padding = evasionChecked ? 50 : 0;
  const jitter = evasionChecked ? 20.0 : 0.0;

  const formData = new FormData();
  formData.append("scenario", scenario);
  formData.append("padding", padding);
  formData.append("jitter", jitter);

  if (scenario === "BENIGN_WEB" || scenario === "BENIGN_STREAM") {
    isThreatActive = false;
    waveColor = "#10b981";
    document.getElementById("oscilloscopeTag").textContent = "MONITORING BENIGN RHYTHM";
    document.getElementById("oscilloscopeTag").style.color = "#10b981";
    document.getElementById("oscilloscopeTag").style.borderColor = "rgba(16, 185, 129, 0.4)";
  } else {
    isThreatActive = true;
    waveColor = "#ef4444";
    document.getElementById("oscilloscopeTag").textContent = `HIGH-RISK PATTERN DETECTED: ${scenario}`;
    document.getElementById("oscilloscopeTag").style.color = "#ef4444";
    document.getElementById("oscilloscopeTag").style.borderColor = "rgba(239, 68, 68, 0.4)";
  }

  try {
    const res = await fetch("/api/simulate", { method: "POST", body: formData });
    const data = await res.json();
    if (data && data.packets) {
      data.packets.forEach(p => {
        pushPacketPulse(p.size, p.direction, data.is_threat);
      });
    }
    handleNewFlow(data, null);
  } catch (err) {
    console.error(err);
  }
}

// Mode B: Execute Manual Slider Forge
async function executeManualForge() {
  const sz = document.getElementById("rngSize").value;
  const dl = document.getElementById("rngDelay").value;
  const rt = document.getElementById("rngRatio").value / 100.0;

  const formData = new FormData();
  formData.append("packet_size", sz);
  formData.append("delay_ms", dl);
  formData.append("upload_ratio", rt);

  try {
    const res = await fetch("/api/manual_forge", { method: "POST", body: formData });
    const flowRecord = await res.json();

    if (flowRecord.is_threat) {
      isThreatActive = true;
      waveColor = "#ef4444";
      document.getElementById("oscilloscopeTag").textContent = `HIGH-RISK PATTERN: ${flowRecord.class}`;
      document.getElementById("oscilloscopeTag").style.color = "#ef4444";
    } else {
      isThreatActive = false;
      waveColor = "#10b981";
      document.getElementById("oscilloscopeTag").textContent = "MONITORING BENIGN RHYTHM";
      document.getElementById("oscilloscopeTag").style.color = "#10b981";
    }

    if (flowRecord.packets) {
      flowRecord.packets.forEach(p => {
        pushPacketPulse(p.size, p.direction, flowRecord.is_threat);
      });
    }

    handleNewFlow(flowRecord, null);
    openInspector(flowRecord);
  } catch (err) {
    console.error(err);
  }
}

// Mode C: PCAP Replay & Upload
async function triggerPcapReplay() {
  const file = document.getElementById("pcapFileSelect").value;
  const speed = document.getElementById("pcapSpeedSelect").value;

  const formData = new FormData();
  formData.append("filename", file);
  formData.append("speed", speed);

  document.getElementById("oscilloscopeTag").textContent = `REPLAYING PCAP: ${file}`;
  document.getElementById("oscilloscopeTag").style.color = "#2563eb";
  document.getElementById("oscilloscopeTag").style.borderColor = "rgba(37, 99, 235, 0.4)";

  try {
    await fetch("/api/ingest/pcap/replay", { method: "POST", body: formData });
    showNotification(`Replaying ${file} at ${speed}x wire speed`);
  } catch (err) {
    console.error(err);
  }
}

async function uploadCustomPcap(input) {
  if (!input.files || input.files.length === 0) return;
  const file = input.files[0];
  const formData = new FormData();
  formData.append("file", file);
  formData.append("auto_replay", "true");
  formData.append("speed", "2.0");

  showNotification(`Uploading & parsing ${file.name}...`);

  try {
    const res = await fetch("/api/ingest/pcap/upload", { method: "POST", body: formData });
    const data = await res.json();
    if (data.status === "UPLOAD_SUCCESS") {
      showNotification(`Replaying uploaded PCAP: ${file.name}`);
      const sel = document.getElementById("pcapFileSelect");
      const opt = document.createElement("option");
      opt.value = file.name;
      opt.textContent = `${file.name} (Uploaded Capture)`;
      opt.selected = true;
      sel.appendChild(opt);
    }
  } catch (err) {
    console.error(err);
  }
}

// Mode D: Live Wire Sniffer
async function loadNetworkInterfaces() {
  try {
    const res = await fetch("/api/interfaces");
    const data = await res.json();
    if (data && data.interfaces) {
      const sel = document.getElementById("liveIfaceSelect");
      if (!sel) return;
      sel.innerHTML = "";
      data.interfaces.forEach(iface => {
        const opt = document.createElement("option");
        opt.value = iface.name;
        opt.textContent = `${iface.name} ${iface.ip ? `(${iface.ip})` : ''} ${iface.is_loopback ? '[Loopback]' : ''}`;
        if (iface.name === "Wi-Fi" || iface.ip.startsWith("192.") || iface.ip.startsWith("10.")) {
          opt.selected = true;
        }
        sel.appendChild(opt);
      });
    }
  } catch (err) {
    console.warn("Could not load interfaces:", err);
  }
}

async function startLiveSniffer() {
  const iface = document.getElementById("liveIfaceSelect").value;
  const formData = new FormData();
  formData.append("interface", iface);

  try {
    const res = await fetch("/api/ingest/live/start", { method: "POST", body: formData });
    const data = await res.json();
    if (data && data.sniffer) {
      updateSnifferHUD(data.sniffer);
      showNotification(`Live sniffer started on ${iface}`);
      document.getElementById("oscilloscopeTag").textContent = `LIVE WIRE INGESTION: ${iface}`;
      document.getElementById("oscilloscopeTag").style.color = "#059669";
    }
  } catch (err) {
    console.error(err);
  }
}

async function stopLiveSniffer() {
  try {
    const res = await fetch("/api/ingest/live/stop", { method: "POST" });
    const data = await res.json();
    if (data && data.sniffer) {
      updateSnifferHUD(data.sniffer);
      showNotification("Live sniffer stopped");
      document.getElementById("oscilloscopeTag").textContent = "MONITORING NORMAL STREAM";
    }
  } catch (err) {
    console.error(err);
  }
}

// Threat Feed Handling
function handleNewFlow(flow, stats) {
  if (stats) updateStats(stats);
  currentFlows.unshift(flow);
  if (currentFlows.length > 25) currentFlows.pop();

  renderThreatTable();
}

function renderThreatTable() {
  const tbody = document.getElementById("threatTableBody");
  if (!tbody) return;
  tbody.innerHTML = "";

  currentFlows.forEach((f, idx) => {
    const tr = document.createElement("tr");

    let badgeClass = "badge-exfil";
    if (f.class.includes("SCAN")) badgeClass = "badge-scan";
    else if (f.class.includes("BEACON")) badgeClass = "badge-beacon";
    else if (!f.is_threat) badgeClass = "badge-benign";

    tr.innerHTML = `
      <td>${f.timestamp}</td>
      <td><span class="threat-badge ${badgeClass}">${f.class}</span></td>
      <td>${(f.confidence * 100).toFixed(1)}%</td>
      <td>${f.latency_ms} ms</td>
      <td><button class="btn-inspect" onclick="openInspectorByIndex(${idx})">Inspect</button></td>
    `;
    tbody.appendChild(tr);
  });
}

function openInspectorByIndex(idx) {
  const flow = currentFlows[idx];
  if (flow) openInspector(flow);
}

// Flow Forensic Inspector
function openInspector(flow) {
  const drawer = document.getElementById("inspectorDrawer");
  drawer.classList.add("open");

  // Stage 1: Packets
  const pList = document.getElementById("inspectPackets");
  pList.innerHTML = "";
  if (flow.packets) {
    flow.packets.forEach((p, i) => {
      const div = document.createElement("div");
      div.className = "packet-item";
      const dirSymbol = p.direction === 1 ? "↑ (Client)" : "↓ (Server)";
      div.innerHTML = `<span>Pkt ${String(i+1).padStart(2, '0')}</span> <span>${p.size} B</span> <span>${dirSymbol}</span>`;
      pList.appendChild(div);
    });
  }

  // Stage 2: Features
  const fContainer = document.getElementById("inspectFeatures");
  fContainer.innerHTML = "";
  if (flow.features) {
    const featsToShow = [
      { label: "Mean Size", val: `${Math.round(flow.features.mean_packet_size)} B` },
      { label: "Mean IAT", val: `${(flow.features.mean_iat * 1000).toFixed(2)} ms` },
      { label: "Upload Ratio", val: `${(flow.features.fwd_bwd_byte_ratio || 0).toFixed(1)}x` },
      { label: "Packet Rate", val: `${Math.round(flow.features.packet_rate || 0)} /s` },
      { label: "Byte Rate", val: `${((flow.features.byte_rate || 0) / 1024).toFixed(1)} KB/s` },
      { label: "TCP Window", val: `${Math.round(flow.features.mean_tcp_window || 65535)}` }
    ];

    featsToShow.forEach(f => {
      const item = document.createElement("div");
      item.className = "feat-item";
      item.innerHTML = `<span>${f.label}</span><strong>${f.val}</strong>`;
      fContainer.appendChild(item);
    });
  }

  // Stage 3: Attribution & Evidence
  const resDiv = document.getElementById("inspectResult");
  resDiv.textContent = `${flow.class} (${(flow.confidence * 100).toFixed(1)}% Confidence)`;
  resDiv.style.color = flow.is_threat ? "#ef4444" : "#10b981";

  const evList = document.getElementById("inspectEvidence");
  evList.innerHTML = "";
  if (flow.evidence) {
    flow.evidence.forEach(ev => {
      const li = document.createElement("li");
      li.textContent = ev;
      evList.appendChild(li);
    });
  }

  // Granular Latency
  const latDiv = document.getElementById("inspectLatency");
  latDiv.innerHTML = `
    <strong>Granular Latency:</strong> Extraction: 0.15ms | Model Inference: ${(flow.latency_ms - 0.15).toFixed(2)}ms | Total: ${flow.latency_ms}ms
  `;
}

function closeInspector() {
  document.getElementById("inspectorDrawer").classList.remove("open");
}

function loadInitialMockThreats() {
  const initial = [
    {
      id: "FLOW-98214",
      timestamp: "22:58:12",
      class: "DATA_EXFIL",
      confidence: 0.974,
      is_threat: true,
      latency_ms: 0.72,
      evidence: [
        "Abnormal upstream upload bias (14.8x forward/backward ratio vs ~0.15x normal baseline)",
        "Unusually rapid machine-gun packet intervals (Mean IAT: 1.10ms vs ~45ms normal)",
        "Continuous full-MTU packet saturation (Max size: 1440 bytes)"
      ],
      features: {
        mean_packet_size: 1380,
        mean_iat: 0.0011,
        fwd_bwd_byte_ratio: 14.8,
        packet_rate: 1850,
        byte_rate: 940000,
        mean_tcp_window: 32768
      },
      packets: [
        { size: 1440, direction: 1, iat_ms: 0.0 },
        { size: 1440, direction: 1, iat_ms: 1.1 },
        { size: 1440, direction: 1, iat_ms: 2.2 },
        { size: 64, direction: -1, iat_ms: 3.1 },
        { size: 1440, direction: 1, iat_ms: 4.2 }
      ]
    },
    {
      id: "FLOW-98201",
      timestamp: "22:57:44",
      class: "C2_BEACON",
      confidence: 0.912,
      is_threat: true,
      latency_ms: 0.61,
      evidence: [
        "Near-zero timing jitter (StdDev: 0.85ms) indicating automated programmatic transmission",
        "Deterministic periodic interval signature matching botnet heartbeat"
      ],
      features: {
        mean_packet_size: 112,
        mean_iat: 0.050,
        fwd_bwd_byte_ratio: 1.1,
        packet_rate: 20,
        byte_rate: 2200,
        mean_tcp_window: 16384
      },
      packets: [
        { size: 128, direction: 1, iat_ms: 0.0 },
        { size: 96, direction: -1, iat_ms: 50.1 },
        { size: 128, direction: 1, iat_ms: 100.2 },
        { size: 96, direction: -1, iat_ms: 150.3 }
      ]
    }
  ];

  currentFlows = initial;
  renderThreatTable();
}

function showNotification(msg) {
  console.log(`[CipherSieve Alert]: ${msg}`);
}
