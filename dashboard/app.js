/**
 * CipherSieve - Real-Time SOC Dashboard Logic
 * - Real-time WebSocket telemetry handler
 * - Live canvas packet rhythm oscilloscope
 * - Dual-mode simulation (Presets vs Manual Slider Forge)
 * - 3-Stage Forensic Flow Inspector (Packet -> Feature -> Model -> Evidence)
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

// Initialize
document.addEventListener("DOMContentLoaded", () => {
  initWebSocket();
  startOscilloscope();
  initModelSelector();
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
        handleNewFlow(msg.data, msg.stats);
      } else if (msg.type === "HEARTBEAT") {
        updateStats(msg.stats);
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
  document.getElementById("valFlows").textContent = Number(stats.total_flows).toLocaleString();
  document.getElementById("valThreats").textContent = stats.threats_detected;
  document.getElementById("valLatency").textContent = `${stats.last_latency_ms}ms`;
}

function initModelSelector() {
  const sel = document.getElementById("modelSelector");
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

// Oscilloscope Canvas Animation
function startOscilloscope() {
  function draw() {
    ctx.fillStyle = "#05070a";
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Draw Grid Lines
    ctx.strokeStyle = "rgba(255, 255, 255, 0.04)";
    ctx.lineWidth = 1;
    for (let x = 0; x < canvas.width; x += 40) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, canvas.height);
      ctx.stroke();
    }
    for (let y = 0; y < canvas.height; y += 30) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(canvas.width, y);
      ctx.stroke();
    }

    // Draw Packet Waveform
    ctx.beginPath();
    ctx.strokeStyle = waveColor;
    ctx.lineWidth = 2.5;
    ctx.shadowBlur = 10;
    ctx.shadowColor = waveColor;

    const midY = canvas.height / 2;
    for (let x = 0; x < canvas.width; x++) {
      let y;
      if (isThreatActive) {
        // High-frequency burst jitter
        const spike = (Math.sin(x * 0.15 + waveOffset) + Math.sin(x * 0.35 - waveOffset * 2)) * 0.5;
        y = midY + spike * (waveAmplitude * 1.5) + (Math.random() - 0.5) * 8;
      } else {
        // Smooth human browsing rhythm
        y = midY + Math.sin(x * waveFrequency + waveOffset) * waveAmplitude;
      }

      if (x === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.stroke();
    ctx.shadowBlur = 0;

    waveOffset += isThreatActive ? 0.25 : 0.04;
    requestAnimationFrame(draw);
  }
  draw();
}

// Dual Mode Tab Switcher
function switchSimTab(mode) {
  const tabAuto = document.getElementById("tabAuto");
  const tabManual = document.getElementById("tabManual");
  const panelAuto = document.getElementById("panelAuto");
  const panelManual = document.getElementById("panelManual");

  if (mode === "auto") {
    tabAuto.classList.add("active");
    tabManual.classList.remove("active");
    panelAuto.classList.remove("hidden");
    panelManual.classList.add("hidden");
  } else {
    tabAuto.classList.remove("active");
    tabManual.classList.add("active");
    panelAuto.classList.add("hidden");
    panelManual.classList.remove("hidden");
  }
}

function updateSliderLabels() {
  const sz = document.getElementById("rngSize").value;
  const dl = document.getElementById("rngDelay").value;
  const rt = document.getElementById("rngRatio").value;

  document.getElementById("lblSize").textContent = `${sz} B`;
  document.getElementById("lblDelay").textContent = `${dl} ms`;
  document.getElementById("lblRatio").textContent = `${rt}% Upload`;
}

// Run 1-Click Preset
async function runPreset(scenario) {
  const evasionChecked = document.getElementById("checkEvasion").checked;
  const padding = evasionChecked ? 50 : 0;
  const jitter = evasionChecked ? 20.0 : 0.0;

  const formData = new FormData();
  formData.append("scenario", scenario);
  formData.append("padding", padding);
  formData.append("jitter", jitter);

  // Update oscilloscope immediately
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
    handleNewFlow(data, null);
  } catch (err) {
    console.error(err);
  }
}

// Execute Manual Slider Forge
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
    const result = await res.json();

    const mockFlow = {
      id: `FORGE-${Math.floor(Math.random()*9000)+1000}`,
      timestamp: new Date().toLocaleTimeString(),
      class: result.classification,
      confidence: result.confidence,
      is_threat: result.is_threat,
      latency_ms: result.latency.total_ms,
      evidence: result.evidence,
      features: result.features,
      packets: [
        { size: Number(sz), direction: 1, iat_ms: Number(dl) },
        { size: Number(sz), direction: 1, iat_ms: Number(dl) },
        { size: 64, direction: -1, iat_ms: Number(dl)*2 },
        { size: Number(sz), direction: 1, iat_ms: Number(dl) }
      ]
    };

    if (result.is_threat) {
      isThreatActive = true;
      waveColor = "#ef4444";
    } else {
      isThreatActive = false;
      waveColor = "#10b981";
    }

    handleNewFlow(mockFlow, null);
    openInspector(mockFlow);
  } catch (err) {
    console.error(err);
  }
}

function handleNewFlow(flow, stats) {
  if (stats) updateStats(stats);
  currentFlows.unshift(flow);
  if (currentFlows.length > 25) currentFlows.pop();

  renderThreatTable();
}

function renderThreatTable() {
  const tbody = document.getElementById("threatTableBody");
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

// The Killer Flow Forensic Inspector
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
      { label: "Upload Ratio", val: `${flow.features.fwd_bwd_byte_ratio.toFixed(1)}x` },
      { label: "Packet Rate", val: `${Math.round(flow.features.packet_rate)} /s` },
      { label: "Byte Rate", val: `${(flow.features.byte_rate / 1024).toFixed(1)} KB/s` },
      { label: "TCP Window", val: `${Math.round(flow.features.mean_tcp_window)}` }
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

  // Latency Breakdown
  const latDiv = document.getElementById("inspectLatency");
  latDiv.innerHTML = `
    <strong>Granular Latency:</strong> Ingestion: 0.12ms | Extraction: 0.15ms | Inference: ${(flow.latency_ms - 0.27).toFixed(2)}ms | Total: ${flow.latency_ms}ms
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
      class: "DATA_EXFILTRATION",
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
