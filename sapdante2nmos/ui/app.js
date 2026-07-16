"use strict";

const $ = (id) => document.getElementById(id);

let running = true;

// ---------------------------------------------------------------- tabs

document.querySelectorAll("#tabs .tab").forEach((btn) => {
  btn.onclick = () => {
    document.querySelectorAll("#tabs .tab").forEach((b) =>
      b.classList.toggle("active", b === btn));
    document.querySelectorAll(".tabpane").forEach((p) =>
      (p.hidden = p.id !== "tab-" + btn.dataset.tab));
  };
});

// ---------------------------------------------------------------- polling

async function refresh() {
  let state;
  try {
    state = await (await fetch("/api/state")).json();
  } catch {
    setChip($("registry-chip"), "err", "backend offline");
    return;
  }

  running = state.running;
  $("btn-toggle").textContent = running ? "Stop" : "Start";

  const chip = $("registry-chip");
  chip.title = state.registrar || "";
  const auto = state.registrar_source === "discovered" ? " (auto)" : "";
  if (!state.registrar) {
    if (state.auto_registrar) {
      setChip(chip, "warn", "discovering registry…");
    } else {
      setChip(chip, "warn", "no registry configured");
    }
  } else if (state.registry_ok) {
    setChip(chip, "ok", "registry connected" + auto);
  } else {
    setChip(chip, "err",
      "registry " + (state.registry_error || "unreachable") + auto);
  }
  $("sap-chip").textContent = "SAP: " + state.sap_packets;

  const dante = state.dante || { receivers: [], devices: [], apply_mode: false };
  if (dante.apply_mode) {
    setChip($("apply-chip"), "err", "ARMED");
  } else {
    setChip($("apply-chip"), "warn", "DRY-RUN");
  }

  $("count-senders").textContent = state.streams.length || "";
  $("count-receivers").textContent = dante.receivers.length || "";
  $("count-devices").textContent = dante.devices.length || "";

  renderStreams(state.streams);
  renderReceivers(dante.receivers);
  renderDevices(dante);
  $("log").textContent = state.log.slice().reverse().join("\n");
}

function setChip(el, cls, text) {
  el.className = "chip " + cls;
  el.textContent = text;
}

// ---------------------------------------------------------------- senders

let lastStreamsJson = "";

function renderStreams(streams) {
  const tbody = $("stream-rows");
  $("empty-senders").hidden = streams.length > 0;

  // Only rebuild the table when the data actually changed — a rebuild in the
  // middle of a click would swallow it. The "last seen" cells update below.
  const json = JSON.stringify(streams);
  if (json === lastStreamsJson) {
    tbody.querySelectorAll("td[data-ts]").forEach((td) => {
      td.textContent = ago(parseFloat(td.dataset.ts));
    });
    return;
  }
  lastStreamsJson = json;
  tbody.innerHTML = "";

  for (const s of streams) {
    const tr = document.createElement("tr");
    if (s.stale) tr.classList.add("stale");

    let status;
    if (s.stale) status = badge("stale", "stale");
    else if (s.external) status = badge("ext", "in registry (external)");
    else if (s.registered) status = badge("reg", "registered");
    else status = badge("pending", "pending");

    tr.innerHTML = `
      <td class="name" title="${esc(s.name)}">${esc(s.name) || "<i>unnamed</i>"}</td>
      <td class="mono">${esc(s.mcast)}</td>
      <td class="mono">${s.port ?? ""}</td>
      <td>${esc(s.format)}</td>
      <td class="mono">${esc(s.src_ip)}</td>
      <td>${badge(s.origin, s.origin === "sap" ? "SAP" : "manual")}</td>
      <td>${status}</td>
      <td data-ts="${s.last_seen}">${ago(s.last_seen)}</td>
      <td>
        <button class="icon" data-sdp="${s.hash}" title="View SDP">SDP</button>
        <button class="icon" data-del="${s.hash}" title="Remove stream">&#10005;</button>
      </td>`;
    tbody.appendChild(tr);
  }
}

// ---------------------------------------------------------------- receivers

let lastReceiversJson = "";

function renderReceivers(receivers) {
  const tbody = $("receiver-rows");
  $("empty-receivers").hidden = receivers.length > 0;

  const json = JSON.stringify(receivers);
  if (json === lastReceiversJson) return;
  lastReceiversJson = json;
  tbody.innerHTML = "";

  for (const r of receivers) {
    const tr = document.createElement("tr");
    const chRange = r.channels > 1
      ? `${r.dante_base_channel}–${r.dante_base_channel + r.channels - 1}`
      : `${r.dante_base_channel}`;

    let patch = r.active ? badge("reg", "active") : badge("pending", "idle");

    let flow = "";
    if (r.active) {
      const fmap = {
        connected: ["reg", "audio"],
        no_audio: ["stale", "NO AUDIO"],
        none: ["stale", "no flow"],
        unknown: ["pending", "polling…"],
      };
      const [cls, label] = fmap[r.stream_health] || fmap.unknown;
      flow = badge(cls, label);
    }

    const sender = r.sender_id
      ? `<div class="sub mono" title="connected sender">← ${esc(r.sender_id)}</div>` : "";

    let lastCmd = "";
    if (r.last_result && r.last_result.length) {
      if (r.last_ack === true) lastCmd = badge("reg", "ACK ok");
      else if (r.last_ack === false) lastCmd = badge("stale", "NO ACK");
      else lastCmd = badge("sap", "dry-run");
      lastCmd += ` <button class="icon" data-rxdetail="${r.nmos_id}">details</button>`;
    }

    tr.innerHTML = `
      <td class="name" title="${esc(r.label)}">${esc(r.label)}</td>
      <td class="mono">${esc(r.dante_device_ip)}</td>
      <td class="mono">${chRange} (${r.channels}ch)</td>
      <td>${patch}</td>
      <td>${flow}</td>
      <td class="mono">${esc(r.source)}${sender}</td>
      <td>${lastCmd}</td>
      <td>
        <button class="icon" data-rxdel="${r.nmos_id}" title="Remove receiver">&#10005;</button>
      </td>`;
    tbody.appendChild(tr);
  }
}

// ---------------------------------------------------------------- devices

let lastDevicesJson = "";

function renderDevices(dante) {
  const tbody = $("device-rows");
  $("empty-devices").hidden = dante.devices.length > 0;
  $("devices-updated").textContent = dante.devices_updated
    ? "last scan: " + ago(dante.devices_updated) : "";

  const json = JSON.stringify(dante.devices);
  if (json === lastDevicesJson) return;
  lastDevicesJson = json;
  tbody.innerHTML = "";
  const dl = $("device-ips");
  dl.innerHTML = "";

  for (const d of dante.devices) {
    const tr = document.createElement("tr");
    const rate = d.sample_rate ? (d.sample_rate / 1000) + " kHz" : "";
    const prefix = d.mcast_prefix
      ? `<span class="mono">239.${d.mcast_prefix}.x.x</span>
         <button class="icon" data-prefix="${esc(d.ip)}" data-pfxval="${d.mcast_prefix}"
           title="Set AES67 multicast prefix">edit</button>`
      : "—";
    tr.innerHTML = `
      <td class="name">${esc(d.name)}</td>
      <td class="mono">${esc(d.ip)}</td>
      <td>${esc(d.model)}</td>
      <td>${d.aes67_enabled ? badge("reg", "yes") : badge("stale", "no")}</td>
      <td>${prefix}</td>
      <td class="mono">${rate}</td>
      <td class="mono">${d.rx_channels}</td>
      <td class="mono">${d.tx_channels}</td>
      <td><button class="icon" data-mkrx="${esc(d.ip)}" data-mkname="${esc(d.name)}"
        title="Create receiver for this device">+ RX</button></td>`;
    tbody.appendChild(tr);

    const opt = document.createElement("option");
    opt.value = d.ip;
    opt.label = d.name;
    dl.appendChild(opt);
  }
}

// ---------------------------------------------------------------- helpers

function badge(cls, text) {
  return `<span class="badge ${cls}">${text}</span>`;
}

function esc(s) {
  return (s || "").toString().replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function ago(ts) {
  const d = Math.max(0, Date.now() / 1000 - ts);
  if (d < 5) return "now";
  if (d < 90) return Math.round(d) + "s ago";
  if (d < 5400) return Math.round(d / 60) + "m ago";
  return Math.round(d / 3600) + "h ago";
}

// ---------------------------------------------------------------- modals

function openModal(id) { $(id).hidden = false; }
function closeModals() {
  document.querySelectorAll(".modal-backdrop").forEach((m) => (m.hidden = true));
}

document.addEventListener("click", (e) => {
  if (e.target.matches("[data-close]")) closeModals();
  if (e.target.classList.contains("modal-backdrop")) closeModals();
});

// ---------------------------------------------------------------- add SDP

$("btn-add").onclick = () => {
  $("sdp-text").value = "";
  $("add-error").textContent = "";
  $("sdp-file").value = "";
  openModal("modal-add");
};

$("sdp-file").onchange = async (e) => {
  const file = e.target.files[0];
  if (file) $("sdp-text").value = await file.text();
};

$("btn-add-confirm").onclick = async () => {
  const sdp = $("sdp-text").value.trim();
  if (!sdp) {
    $("add-error").textContent = "Please paste an SDP or choose a file.";
    return;
  }
  const r = await fetch("/api/sdp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sdp }),
  });
  const res = await r.json();
  if (!r.ok) {
    $("add-error").textContent = res.error || "Failed to add SDP.";
    return;
  }
  closeModals();
  refresh();
};

// ---------------------------------------------------------------- add receiver

function openAddReceiver(prefillIp, prefillName) {
  $("rx-label").value = prefillName ? `${prefillName} RX 1-2` : "";
  $("rx-ip").value = prefillIp || "";
  $("rx-base").value = 1;
  $("rx-channels").value = 2;
  $("add-rx-error").textContent = "";
  openModal("modal-add-rx");
}

$("btn-add-rx").onclick = () => openAddReceiver();

$("btn-add-rx-confirm").onclick = async () => {
  const body = {
    label: $("rx-label").value.trim(),
    dante_device_ip: $("rx-ip").value.trim(),
    dante_base_channel: parseInt($("rx-base").value, 10) || 0,
    channels: parseInt($("rx-channels").value, 10) || 2,
  };
  const r = await fetch("/api/receivers", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const res = await r.json();
  if (!r.ok) {
    $("add-rx-error").textContent = res.error || "Failed to add receiver.";
    return;
  }
  closeModals();
  refresh();
};

// ---------------------------------------------------------------- settings

$("btn-settings").onclick = async () => {
  $("settings-error").textContent = "";
  const [cfg, ifaces] = await Promise.all([
    (await fetch("/api/config")).json(),
    (await fetch("/api/interfaces")).json(),
  ]);
  const sel = $("cfg-interface");
  sel.innerHTML = '<option value="">auto (default route)</option>';
  for (const i of ifaces) {
    const o = document.createElement("option");
    o.value = i.ip;
    o.textContent = `${i.ip}  (${i.name})`;
    sel.appendChild(o);
  }
  sel.value = cfg.interface_ip || "";
  $("cfg-registrar").value = cfg.registrar;
  $("cfg-dnsdomain").value = cfg.dns_sd_domain || "";
  $("cfg-dnsns").value = cfg.dns_sd_nameserver || "";
  $("cfg-autoreg").checked = !!cfg.auto_registrar;
  $("cfg-apply").checked = !!cfg.apply_mode;
  $("discover-results").innerHTML = "";
  $("cfg-group").value = cfg.sap_group;
  $("cfg-sapport").value = cfg.sap_port;
  $("cfg-timeout").value = cfg.stream_timeout;
  $("cfg-httpport").value = cfg.http_port;
  openModal("modal-settings");
};

$("btn-settings-save").onclick = async () => {
  const body = {
    registrar: $("cfg-registrar").value.trim(),
    auto_registrar: $("cfg-autoreg").checked,
    dns_sd_domain: $("cfg-dnsdomain").value.trim(),
    dns_sd_nameserver: $("cfg-dnsns").value.trim(),
    interface_ip: $("cfg-interface").value,
    sap_group: $("cfg-group").value.trim(),
    sap_port: parseInt($("cfg-sapport").value, 10) || 9875,
    stream_timeout: parseInt($("cfg-timeout").value, 10) || 120,
    http_port: parseInt($("cfg-httpport").value, 10) || 8085,
    apply_mode: $("cfg-apply").checked,
  };
  const r = await fetch("/api/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const res = await r.json().catch(() => ({}));
    $("settings-error").textContent = res.error || "Failed to save settings.";
    return;
  }
  closeModals();
  refresh();
};

$("btn-discover").onclick = async () => {
  const box = $("discover-results");
  box.innerHTML = '<span class="note">Searching&hellip;</span>';
  const domain = encodeURIComponent($("cfg-dnsdomain").value.trim());
  let res;
  try {
    const r = await fetch("/api/discover?domain=" + domain);
    res = await r.json();
    if (!r.ok) throw new Error(res.error || r.statusText);
  } catch (e) {
    box.innerHTML = `<span class="note">Discovery failed: ${esc(e.message)}</span>`;
    return;
  }
  if (!res.candidates.length) {
    box.innerHTML = `<span class="note">No registry found via DNS-SD
      (domains tried: ${esc(res.domains.join(", ") || "none")})</span>`;
    return;
  }
  box.innerHTML = "";
  for (const c of res.candidates) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "candidate";
    b.textContent = `${c.name}  —  ${c.url}  (pri ${c.priority})`;
    b.onclick = () => { $("cfg-registrar").value = c.url; };
    box.appendChild(b);
  }
};

// ---------------------------------------------------------------- table actions

let lastState = null;

$("stream-rows").addEventListener("click", async (e) => {
  const btn = e.target.closest("button");
  if (!btn) return;

  if (btn.dataset.sdp) {
    const r = await fetch("/api/sdp/" + btn.dataset.sdp);
    if (!r.ok) return;
    $("sdp-view-title").textContent = "SDP";
    $("sdp-view").textContent = await r.text();
    openModal("modal-sdp");
  }

  if (btn.dataset.del) {
    if (!confirm("Remove this stream (and unregister it from the registry)?")) return;
    await fetch("/api/stream/" + btn.dataset.del, { method: "DELETE" });
    refresh();
  }
});

$("receiver-rows").addEventListener("click", async (e) => {
  const btn = e.target.closest("button");
  if (!btn) return;

  if (btn.dataset.rxdel) {
    if (!confirm("Remove this receiver (and unregister it from the registry)?")) return;
    await fetch("/api/receiver/" + btn.dataset.rxdel, { method: "DELETE" });
    refresh();
  }

  if (btn.dataset.rxdetail) {
    const state = await (await fetch("/api/state")).json();
    const rx = (state.dante.receivers || []).find(
      (r) => r.nmos_id === btn.dataset.rxdetail);
    if (!rx) return;
    const lines = (rx.last_result || []).map((s) => {
      let l = s.step;
      if ("ack" in s) l += `   ack=${s.ack}`;
      l += "\n  " + s.hex;
      if (s.response) l += "\n  resp: " + s.response;
      return l;
    });
    $("sdp-view-title").textContent = `Last Dante commands — ${rx.label}`;
    $("sdp-view").textContent = lines.join("\n\n") || "(none)";
    openModal("modal-sdp");
  }
});

$("device-rows").addEventListener("click", async (e) => {
  const btn = e.target.closest("button");
  if (!btn) return;
  if (btn.dataset.mkrx) {
    openAddReceiver(btn.dataset.mkrx, btn.dataset.mkname);
  }
  if (btn.dataset.prefix) {
    const cur = btn.dataset.pfxval;
    const val = prompt(`AES67 multicast prefix for ${btn.dataset.prefix}\n` +
      `Address range becomes 239.<prefix>.x.x (0–255).\n` +
      `Writing requires ARMED mode.`, cur);
    if (val === null) return;
    const prefix = parseInt(val, 10);
    if (isNaN(prefix) || prefix < 0 || prefix > 255) {
      alert("Prefix must be a number 0–255.");
      return;
    }
    const r = await fetch("/api/devices/prefix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip: btn.dataset.prefix, prefix }),
    });
    const res = await r.json();
    if (!r.ok) alert(res.message || "Failed to set prefix.");
    refresh();
  }
});

$("btn-refresh-devices").onclick = async () => {
  await fetch("/api/devices/refresh", { method: "POST" });
};

$("btn-copy-sdp").onclick = () => {
  navigator.clipboard.writeText($("sdp-view").textContent);
};

// ---------------------------------------------------------------- misc

$("btn-toggle").onclick = async () => {
  await fetch(running ? "/api/stop" : "/api/start", { method: "POST" });
  refresh();
};

$("log-toggle").onclick = () => {
  const log = $("log");
  log.hidden = !log.hidden;
  $("log-arrow").innerHTML = log.hidden ? "&#9662;" : "&#9652;";
};

refresh();
setInterval(refresh, 2000);
