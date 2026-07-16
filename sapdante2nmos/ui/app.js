"use strict";

const $ = (id) => document.getElementById(id);

let running = true;

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
    setChip(chip, "warn", state.auto_registrar
      ? "discovering registry…" : "no registry configured");
  } else if (state.registry_ok) {
    setChip(chip, "ok", "registry connected" + auto);
  } else {
    setChip(chip, "err",
      "registry " + (state.registry_error || "unreachable") + auto);
  }
  $("sap-chip").textContent = "SAP: " + state.sap_packets;

  const dante = state.dante || { receivers: [], devices: [], apply_mode: false };
  setChip($("apply-chip"), dante.apply_mode ? "err" : "warn",
    dante.apply_mode ? "ARMED" : "DRY-RUN");

  $("devices-updated").textContent = dante.devices_updated
    ? "last device scan: " + ago(dante.devices_updated) : "";

  renderDeviceCentric(state.streams, dante);
  $("log").textContent = state.log.slice().reverse().join("\n");
}

function setChip(el, cls, text) {
  el.className = "chip " + cls;
  el.textContent = text;
}

// ---------------------------------------------------------------- device-centric view

let lastSig = "";

function renderDeviceCentric(streams, dante) {
  const devices = dante.devices || [];
  const receivers = dante.receivers || [];

  // Rebuild only when structure/status changes (not on every "last seen" tick),
  // otherwise a rebuild mid-click would swallow the interaction.
  const sig = JSON.stringify([
    devices, receivers,
    streams.map((s) => [s.hash, s.name, s.mcast, s.port, s.format, s.src_ip,
      s.origin, s.registered, s.external, s.stale]),
  ]);
  if (sig !== lastSig) {
    lastSig = sig;
    buildDeviceCentric(streams, devices, receivers);
  }
  // Live-update the "last seen" cells in place.
  document.querySelectorAll("td[data-ts]").forEach((td) => {
    td.textContent = ago(parseFloat(td.dataset.ts));
  });
}

function buildDeviceCentric(streams, devices, receivers) {
  const list = $("device-list");
  list.innerHTML = "";

  // Index senders by source IP and receivers by device IP.
  const sendersByIp = {};
  for (const s of streams) (sendersByIp[s.src_ip] ||= []).push(s);
  const rxByIp = {};
  for (const r of receivers) (rxByIp[r.dante_device_ip] ||= []).push(r);

  const deviceIps = new Set(devices.map((d) => d.ip));

  // datalist for the add-receiver IP field
  const dl = $("device-ips");
  dl.innerHTML = "";
  for (const d of devices) {
    const o = document.createElement("option");
    o.value = d.ip; o.label = d.name; dl.appendChild(o);
  }

  for (const d of devices) {
    list.appendChild(deviceCard(d, sendersByIp[d.ip] || [], rxByIp[d.ip] || []));
  }

  // Senders whose source is not a discovered Dante device, plus receivers
  // pointing at an unknown IP.
  const other = streams.filter((s) => !deviceIps.has(s.src_ip));
  const otherRx = receivers.filter((r) => !deviceIps.has(r.dante_device_ip));
  $("other-section").hidden = other.length === 0 && otherRx.length === 0;
  const otbody = $("other-rows");
  otbody.innerHTML = "";
  for (const s of other) otbody.insertAdjacentHTML("beforeend", senderRow(s, true));
  for (const r of otherRx) {
    otbody.insertAdjacentHTML("beforeend",
      `<tr><td colspan="9" class="sub">RX ${esc(r.label)} → unknown device
       ${esc(r.dante_device_ip)} ${receiverInline(r)}</td></tr>`);
  }

  $("empty-all").hidden = devices.length > 0 || streams.length > 0;
}

function deviceCard(d, senders, receivers) {
  const card = document.createElement("div");
  card.className = "device-card";
  const rate = d.sample_rate ? (d.sample_rate / 1000) + " kHz" : "";
  const autoBtn = `<button class="icon ${d.auto_prefix ? "on" : ""}"
      data-autopfx="${esc(d.ip)}" data-autoval="${d.auto_prefix ? 1 : 0}"
      title="Auto: follow the patched multicast's prefix on NMOS connect">
      Auto${d.auto_prefix ? " ✓" : ""}</button>`;
  const prefix = d.mcast_prefix
    ? `<span class="mono">239.${d.mcast_prefix}.x.x</span>
       <button class="icon" data-prefix="${esc(d.ip)}" data-pfxval="${d.mcast_prefix}"
         title="Set AES67 multicast prefix">edit</button> ${autoBtn}`
    : autoBtn;

  const txRows = senders.length
    ? `<table><tbody>${senders.map((s) => senderRow(s, false)).join("")}</tbody></table>`
    : `<div class="lane-empty">no transmitted flows</div>`;
  const rxRows = receivers.length
    ? `<table><tbody>${receivers.map((r) => receiverRow(r)).join("")}</tbody></table>`
    : `<div class="lane-empty">no receivers — add one with “+ Add RX”</div>`;

  card.innerHTML = `
    <div class="device-head">
      <div class="device-title">
        <span class="device-name">${esc(d.name) || "&lt;unnamed&gt;"}</span>
        <span class="mono device-ip">${esc(d.ip)}</span>
        ${d.aes67_enabled ? badge("reg", "AES67") : badge("stale", "no AES67")}
        <span class="device-meta">${prefix}</span>
        <span class="device-meta note">${esc(d.model)} · ${rate}
          · ${d.tx_channels}tx/${d.rx_channels}rx</span>
      </div>
      <div class="device-actions">
        <button class="icon" data-createtx="${esc(d.ip)}" data-txname="${esc(d.name)}"
          title="Create a multicast TX flow (NMOS sender) on this device">+ Create TX</button>
        <button class="icon" data-mkrx="${esc(d.ip)}" data-mkname="${esc(d.name)}"
          title="Add an NMOS receiver on this device">+ Add RX</button>
      </div>
    </div>
    <div class="device-body">
      <div class="lane">
        <div class="lane-title">Sending (TX) &rarr; NMOS senders <span class="count">${senders.length}</span></div>
        ${txRows}
      </div>
      <div class="lane">
        <div class="lane-title">Receiving (RX) &larr; NMOS receivers <span class="count">${receivers.length}</span></div>
        ${rxRows}
      </div>
    </div>`;
  return card;
}

function senderRow(s, showSrc) {
  let status;
  if (s.stale) status = badge("stale", "stale");
  else if (s.external) status = badge("ext", "in registry (external)");
  else if (s.registered) status = badge("reg", "registered");
  else status = badge("pending", "pending");
  const src = showSrc ? `<td class="mono">${esc(s.src_ip)}</td>` : "";
  return `<tr class="${s.stale ? "stale" : ""}">
    <td class="name" title="${esc(s.name)}">${esc(s.name) || "<i>unnamed</i>"}</td>
    <td class="mono">${esc(s.mcast)}:${s.port ?? ""}</td>
    <td>${esc(s.format)}</td>
    ${showSrc ? `<td>${badge(s.origin, s.origin === "sap" ? "SAP" : "manual")}</td>` : ""}
    ${src}
    <td>${status}</td>
    <td data-ts="${s.last_seen}">${ago(s.last_seen)}</td>
    <td class="row-actions">
      <button class="icon" data-sdp="${s.hash}" title="View SDP">SDP</button>
      <button class="icon" data-del="${s.hash}" title="Remove stream">&#10005;</button>
    </td></tr>`;
}

function receiverRow(r) {
  const chRange = r.channels > 1
    ? `${r.dante_base_channel}–${r.dante_base_channel + r.channels - 1}`
    : `${r.dante_base_channel}`;
  const patch = r.active ? badge("reg", "active") : badge("pending", "idle");
  let flow = "";
  if (r.active) {
    const fmap = { connected: ["reg", "audio"], no_audio: ["stale", "NO AUDIO"],
      none: ["stale", "no flow"], unknown: ["pending", "polling…"] };
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
  return `<tr>
    <td class="name" title="${esc(r.label)}">${esc(r.label)}</td>
    <td class="mono">ch ${chRange} (${r.channels})</td>
    <td>${patch}</td>
    <td>${flow}</td>
    <td class="mono">${esc(r.source)}${sender}</td>
    <td>${lastCmd}</td>
    <td class="row-actions">
      <button class="icon" data-rxdel="${r.nmos_id}" title="Remove receiver">&#10005;</button>
    </td></tr>`;
}

function receiverInline(r) {
  return r.active ? badge("reg", "active") : badge("pending", "idle");
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
  $("cfg-recheck").value = cfg.registry_recheck_interval;
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
    registry_recheck_interval: parseInt($("cfg-recheck").value, 10) || 300,
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

async function handleAction(e) {
  const btn = e.target.closest("button");
  if (!btn) return;
  const d = btn.dataset;

  if (d.sdp) {
    const r = await fetch("/api/sdp/" + d.sdp);
    if (!r.ok) return;
    $("sdp-view-title").textContent = "SDP";
    $("sdp-view").textContent = await r.text();
    openModal("modal-sdp");
  } else if (d.del) {
    if (!confirm("Remove this stream (and unregister it from the registry)?")) return;
    await fetch("/api/stream/" + d.del, { method: "DELETE" });
    refresh();
  } else if (d.rxdel) {
    if (!confirm("Remove this receiver (and unregister it from the registry)?")) return;
    await fetch("/api/receiver/" + d.rxdel, { method: "DELETE" });
    refresh();
  } else if (d.rxdetail) {
    const state = await (await fetch("/api/state")).json();
    const rx = (state.dante.receivers || []).find((r) => r.nmos_id === d.rxdetail);
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
  } else if (d.mkrx) {
    openAddReceiver(d.mkrx, d.mkname);
  } else if (d.createtx) {
    alert("Creating a multicast TX flow on " + d.txname + " (" + d.createtx +
      ") is not wired up yet — the Dante 'create flow' command still needs to " +
      "be captured. Once done, this button creates the flow and it appears as " +
      "an NMOS sender.");
  } else if (d.autopfx) {
    await fetch("/api/devices/auto_prefix", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip: d.autopfx, enabled: d.autoval !== "1" }),
    });
    refresh();
  } else if (d.prefix) {
    const val = prompt(`AES67 multicast prefix for ${d.prefix}\n` +
      `Address range becomes 239.<prefix>.x.x (0–255).\nWriting requires ARMED mode.`,
      d.pfxval);
    if (val === null) return;
    const prefix = parseInt(val, 10);
    if (isNaN(prefix) || prefix < 0 || prefix > 255) {
      alert("Prefix must be a number 0–255.");
      return;
    }
    const r = await fetch("/api/devices/prefix", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip: d.prefix, prefix }),
    });
    const res = await r.json();
    if (!r.ok) alert(res.message || "Failed to set prefix.");
    refresh();
  }
}

$("device-list").addEventListener("click", handleAction);
$("other-rows").addEventListener("click", handleAction);

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
