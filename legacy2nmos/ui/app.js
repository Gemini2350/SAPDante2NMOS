"use strict";

const $ = (id) => document.getElementById(id);

let running = true;

// ---------------------------------------------------------------- tabs

document.querySelectorAll("#tabs .tab").forEach((btn) => {
  btn.onclick = () => {
    document.querySelectorAll("#tabs .tab").forEach((b) =>
      b.classList.toggle("active", b === btn));
    document.querySelectorAll(".pane").forEach((p) =>
      (p.hidden = p.id !== "pane-" + btn.dataset.tab));
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
  if (state.version) {
    $("settings-version").textContent = "Legacy2NMOS v" + state.version;
    $("app-version").textContent = "v" + state.version;
  }

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

  const dante = state.dante || { receivers: [], devices: [] };

  $("devices-updated").textContent = dante.devices_updated
    ? "last scan: " + ago(dante.devices_updated) : "";

  $("count-sap").textContent = state.streams.length || "";
  $("count-dante").textContent = (dante.devices || []).length || "";

  window._lastStreams = state.streams;
  renderSap(state.streams);
  renderDante(dante);
  renderLawo(state.lawo || { devices: [] });
  renderCymatic(state.cymatic || { devices: [] });
  $("log").textContent = state.log.slice().reverse().join("\n");
}

function setChip(el, cls, text) {
  el.className = "chip " + cls;
  el.textContent = text;
}

// ---------------------------------------------------------------- SAP Discovery tab

let lastSapSig = "";

function renderSap(streams) {
  $("empty-sap").hidden = streams.length > 0;
  const sig = JSON.stringify(streams.map((s) => [s.hash, s.name, s.mcast, s.port,
    s.format, s.src_ip, s.origin, s.registered, s.external, s.stale]));
  const body = $("sap-rows");
  if (sig !== lastSapSig) {
    lastSapSig = sig;
    body.innerHTML = streams.map((s) => senderRow(s, true)).join("");
  }
  body.querySelectorAll("td[data-ts]").forEach((td) => {
    td.textContent = ago(parseFloat(td.dataset.ts));
  });
}

// ---------------------------------------------------------------- Dante tab (device-centric)

let lastDanteSig = "";

function renderDante(dante) {
  const devices = dante.devices || [];
  const receivers = dante.receivers || [];
  window._lastDevices = devices;
  $("empty-dante").hidden = devices.length > 0;

  const sig = JSON.stringify([devices, receivers,
    (window._lastStreams || []).map((s) => [s.hash, s.src_ip, s.registered,
      s.external, s.stale])]);
  if (sig === lastDanteSig) {
    $("device-list").querySelectorAll("td[data-ts]").forEach((td) => {
      td.textContent = ago(parseFloat(td.dataset.ts));
    });
    return;
  }
  lastDanteSig = sig;

  const streams = window._lastStreams || [];
  const sendersByIp = {};
  for (const s of streams) (sendersByIp[s.src_ip] ||= []).push(s);
  const rxByIp = {};
  for (const r of receivers) (rxByIp[r.dante_device_ip] ||= []).push(r);

  const dl = $("device-ips");
  dl.innerHTML = "";
  for (const d of devices) {
    const o = document.createElement("option");
    o.value = d.ip; o.label = d.name; dl.appendChild(o);
  }

  const list = $("device-list");
  list.innerHTML = "";
  for (const d of devices) {
    list.appendChild(deviceCard(d, sendersByIp[d.ip] || [], rxByIp[d.ip] || []));
  }
}

function deviceCard(d, senders, receivers) {
  const card = document.createElement("div");
  card.className = "device-card";
  const rate = d.sample_rate ? (d.sample_rate / 1000) + " kHz" : "";
  const prefix = d.mcast_prefix
    ? `<span class="mono">239.${d.mcast_prefix}.x.x</span>
       <button class="icon" data-prefix="${esc(d.ip)}" data-pfxval="${d.mcast_prefix}"
         title="Set AES67 multicast prefix">edit</button>`
    : "";

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
        ${d.manual ? badge("manual", "manual") : ""}
        ${d.aes67_enabled ? badge("reg", "AES67") : badge("stale", "no AES67")}
        ${d.locked ? badge("pending", "🔒 locked") : ""}
        <span class="device-meta">${prefix}</span>
        <span class="device-meta note">${esc(d.model)} · ${rate}
          · ${d.tx_channels}tx/${d.rx_channels}rx</span>
      </div>
      <div class="device-actions">
        <button class="icon" data-createtx="${esc(d.ip)}" data-txname="${esc(d.name)}"
          title="Create a multicast TX flow (NMOS sender) on this device">+ Create TX</button>
        <button class="icon" data-mkrx="${esc(d.ip)}" data-mkname="${esc(d.name)}"
          title="Add an NMOS receiver on this device">+ Add RX</button>
        ${d.manual ? `<button class="icon" data-devdel="${esc(d.ip)}"
          title="Remove this manually added device">&#10005;</button>` : ""}
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
    ${showSrc ? `<td>${badge(s.origin, { sap: "SAP", manual: "manual",
      "dante-tx": "Dante TX" }[s.origin] || s.origin)}</td>` : ""}
    ${src}
    <td>${status}</td>
    <td data-ts="${s.last_seen}">${ago(s.last_seen)}</td>
    <td class="row-actions">
      <button class="icon" data-rename="${s.hash}" data-rnval="${esc(s.name)}"
        title="Set the NMOS name">name</button>
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
    const fmap = { connected: ["reg", "audio"], warning: ["pending", "warning"],
      no_audio: ["stale", "NO AUDIO"],
      none: ["idle", "no status"], unknown: ["idle", "no status"] };
    const [cls, label] = fmap[r.stream_health] || fmap.unknown;
    const codes = (r.rx_status_codes || []).join(",");
    flow = `<span title="Dante subscription codes: ${codes || "?"} `
      + `(10=audio, 14=no audio, 0=none)">${badge(cls, label)}</span>`;
  }
  const sender = r.sender_id
    ? `<div class="sub mono" title="connected sender">← ${esc(r.sender_id)}</div>` : "";
  let lastCmd = "";
  if (r.last_result && r.last_result.length) {
    if (r.last_ack === true) lastCmd = badge("reg", "ACK ok");
    else if (r.last_ack === false) lastCmd = badge("stale", "NO ACK");
    else lastCmd = badge("sap", "sent");
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

// ---------------------------------------------------------------- Lawo tab

let lastLawoSig = "";

function renderLawo(lawo) {
  const devices = lawo.devices || [];
  $("empty-lawo").hidden = devices.length > 0;
  const sig = JSON.stringify(devices);
  if (sig === lastLawoSig) return;
  lastLawoSig = sig;
  const list = $("lawo-list");
  list.innerHTML = "";
  for (const d of devices) {
    const card = document.createElement("div");
    card.className = "device-card";
    card.innerHTML = `
      <div class="device-head">
        <div class="device-title">
          <span class="device-name">${esc(d.label || d.host)}</span>
          <span class="mono device-ip">${esc(d.host)}:${d.port}</span>
        </div>
        <div class="device-actions">
          <button class="icon" data-lawobrowse="${esc(d.host)}" data-lawoport="${d.port}"
            title="Browse the Ember+ tree">Browse</button>
          <button class="icon" data-lawodel="${esc(d.host)}" data-lawoport="${d.port}"
            title="Remove device">&#10005;</button>
        </div>
      </div>
      <div class="lawo-tree" id="tree-${esc(d.host)}-${d.port}"></div>`;
    list.appendChild(card);
  }
}

async function lawoBrowse(host, port, path, container) {
  const q = `host=${encodeURIComponent(host)}&port=${port}` +
    (path ? `&path=${encodeURIComponent(path)}` : "");
  container.innerHTML = '<div class="note">loading…</div>';
  let res;
  try {
    res = await (await fetch("/api/lawo/browse?" + q)).json();
  } catch {
    container.innerHTML = '<div class="note">connection failed</div>';
    return;
  }
  if (res.error) {
    container.innerHTML = `<div class="note">error: ${esc(res.error)}</div>`;
    return;
  }
  container.innerHTML = "";
  for (const el of res.elements) container.appendChild(lawoNode(host, port, el));
}

function lawoNode(host, port, el) {
  const row = document.createElement("div");
  row.className = "tree-row";
  const isParam = el.kind === "parameter";
  const label = esc(el.identifier || "#" + el.number);
  const desc = el.description ? ` <span class="note">${esc(el.description)}</span>` : "";
  if (isParam) {
    const v = el.value === null || el.value === undefined ? "" : el.value;
    row.innerHTML = `<span class="tree-key">${label}</span>${desc}
      <span class="tree-val mono">${esc(String(v))}</span>
      <button class="icon" data-lawoset="${esc(el.path)}"
        data-lawohost="${esc(host)}" data-lawoport="${port}"
        data-lawoval="${esc(String(v))}" title="Set value">set</button>
      <span class="note mono">${esc(el.path)}</span>`;
  } else {
    row.innerHTML = `<span class="tree-toggle" data-lawoexpand="${esc(el.path)}"
      data-lawohost="${esc(host)}" data-lawoport="${port}">▸</span>
      <span class="tree-key">${label}</span>${desc}
      <span class="note mono">${esc(el.path)}</span>
      <div class="tree-children" hidden></div>`;
  }
  return row;
}

// ---------------------------------------------------------------- Cymatic tab

let lastCymaticSig = "";

function renderCymatic(cymatic) {
  const devices = cymatic.devices || [];
  $("empty-cymatic").hidden = devices.length > 0;
  const sig = JSON.stringify(devices);
  if (sig === lastCymaticSig) return;
  lastCymaticSig = sig;
  const list = $("cymatic-list");
  list.innerHTML = "";
  for (const d of devices) {
    const card = document.createElement("div");
    card.className = "device-card";
    card.innerHTML = `
      <div class="device-head">
        <div class="device-title">
          <span class="device-name">${esc(d.label || d.host)}</span>
          <span class="mono device-ip">${esc(d.host)}</span>
        </div>
        <div class="device-actions">
          <button class="icon" data-cymload="${esc(d.host)}"
            title="Read sources/outputs">Refresh</button>
          <button class="icon" data-cymttl="${esc(d.host)}"
            title="Force multicast TTL to 64">TTL→64</button>
          <button class="icon" data-cymdel="${esc(d.host)}"
            title="Remove device">&#10005;</button>
        </div>
      </div>
      <div class="device-body" id="cym-${cssId(d.host)}">
        <div class="lane-empty">click Refresh to read streams</div>
      </div>`;
    list.appendChild(card);
  }
}

function cssId(s) { return s.replace(/[^a-zA-Z0-9]/g, "_"); }

async function cymaticLoad(host) {
  const box = document.getElementById("cym-" + cssId(host));
  box.innerHTML = '<div class="lane-empty">loading…</div>';
  let s;
  try {
    s = await (await fetch("/api/cymatic/snapshot?host=" + encodeURIComponent(host))).json();
  } catch { box.innerHTML = '<div class="lane-empty">connection failed</div>'; return; }
  if (!s.reachable) {
    box.innerHTML = `<div class="lane-empty">unreachable: ${esc(s.error || "no response")}</div>`;
    return;
  }
  const ttlWarn = s.ttl_ok === false
    ? ` ${badge("stale", "TTL≠64")}` : (s.ttl_ok ? ` ${badge("reg", "TTL 64")}` : "");
  const srcRows = s.sources.length ? s.sources.map((x) =>
    `<tr><td class="name">${esc(x.name)}</td><td class="mono">${esc(x.multicast)}</td>
      <td>${x.enabled ? badge("reg", "on") : badge("pending", "off")}</td>
      <td>${badge(statusCls(x.status), esc(String(x.status)))}</td>
      <td class="mono">ttl ${x.ttl}</td></tr>`).join("")
    : `<tr><td class="lane-empty">none</td></tr>`;
  const outRows = s.outputs.length ? s.outputs.map((x) =>
    `<tr><td class="name">${esc(x.name)}</td>
      <td class="mono">${esc(x.stream_path || x.manual_sdp ? "SDP set" : "—")}</td>
      <td>${badge(statusCls(x.status), esc(String(x.status)))}</td></tr>`).join("")
    : `<tr><td class="lane-empty">none</td></tr>`;
  box.innerHTML = `
    <div class="lane"><div class="lane-title">Sources (TX) &rarr; NMOS senders${ttlWarn}</div>
      <table><tbody>${srcRows}</tbody></table></div>
    <div class="lane"><div class="lane-title">Outputs (RX) &larr; NMOS receivers</div>
      <table><tbody>${outRows}</tbody></table></div>`;
}

function statusCls(s) {
  if (s === "transmitting" || s === "receiving") return "reg";
  if (s === "error" || s === "collision" || s === "no decoders") return "stale";
  return "pending";
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

// receiver add is triggered from device cards (+ Add RX)

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

// ---------------------------------------------------------------- create TX flow

let txDeviceIp = "";

function openCreateTx(ip, name) {
  txDeviceIp = ip;
  $("tx-devname").textContent = `${name} (${ip})`;
  $("tx-ch1").value = 1;
  $("tx-ch2").value = 2;
  $("tx-port").value = 5004;
  $("tx-name").value = "";
  // prefill multicast from the device's prefix if known
  const dev = (window._lastDevices || []).find((x) => x.ip === ip);
  $("tx-mcast").value = dev && dev.mcast_prefix
    ? `239.${dev.mcast_prefix}.1.1` : "239.69.1.1";
  $("tx-error").textContent = "";
  openModal("modal-tx");
}

$("btn-tx-confirm").onclick = async () => {
  const ch1 = parseInt($("tx-ch1").value, 10);
  const ch2 = parseInt($("tx-ch2").value, 10);
  const channels = [ch1];
  if (ch2 > 0) channels.push(ch2);
  const body = {
    ip: txDeviceIp,
    channels,
    multicast: $("tx-mcast").value.trim(),
    port: parseInt($("tx-port").value, 10) || 5004,
    name: $("tx-name").value.trim(),
  };
  const r = await fetch("/api/devices/tx", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const res = await r.json();
  if (!r.ok) {
    $("tx-error").textContent = res.message || "Failed to create flow.";
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
  } else if (d.rename) {
    const val = prompt("NMOS name for this sender\n" +
      "(empty = use the device's own name)", d.rnval || "");
    if (val === null) return;
    await fetch("/api/stream/" + d.rename + "/name", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: val.trim() }),
    });
    refresh();
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
    openCreateTx(d.createtx, d.txname);
  } else if (d.devdel) {
    if (!confirm(`Remove manually added device ${d.devdel}?`)) return;
    await fetch("/api/devices/manual/" + d.devdel, { method: "DELETE" });
    refresh();
  } else if (d.prefix) {
    const val = prompt(`AES67 multicast prefix for ${d.prefix}\n` +
      `Address range becomes 239.<prefix>.x.x (0–255).\nWrites to the device immediately.`,
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
$("sap-rows").addEventListener("click", handleAction);

$("btn-refresh-devices").onclick = async () => {
  await fetch("/api/devices/refresh", { method: "POST" });
};

// ---------------------------------------------------------------- Lawo actions

$("btn-add-lawo").onclick = () => {
  $("lawo-label").value = "";
  $("lawo-host").value = "";
  $("lawo-port").value = 9000;
  $("lawo-error").textContent = "";
  openModal("modal-lawo");
};

$("btn-lawo-confirm").onclick = async () => {
  const body = {
    label: $("lawo-label").value.trim(),
    host: $("lawo-host").value.trim(),
    port: parseInt($("lawo-port").value, 10) || 9000,
  };
  if (!body.host) { $("lawo-error").textContent = "Enter a host/IP."; return; }
  const r = await fetch("/api/lawo/device", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const res = await r.json();
  if (!r.ok) { $("lawo-error").textContent = res.message || "Failed."; return; }
  closeModals();
  lastLawoSig = "";  // force re-render
  refresh();
};

// ---------------------------------------------------------------- Cymatic actions

$("btn-add-cymatic").onclick = () => {
  $("cym-label").value = "";
  $("cym-host").value = "";
  $("cym-error").textContent = "";
  openModal("modal-cymatic");
};

$("btn-cym-confirm").onclick = async () => {
  const body = { label: $("cym-label").value.trim(), host: $("cym-host").value.trim() };
  if (!body.host) { $("cym-error").textContent = "Enter an address."; return; }
  const r = await fetch("/api/cymatic/device", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const res = await r.json();
  if (!r.ok) { $("cym-error").textContent = res.message || "Failed."; return; }
  closeModals();
  lastCymaticSig = "";
  refresh();
};

$("cymatic-list").addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-cymload],[data-cymttl],[data-cymdel]");
  if (!btn) return;
  const d = btn.dataset;
  if (d.cymload) {
    cymaticLoad(d.cymload);
  } else if (d.cymttl) {
    const r = await fetch("/api/cymatic/ttl", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host: d.cymttl }),
    });
    const res = await r.json();
    if (!r.ok) alert("TTL set failed: " + (res.error || r.statusText));
    else alert("TTL set to 64" + (res.changed && res.changed.length
      ? " (" + res.changed.join(", ") + ")" : " (already 64)"));
    cymaticLoad(d.cymttl);
  } else if (d.cymdel) {
    if (!confirm(`Remove Cymatic device ${d.cymdel}?`)) return;
    await fetch("/api/cymatic/device/" + encodeURIComponent(d.cymdel), { method: "DELETE" });
    lastCymaticSig = "";
    refresh();
  }
});

$("lawo-list").addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-lawobrowse],[data-lawoexpand],[data-lawoset],[data-lawodel]");
  if (!btn) return;
  const d = btn.dataset;

  if (d.lawobrowse) {
    lawoBrowse(d.lawobrowse, d.lawoport,
      null, document.getElementById(`tree-${d.lawobrowse}-${d.lawoport}`));
  } else if (d.lawoexpand) {
    const children = btn.parentElement.querySelector(".tree-children");
    if (!children.hidden) { children.hidden = true; btn.textContent = "▸"; return; }
    children.hidden = false; btn.textContent = "▾";
    if (!children.dataset.loaded) {
      children.dataset.loaded = "1";
      lawoBrowse(d.lawohost, d.lawoport, d.lawoexpand, children);
    }
  } else if (d.lawoset) {
    const val = prompt(`Set ${d.lawoset}`, d.lawoval);
    if (val === null) return;
    const isNum = /^-?\d+$/.test(val.trim());
    const r = await fetch("/api/lawo/set", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host: d.lawohost, port: parseInt(d.lawoport, 10),
        path: d.lawoset, value: isNum ? parseInt(val, 10) : val,
        type: isNum ? "int" : "string" }),
    });
    if (!r.ok) alert("Set failed: " + ((await r.json()).error || r.statusText));
  } else if (d.lawodel) {
    if (!confirm(`Remove Lawo device ${d.lawodel}:${d.lawoport}?`)) return;
    await fetch(`/api/lawo/device/${d.lawodel}/${d.lawoport}`, { method: "DELETE" });
    lastLawoSig = "";
    refresh();
  }
});

$("btn-add-device").onclick = () => {
  $("dev-ip").value = "";
  $("dev-error").textContent = "";
  openModal("modal-device");
};

$("btn-device-confirm").onclick = async () => {
  const ip = $("dev-ip").value.trim();
  if (!ip) { $("dev-error").textContent = "Enter a device IP."; return; }
  const r = await fetch("/api/devices/manual", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip }),
  });
  const res = await r.json();
  if (!r.ok) { $("dev-error").textContent = res.message || "Failed to add device."; return; }
  closeModals();
  refresh();
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
