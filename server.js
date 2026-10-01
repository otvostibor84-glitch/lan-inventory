const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const net = require("net");
const snmp = require("net-snmp");
const { DatabaseSync } = require("node:sqlite");

const app = express();
const port = Number(process.env.PORT || 3000);
const host = process.env.BIND_ADDRESS || "127.0.0.1";
const dataDir = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new DatabaseSync(path.join(dataDir, "inventory.sqlite"));
db.exec(`
  PRAGMA foreign_keys = ON;
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS switches (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    management_ip TEXT,
    model TEXT,
    base_mac TEXT,
    location TEXT,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY,
    switch_id INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    label TEXT,
    media TEXT NOT NULL DEFAULT 'rez' CHECK(media IN ('rez','optika','egyeb')),
    mode TEXT NOT NULL DEFAULT 'ismeretlen' CHECK(mode IN ('access','trunk','uplink','ismeretlen')),
    vlan_id INTEGER,
    vlan_name TEXT,
    remote_switch TEXT,
    remote_port TEXT,
    notes TEXT,
    UNIQUE(switch_id, name)
  );
  CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    port_id INTEGER NOT NULL REFERENCES ports(id) ON DELETE CASCADE,
    mac TEXT NOT NULL,
    name TEXT,
    ip_address TEXT,
    vlan_id INTEGER,
    notes TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(port_id, mac)
  );
`);

const schemaVersion = Number(db.prepare("PRAGMA user_version").get().user_version);
if (schemaVersion < 1) {
  db.exec(`
    BEGIN;
    ALTER TABLE devices RENAME TO devices_old;
    CREATE TABLE devices (
      id INTEGER PRIMARY KEY,
      port_id INTEGER NOT NULL REFERENCES ports(id) ON DELETE CASCADE,
      mac TEXT NOT NULL,
      name TEXT,
      ip_address TEXT,
      vlan_id INTEGER NOT NULL DEFAULT 1,
      notes TEXT,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(port_id, mac, vlan_id)
    );
    INSERT INTO devices (id,port_id,mac,name,ip_address,vlan_id,notes,updated_at)
      SELECT id,port_id,mac,name,ip_address,COALESCE(vlan_id,1),notes,updated_at FROM devices_old;
    DROP TABLE devices_old;
    PRAGMA user_version = 1;
    COMMIT;
  `);
}

if (schemaVersion < 2) {
  db.exec(`
    BEGIN;
    ALTER TABLE ports ADD COLUMN snmp_if_index INTEGER;
    ALTER TABLE ports ADD COLUMN link_state TEXT;
    ALTER TABLE ports ADD COLUMN link_speed_mbps INTEGER;
    ALTER TABLE ports ADD COLUMN snmp_updated_at TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_ports_switch_snmp_if
      ON ports(switch_id, snmp_if_index) WHERE snmp_if_index IS NOT NULL;
    PRAGMA user_version = 2;
    COMMIT;
  `);
}

db.exec(`
  CREATE TABLE IF NOT EXISTS arp_entries (
    mac TEXT PRIMARY KEY,
    ip_address TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

app.use(express.json({ limit: "1mb" }));

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

app.use((req, res, next) => {
  const user = process.env.APP_USER;
  const password = process.env.APP_PASSWORD;
  if (!user || !password) return next();
  const value = req.headers.authorization || "";
  const [scheme, encoded] = value.split(" ");
  let suppliedUser = "";
  let suppliedPassword = "";
  if (scheme === "Basic" && encoded) {
    [suppliedUser, suppliedPassword] = Buffer.from(encoded, "base64").toString().split(":", 2);
  }
  if (safeEqual(user, suppliedUser) && safeEqual(password, suppliedPassword)) return next();
  res.set("WWW-Authenticate", 'Basic realm="LAN Inventory"');
  return res.status(401).send("Bejelentkezés szükséges");
});

app.use(express.static(path.join(__dirname, "public")));

const clean = value => value === undefined || value === null ? null : String(value).trim() || null;
const integer = value => value === "" || value === undefined || value === null ? null : Number(value);
const mac = value => clean(value)?.toUpperCase().replace(/-/g, ":") || null;

function privateIpv4(value) {
  if (net.isIP(value) !== 4) return false;
  const [a, b] = value.split(".").map(Number);
  return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31);
}

function snmpOptions() {
  const community = process.env.SNMP_COMMUNITY;
  if (!community) throw new Error("Az SNMP nincs beállítva a szerveren (SNMP_COMMUNITY).");
  return {
    community,
    version: String(process.env.SNMP_VERSION || "2c").toLowerCase() === "1" ? snmp.Version1 : snmp.Version2c,
    timeout: Math.min(Math.max(Number(process.env.SNMP_TIMEOUT || 5000), 1000), 15000),
    retries: Math.min(Math.max(Number(process.env.SNMP_RETRIES || 1), 0), 3)
  };
}

function snmpSession(address) {
  if (!privateIpv4(address)) throw new Error("SNMP csak privát IPv4-címen használható.");
  const options = snmpOptions();
  return snmp.createSession(address, options.community, options);
}

const snmpValue = value => Buffer.isBuffer(value) ? value.toString() : value;
const snmpMac = value => Buffer.isBuffer(value) && value.length >= 6
  ? [...value.subarray(0, 6)].map(x => x.toString(16).padStart(2, "0")).join(":").toUpperCase()
  : null;

function snmpGet(session, oids) {
  return new Promise((resolve, reject) => session.get(oids, (error, varbinds) => {
    if (error) return reject(error);
    const problem = varbinds.find(snmp.isVarbindError);
    if (problem) return reject(new Error(snmp.varbindError(problem)));
    resolve(varbinds.map(v => snmpValue(v.value)));
  }));
}

function snmpTable(session, oid) {
  return new Promise((resolve, reject) => session.table(oid, 20, (error, table) => error ? reject(error) : resolve(table)));
}

function snmpWalk(session, oid, limit = 10000) {
  return new Promise((resolve, reject) => {
    const rows = [];
    session.subtree(oid, 20, varbinds => {
      for (const row of varbinds) {
        if (snmp.isVarbindError(row)) continue;
        if (rows.length >= limit) return true;
        rows.push(row);
      }
      return false;
    }, error => error ? reject(error) : resolve(rows));
  });
}

async function readSnmpInventory(sw) {
  const session = snmpSession(sw.management_ip);
  try {
    const [system, ifTable, bridgeRows] = await Promise.all([
      snmpGet(session, ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0"]),
      snmpTable(session, "1.3.6.1.2.1.2.2"),
      snmpWalk(session, "1.3.6.1.2.1.17.1.4.1.2")
    ]);
    const bridgeToIf = new Map(bridgeRows.map(row => [Number(row.oid.split(".").at(-1)), Number(row.value)]));
    const ifToBridge = new Map([...bridgeToIf].map(([bridgePort, ifIndex]) => [ifIndex, bridgePort]));
    const ports = Object.entries(ifTable).map(([index, row]) => {
      const ifIndex = Number(index);
      const portNumber = ifToBridge.get(ifIndex);
      return {
        port: portNumber || ifIndex,
        if_index: ifIndex,
        name: String(snmpValue(row["2"]) || `${portNumber || ifIndex}. port`),
        admin_state: Number(row["7"]) === 1 ? "up" : "down",
        link_state: Number(row["8"]) === 1 ? "up" : "down",
        speed_mbps: Math.round(Number(row["5"] || 0) / 1000000),
        interface_mac: snmpMac(row["6"])
      };
    }).filter(row => ifToBridge.size ? ifToBridge.has(row.if_index) : Number(ifTable[row.if_index]?.["3"]) === 6)
      .sort((a, b) => a.port - b.port);

    const [classicFdb, qFdb, vlanFdb] = await Promise.all([
      snmpWalk(session, "1.3.6.1.2.1.17.4.3.1.2").catch(() => []),
      snmpWalk(session, "1.3.6.1.2.1.17.7.1.2.2.1.2").catch(() => []),
      snmpWalk(session, "1.3.6.1.2.1.17.7.1.4.2.1.3").catch(() => [])
    ]);
    const fdbToVlan = new Map(vlanFdb.map(row => [Number(row.value), Number(row.oid.split(".").at(-1))]));
    const learned = [];
    const addMac = (bridgePort, address, vlan) => {
      const first = Number.parseInt(address.slice(0, 2), 16);
      const port = ports.find(p => p.if_index === bridgeToIf.get(Number(bridgePort)));
      if (port && (first & 1) === 0) learned.push({ port: port.port, if_index: port.if_index, mac: address, vlan: vlan || 1 });
    };
    if (qFdb.length) {
      for (const row of qFdb) {
        const suffix = row.oid.slice("1.3.6.1.2.1.17.7.1.2.2.1.2.".length).split(".").map(Number);
        if (suffix.length < 7) continue;
        addMac(Number(row.value), suffix.slice(1, 7).map(x => x.toString(16).padStart(2, "0")).join(":").toUpperCase(), fdbToVlan.get(suffix[0]) || 1);
      }
    } else {
      for (const row of classicFdb) {
        const bytes = row.oid.split(".").slice(-6).map(Number);
        addMac(Number(row.value), bytes.map(x => x.toString(16).padStart(2, "0")).join(":").toUpperCase(), 1);
      }
    }
    const unique = [...new Map(learned.map(row => [`${row.port}|${row.mac}|${row.vlan}`, row])).values()];
    return {
      system: { description: String(system[0] || ""), object_id: String(system[1] || ""), uptime_ticks: Number(system[2] || 0), name: String(system[3] || "") },
      ports,
      macs: unique,
      collected_at: new Date().toISOString()
    };
  } finally {
    session.close();
  }
}

function parseFdb(text) {
  const rows = [];
  const seen = new Set();
  const add = (port, address, vlan) => {
    const row = { port: Number(port), mac: mac(address), vlan: Number(vlan) || 1 };
    const key = `${row.port}|${row.mac}|${row.vlan}`;
    if (row.port > 0 && row.mac && !seen.has(key)) { seen.add(key); rows.push(row); }
  };
  let match;
  const dlink = /^\s*\d+\s+(\d+)\s+([0-9a-f:-]{17})\s+(\d+)\s+(?:Dynamic|Static)\b/gmi;
  while ((match = dlink.exec(text))) add(match[1], match[2], match[3]);
  const threeCom = /([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+(\d+)\s+Config\s+(?:dynamic|static)\s+(\d+)\s+(?:AGING|STATIC)/gi;
  while ((match = threeCom.exec(text))) add(match[3], match[1], match[2]);
  return rows;
}

function parseArp(text) {
  const rows = [];
  const arp = /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f-]{17})\s+(?:dynamic|static)\b/gmi;
  let match;
  while ((match = arp.exec(text))) {
    const address = mac(match[2]);
    const firstByte = Number.parseInt(address.slice(0, 2), 16);
    if (address !== "FF:FF:FF:FF:FF:FF" && (firstByte & 1) === 0) rows.push({ ip: match[1], mac: address });
  }
  return rows;
}

app.get("/api/inventory", (req, res) => {
  const switches = db.prepare("SELECT * FROM switches ORDER BY name COLLATE NOCASE").all();
  const ports = db.prepare("SELECT * FROM ports ORDER BY switch_id, name COLLATE NOCASE").all();
  const devices = db.prepare("SELECT * FROM devices ORDER BY port_id, mac").all();
  res.json(switches.map(sw => ({
    ...sw,
    ports: ports.filter(p => p.switch_id === sw.id).map(p => ({
      ...p,
      devices: devices.filter(d => d.port_id === p.id)
    }))
  })));
});

app.post("/api/switches", (req, res, next) => {
  try {
    const b = req.body;
    if (!clean(b.name)) return res.status(400).json({ error: "A switch neve kötelező." });
    const result = db.prepare("INSERT INTO switches (name, management_ip, model, base_mac, location, notes) VALUES (?, ?, ?, ?, ?, ?)")
      .run(clean(b.name), clean(b.management_ip), clean(b.model), mac(b.base_mac), clean(b.location), clean(b.notes));
    res.status(201).json({ id: Number(result.lastInsertRowid) });
  } catch (e) { next(e); }
});

app.put("/api/switches/:id", (req, res, next) => {
  try {
    const b = req.body;
    db.prepare("UPDATE switches SET name=?, management_ip=?, model=?, base_mac=?, location=?, notes=? WHERE id=?")
      .run(clean(b.name), clean(b.management_ip), clean(b.model), mac(b.base_mac), clean(b.location), clean(b.notes), req.params.id);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.delete("/api/switches/:id", (req, res) => {
  db.prepare("DELETE FROM switches WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

function snmpFailure(res, error) {
  const text = String(error?.message || "");
  const message = text.includes("SNMP_COMMUNITY") || text.includes("privát IPv4")
    ? text
    : text.toLowerCase().includes("timeout") || text.toLowerCase().includes("timed out")
      ? "Az SNMP-lekérdezés időtúllépéssel leállt. Ellenőrizd az SNMP állapotát, communityt és a UDP 161 elérését."
      : "Az SNMP-lekérdezés nem sikerült.";
  res.status(502).json({ error: message });
}

app.get("/api/switches/:id/snmp", async (req, res) => {
  try {
    const sw = db.prepare("SELECT * FROM switches WHERE id=?").get(req.params.id);
    if (!sw) return res.status(404).json({ error: "A switch nem található." });
    if (!sw.management_ip) return res.status(400).json({ error: "A switchnek nincs menedzsment IP-címe." });
    res.json(await readSnmpInventory(sw));
  } catch (error) { snmpFailure(res, error); }
});

app.post("/api/switches/:id/snmp/import", async (req, res) => {
  try {
    const switchId = integer(req.params.id);
    const sw = db.prepare("SELECT * FROM switches WHERE id=?").get(switchId);
    if (!sw) return res.status(404).json({ error: "A switch nem található." });
    if (!sw.management_ip) return res.status(400).json({ error: "A switchnek nincs menedzsment IP-címe." });
    const snapshot = await readSnmpInventory(sw);
    const findPort = db.prepare(`SELECT id FROM ports WHERE switch_id=? AND
      (snmp_if_index=? OR lower(name) IN (?,?,?))
      ORDER BY snmp_if_index IS NOT NULL DESC LIMIT 1`);
    const addPort = db.prepare(`INSERT INTO ports
      (switch_id,name,media,mode,snmp_if_index,link_state,link_speed_mbps,snmp_updated_at)
      VALUES (?,?,'rez','ismeretlen',?,?,?,CURRENT_TIMESTAMP)`);
    const updatePort = db.prepare(`UPDATE ports SET snmp_if_index=?,link_state=?,link_speed_mbps=?,snmp_updated_at=CURRENT_TIMESTAMP WHERE id=?`);
    const findIp = db.prepare("SELECT ip_address FROM arp_entries WHERE mac=?");
    const addDevice = db.prepare(`INSERT INTO devices (port_id,mac,ip_address,vlan_id)
      VALUES (?,?,?,?) ON CONFLICT(port_id,mac,vlan_id) DO UPDATE SET
      ip_address=COALESCE(excluded.ip_address,devices.ip_address),updated_at=CURRENT_TIMESTAMP`);
    const importedPorts = new Map();
    db.exec("BEGIN");
    try {
      for (const row of snapshot.ports) {
        const number = String(row.port);
        let portRow = findPort.get(switchId, row.if_index, number, `${number}. port`, `port ${number}`);
        if (!portRow) {
          portRow = { id: Number(addPort.run(switchId, `${number}. port`, row.if_index, row.link_state, row.speed_mbps).lastInsertRowid) };
        } else {
          updatePort.run(row.if_index, row.link_state, row.speed_mbps, portRow.id);
        }
        importedPorts.set(row.if_index, portRow.id);
      }
      for (const row of snapshot.macs) {
        const portId = importedPorts.get(row.if_index);
        if (!portId) continue;
        const arpRow = findIp.get(row.mac);
        addDevice.run(portId, row.mac, arpRow?.ip_address || null, row.vlan || 1);
      }
      db.exec("COMMIT");
    } catch (error) { db.exec("ROLLBACK"); throw error; }
    res.json({ ok: true, ports: snapshot.ports.length, macs: snapshot.macs.length, collected_at: snapshot.collected_at });
  } catch (error) { snmpFailure(res, error); }
});

app.post("/api/ports", (req, res, next) => {
  try {
    const b = req.body;
    if (!integer(b.switch_id) || !clean(b.name)) return res.status(400).json({ error: "A switch és a port neve kötelező." });
    const result = db.prepare(`INSERT INTO ports
      (switch_id,name,label,media,mode,vlan_id,vlan_name,remote_switch,remote_port,notes)
      VALUES (?,?,?,?,?,?,?,?,?,?)`).run(integer(b.switch_id), clean(b.name), clean(b.label), clean(b.media) || "rez", clean(b.mode) || "ismeretlen", integer(b.vlan_id), clean(b.vlan_name), clean(b.remote_switch), clean(b.remote_port), clean(b.notes));
    res.status(201).json({ id: Number(result.lastInsertRowid) });
  } catch (e) { next(e); }
});

app.put("/api/ports/:id", (req, res, next) => {
  try {
    const b = req.body;
    db.prepare(`UPDATE ports SET name=?,label=?,media=?,mode=?,vlan_id=?,vlan_name=?,remote_switch=?,remote_port=?,notes=? WHERE id=?`)
      .run(clean(b.name),clean(b.label),clean(b.media),clean(b.mode),integer(b.vlan_id),clean(b.vlan_name),clean(b.remote_switch),clean(b.remote_port),clean(b.notes),req.params.id);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.delete("/api/ports/:id", (req, res) => {
  db.prepare("DELETE FROM ports WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

app.post("/api/devices", (req, res, next) => {
  try {
    const b = req.body;
    if (!integer(b.port_id) || !mac(b.mac)) return res.status(400).json({ error: "A port és a MAC-cím kötelező." });
    const result = db.prepare("INSERT INTO devices (port_id,mac,name,ip_address,vlan_id,notes) VALUES (?,?,?,?,?,?)")
      .run(integer(b.port_id), mac(b.mac), clean(b.name), clean(b.ip_address), integer(b.vlan_id), clean(b.notes));
    res.status(201).json({ id: Number(result.lastInsertRowid) });
  } catch (e) { next(e); }
});

app.put("/api/devices/:id", (req, res, next) => {
  try {
    const b = req.body;
    db.prepare("UPDATE devices SET mac=?,name=?,ip_address=?,vlan_id=?,notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=?")
      .run(mac(b.mac),clean(b.name),clean(b.ip_address),integer(b.vlan_id),clean(b.notes),req.params.id);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.delete("/api/devices/:id", (req, res) => {
  db.prepare("DELETE FROM devices WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

app.post("/api/import/fdb", (req, res, next) => {
  try {
    const switchId = integer(req.body.switch_id);
    const rows = parseFdb(String(req.body.text || ""));
    if (!switchId || !rows.length) return res.status(400).json({ error: "Nem találtam importálható MAC-tábla sorokat." });
    const findPort = db.prepare("SELECT id FROM ports WHERE switch_id=? AND lower(name) IN (?,?,?) LIMIT 1");
    const addPort = db.prepare("INSERT INTO ports (switch_id,name,media,mode) VALUES (?,?,'rez','ismeretlen')");
    const findIp = db.prepare("SELECT ip_address FROM arp_entries WHERE mac=?");
    const addDevice = db.prepare(`INSERT INTO devices (port_id,mac,ip_address,vlan_id)
      VALUES (?,?,?,?) ON CONFLICT(port_id,mac,vlan_id) DO UPDATE SET
      ip_address=COALESCE(excluded.ip_address,devices.ip_address),updated_at=CURRENT_TIMESTAMP`);
    db.exec("BEGIN");
    try {
      for (const row of rows) {
        const p = String(row.port);
        let portRow = findPort.get(switchId, p, `${p}. port`, `port ${p}`);
        if (!portRow) portRow = { id: Number(addPort.run(switchId, `${p}. port`).lastInsertRowid) };
        const arpRow = findIp.get(row.mac);
        addDevice.run(portRow.id, row.mac, arpRow?.ip_address || null, row.vlan);
      }
      db.exec("COMMIT");
    } catch (error) { db.exec("ROLLBACK"); throw error; }
    res.json({ ok: true, imported: rows.length });
  } catch (e) { next(e); }
});

app.post("/api/import/arp", (req, res, next) => {
  try {
    const rows = parseArp(String(req.body.text || ""));
    if (!rows.length) return res.status(400).json({ error: "Nem találtam importálható ARP-bejegyzéseket." });
    const upsert = db.prepare(`INSERT INTO arp_entries (mac,ip_address) VALUES (?,?)
      ON CONFLICT(mac) DO UPDATE SET ip_address=excluded.ip_address,updated_at=CURRENT_TIMESTAMP`);
    db.exec("BEGIN");
    try {
      for (const row of rows) upsert.run(row.mac, row.ip);
      db.exec(`UPDATE devices SET ip_address=(SELECT ip_address FROM arp_entries WHERE arp_entries.mac=devices.mac),updated_at=CURRENT_TIMESTAMP
        WHERE EXISTS (SELECT 1 FROM arp_entries WHERE arp_entries.mac=devices.mac)`);
      db.exec("COMMIT");
    } catch (error) { db.exec("ROLLBACK"); throw error; }
    res.json({ ok: true, imported: rows.length });
  } catch (e) { next(e); }
});

app.use((err, req, res, next) => {
  console.error(err);
  const message = String(err.message || "Hiba").includes("UNIQUE") ? "Ez a bejegyzés már létezik." : "A művelet nem sikerült.";
  res.status(400).json({ error: message });
});

app.listen(port, host, () => console.log(`LAN Inventory: http://${host}:${port}`));
