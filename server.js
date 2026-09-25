const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { DatabaseSync } = require("node:sqlite");

const app = express();
const port = Number(process.env.PORT || 3000);
const host = process.env.BIND_ADDRESS || "127.0.0.1";
const dataDir = path.join(__dirname, "data");
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

app.use((err, req, res, next) => {
  console.error(err);
  const message = String(err.message || "Hiba").includes("UNIQUE") ? "Ez a bejegyzés már létezik." : "A művelet nem sikerült.";
  res.status(400).json({ error: message });
});

app.listen(port, host, () => console.log(`LAN Inventory: http://${host}:${port}`));
