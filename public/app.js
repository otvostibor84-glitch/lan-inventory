const inventory = document.querySelector("#inventory");
const dialog = document.querySelector("#form-dialog");
const form = document.querySelector("#editor");
const fields = document.querySelector("#fields");
const message = document.querySelector("#message");
let data = [];

const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const field = (name,label,value="",type="text",full=false) => `<div class="field ${full?"full":""}"><label>${label}</label><input name="${name}" type="${type}" value="${esc(value)}"></div>`;
const select = (name,label,value,options) => `<div class="field"><label>${label}</label><select name="${name}">${options.map(([v,l])=>`<option value="${v}" ${v===value?"selected":""}>${l}</option>`).join("")}</select></div>`;
const notes = value => `<div class="field full"><label>Megjegyzés</label><textarea name="notes">${esc(value)}</textarea></div>`;

async function api(url, options={}) {
  const response = await fetch(url, {headers:{"Content-Type":"application/json"}, ...options});
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || "Hiba történt");
  return body;
}

async function load() {
  data = await api("/api/inventory");
  render();
}

function deviceLine(d) {
  return `<div class="device"><div><strong>${esc(d.mac)}</strong><span class="device-meta">${esc(d.ip_address||"Nincs IP")} ${esc(d.name||"")}${d.vlan_id?` · VLAN ${esc(d.vlan_id)}`:""}</span></div><button class="tiny secondary" onclick="editDevice(${d.id})" title="MAC-cím szerkesztése">✎</button></div>`;
}

function deviceList(devices) {
  if (!devices.length) return "—";
  if (devices.length === 1) return deviceLine(devices[0]);
  return `<details class="mac-list"><summary>${devices.length} MAC-cím</summary><div class="mac-list-body">${devices.map(deviceLine).join("")}</div></details>`;
}

function render() {
  if (!data.length) { inventory.innerHTML='<div class="empty">Még nincs switch. Kezdd a fő switch felvitelével.</div>'; return; }
  inventory.innerHTML=data.map(sw=>`<article class="switch-card">
    <div class="switch-head"><div><h2>${esc(sw.name)}</h2><div class="muted">${esc(sw.management_ip||"Nincs IP")} · ${esc(sw.model||"Ismeretlen típus")} · ${esc(sw.location||"Nincs helyszín")}</div></div>
      <div class="toolbar"><button class="tiny secondary" onclick="importFdb(${sw.id})">MAC import</button><button class="tiny" onclick="editSwitch(${sw.id})">Szerkesztés</button><button class="tiny" onclick="addPort(${sw.id})">+ Port</button><button class="tiny danger" onclick="removeItem('switches',${sw.id},'A switch minden portjával és MAC-címével együtt törlődik. Biztos?')">Törlés</button></div></div>
    <div class="ports"><table><thead><tr><th>Port</th><th>Közeg / mód</th><th>VLAN</th><th>Kapcsolat</th><th>MAC-címek</th><th>Művelet</th></tr></thead><tbody>
      ${sw.ports.length?sw.ports.map(p=>`<tr><td><strong>${esc(p.name)}</strong><br><span class="muted">${esc(p.label||"")}</span></td><td>${esc(p.media)}<br><span class="badge">${esc(p.mode)}</span></td><td>${esc(p.vlan_id||"—")} ${esc(p.vlan_name||"")}</td><td>${esc(p.remote_switch||"—")} ${esc(p.remote_port||"")}</td><td>${deviceList(p.devices)}</td><td><div class="toolbar"><button class="tiny" onclick="addDevice(${p.id})">+ MAC</button><button class="tiny secondary" onclick="editPort(${p.id})">✎</button><button class="tiny danger" onclick="removeItem('ports',${p.id},'Törlöd a portot és a hozzá tartozó MAC-címeket?')">×</button></div></td></tr>`).join(""):'<tr><td colspan="6" class="muted">Nincs rögzített port.</td></tr>'}
    </tbody></table></div></article>`).join("");
}

function openEditor(title, html, endpoint, method, extra={}) {
  document.querySelector("#dialog-title").textContent=title;
  fields.innerHTML=`<div class="grid">${html}</div>`;
  form.onsubmit=async e=>{e.preventDefault(); try { const body=Object.fromEntries(new FormData(form)); await api(endpoint,{method,body:JSON.stringify({...extra,...body})}); dialog.close(); await load(); } catch(err){showError(err.message);} };
  dialog.showModal();
}

document.querySelector("#add-switch").onclick=()=>openEditor("Új switch",field("name","Név")+field("management_ip","Menedzsment IP")+field("model","Típus")+field("base_mac","Saját MAC")+field("location","Helyszín", "", "text", true)+notes(),"/api/switches","POST");
window.editSwitch=id=>{const x=data.find(s=>s.id===id);openEditor("Switch szerkesztése",field("name","Név",x.name)+field("management_ip","Menedzsment IP",x.management_ip)+field("model","Típus",x.model)+field("base_mac","Saját MAC",x.base_mac)+field("location","Helyszín",x.location,"text",true)+notes(x.notes),`/api/switches/${id}`,"PUT")};

const portFields=x=>field("name","Port neve",x.name)+field("label","Elnevezés",x.label)+select("media","Közeg",x.media||"rez",[["rez","Réz"],["optika","Optika"],["egyeb","Egyéb"]])+select("mode","Port mód",x.mode||"ismeretlen",[["ismeretlen","Ismeretlen"],["access","Access"],["trunk","Trunk"],["uplink","Uplink"]])+field("vlan_id","VLAN ID",x.vlan_id,"number")+field("vlan_name","VLAN név",x.vlan_name)+field("remote_switch","Másik switch",x.remote_switch)+field("remote_port","Másik port",x.remote_port)+notes(x.notes);
window.addPort=switch_id=>openEditor("Új port",portFields({}),"/api/ports","POST",{switch_id});
window.editPort=id=>{const x=data.flatMap(s=>s.ports).find(p=>p.id===id);openEditor("Port szerkesztése",portFields(x),`/api/ports/${id}`,"PUT")};

const deviceFields=x=>field("mac","MAC-cím",x.mac)+field("name","Eszköz neve",x.name)+field("ip_address","IP-cím",x.ip_address)+field("vlan_id","VLAN ID",x.vlan_id,"number")+notes(x.notes);
window.addDevice=port_id=>openEditor("Új MAC-cím",deviceFields({}),"/api/devices","POST",{port_id});
window.editDevice=id=>{const x=data.flatMap(s=>s.ports).flatMap(p=>p.devices).find(d=>d.id===id);openEditor("MAC-cím szerkesztése",deviceFields(x),`/api/devices/${id}`,"PUT")};

const importBox=(label,help)=>`<div class="field full"><label>${label}</label><textarea name="text" style="min-height:260px" placeholder="${esc(help)}"></textarea></div>`;
window.importFdb=switch_id=>openEditor("MAC-tábla importálása",importBox("Másold ide a switch teljes MAC-tábláját","D-Link vagy 3Com MAC-tábla"),"/api/import/fdb","POST",{switch_id});
document.querySelector("#import-arp").onclick=()=>openEditor("ARP-tábla importálása",importBox("Másold ide a teljes arp -a kimenetet","Internet Address   Physical Address   Type"),"/api/import/arp","POST");

window.removeItem=async(type,id,text)=>{if(!confirm(text))return;try{await api(`/api/${type}/${id}`,{method:"DELETE"});await load()}catch(err){showError(err.message)}};
document.querySelector("#cancel").onclick=()=>dialog.close();
function showError(text){message.textContent=text;message.style.display="block";setTimeout(()=>message.style.display="none",5000)}
load().catch(e=>showError(e.message));
