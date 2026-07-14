'use strict';
/* ================= PRF crypto (port of PrfCrypto.cs) ================= */
const KEY = CryptoJS.enc.Latin1.parse("Md8ea20lPcftYwsl496q63x9");
const IV  = CryptoJS.enc.Latin1.parse("0Peyx825");
const DES_OPTS = { iv: IV, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding };
const BLOCK = 8;

function u8ToWA(u8){
  const words = [];
  for (let i = 0; i < u8.length; i++) words[i >>> 2] |= u8[i] << (24 - (i % 4) * 8);
  return CryptoJS.lib.WordArray.create(words, u8.length);
}
function waToU8(wa){
  const u8 = new Uint8Array(wa.sigBytes);
  for (let i = 0; i < wa.sigBytes; i++) u8[i] = (wa.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xFF;
  return u8;
}
function padToBlock(u8){
  const rem = u8.length % BLOCK;
  if (!rem) return u8;
  const p = new Uint8Array(u8.length + (BLOCK - rem)); p.set(u8); return p;
}
function prfDecrypt(u8){
  return waToU8(CryptoJS.TripleDES.decrypt({ ciphertext: u8ToWA(padToBlock(u8)) }, KEY, DES_OPTS));
}
function prfEncrypt(u8){
  return waToU8(CryptoJS.TripleDES.encrypt(u8ToWA(padToBlock(u8)), KEY, DES_OPTS).ciphertext);
}
function looksLikePrf(dec){
  if (!dec || dec.length < 8) return false;
  const limit = Math.min(dec.length, 512);
  for (let i = 0; i + 4 <= limit; i++)
    if (dec[i] === 115 && dec[i+1] === 101 && dec[i+2] === 116 && dec[i+3] === 32) return true; // "set "
  return false;
}
function tryDecrypt(enc){
  if (!enc || !enc.length || enc.length % BLOCK !== 0) return null;
  try { const dec = prfDecrypt(enc); return looksLikePrf(dec) ? dec : null; }
  catch { return null; }
}

/* Latin-1: lossless byte <-> char mapping, like Encoding.GetEncoding("ISO-8859-1") */
function bytesToLatin1(u8){
  let s = '';
  for (let i = 0; i < u8.length; i += 8192)
    s += String.fromCharCode.apply(null, u8.subarray(i, i + 8192));
  return s;
}
function latin1ToBytes(s){
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i) & 0xFF;
  return u8;
}

/* ================= config parsing (port of PrfConfig.cs) ================= */
const CFG_RX = /\b(?<cmd>seta?|sets|bind|unbindall|unbind|exec)\b[ \t]+(?<key>[A-Za-z0-9_+\-.]+)(?:[ \t]+(?:"(?<qval>[^"\r\n]*)"|(?<uval>[^\r\n]*?)))?[ \t]*(?=[\r\n]|[\x00-\x08\x0b\x0c\x0e-\x1f]|$)/gmd;

function parseConfig(text){
  const entries = [];
  for (const m of text.matchAll(CFG_RX)){
    const g = m.groups;
    let value, quoted, valueStart, valueLength;
    if (g.qval !== undefined){
      quoted = true; value = g.qval;
      [valueStart] = m.indices.groups.qval;
      valueLength = g.qval.length;
    } else if (g.uval !== undefined && g.uval.length > 0){
      quoted = false; value = g.uval;
      [valueStart] = m.indices.groups.uval;
      valueLength = g.uval.length;
    } else {
      quoted = false; value = '';
      valueStart = m.index + m[0].length; valueLength = 0;
    }
    entries.push({ command: g.cmd, key: g.key, value, origValue: value, quoted, valueStart, valueLength,
                   keyStart: m.indices.groups.key[0], keyLen: g.key.length,
                   matchStart: m.index, matchEnd: m.index + m[0].length });
  }
  return entries;
}
function countSetCommands(text){
  let n = 0;
  for (const m of text.matchAll(CFG_RX)) if (m.groups.cmd.startsWith('set')) n++;
  return n;
}
/* rebuild: replace values back-to-front so offsets stay valid */
function rebuildConfig(text, entries){
  let out = text;
  for (let i = entries.length - 1; i >= 0; i--){
    const e = entries[i];
    if (e.valueLength === 0 && e.value.length === 0) continue;
    out = out.slice(0, e.valueStart) + e.value + out.slice(e.valueStart + e.valueLength);
  }
  return out;
}

/* text-region length = bytes before the binary tail (first char < 0x20 that isn't \t \n \r) */
function textRegionLength(text){
  for (let i = 0; i < text.length; i++){
    const c = text.charCodeAt(i);
    if (c < 32 && c !== 9 && c !== 10 && c !== 13) return i;
  }
  return text.length;
}

/* ================= param.sfo parsing ================= */
/* PS4/PS5 SFO format: "\0PSF" magic, key table + data table, 16-byte index entries */
function parseSfo(u8){
  if (u8.length < 20) return null;
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  if (dv.getUint32(0, true) !== 0x46535000) return null; // 00 50 53 46
  const keyTab = dv.getUint32(8, true), dataTab = dv.getUint32(12, true), n = dv.getUint32(16, true);
  const out = {};
  for (let i = 0; i < n && i < 256; i++){
    const off = 20 + i * 16;
    if (off + 16 > u8.length) break;
    const keyOff  = dv.getUint16(off, true);
    const fmt     = dv.getUint16(off + 2, true);
    const len     = dv.getUint32(off + 4, true);
    const dataOff = dv.getUint32(off + 12, true);
    let k = '', p = keyTab + keyOff;
    while (p < u8.length && u8[p] !== 0) k += String.fromCharCode(u8[p++]);
    const d = dataTab + dataOff;
    if (!k || d >= u8.length) continue;
    let v;
    if (fmt === 0x0404){                       // int32
      v = dv.getUint32(Math.min(d, u8.length - 4), true);
    } else if (fmt === 0x0204){                // utf-8 string
      v = new TextDecoder('utf-8').decode(u8.subarray(d, Math.min(d + len, u8.length))).replace(/\0+$/, '');
    } else {                                   // raw binary blob
      const bl = Math.min(len, 16);
      let hex = '';
      for (let j = 0; j < bl && d + j < u8.length; j++) hex += u8[d + j].toString(16).padStart(2, '0');
      v = '0x' + hex + (len > 16 ? '… (' + len + ' bytes)' : '');
    }
    out[k] = v;
  }
  return out;
}

/* Small starter lookup of public PS4 title IDs. The save's own MAINTITLE is
   always preferred — this only fills in when the SFO lacks a title. Extend freely. */
const TITLE_DB = {
  CUSA00419: 'Grand Theft Auto V',
  CUSA00411: 'Grand Theft Auto V',
  CUSA00207: 'Bloodborne',
  CUSA00208: 'Bloodborne',
  CUSA00552: 'The Last of Us Remastered',
  CUSA00556: 'The Last of Us Remastered',
  CUSA07408: 'God of War',
  CUSA07410: 'God of War',
  CUSA02299: "Marvel's Spider-Man",
  CUSA03388: 'Dark Souls III',
  CUSA07820: 'The Last of Us Part II',
  CUSA08519: 'Red Dead Redemption 2',
  CUSA00744: 'Minecraft: PlayStation 4 Edition',
};

function updateGameCard(){
  const sfoFile  = files.find(f => f.kind === 'sfo' && /sce_sys/i.test(f.path)) || files.find(f => f.kind === 'sfo');
  const iconFile = files.find(f => /(^|\/)icon0\.[a-z0-9]+$/i.test(f.path))
                || files.find(f => f.kind === 'image' && /sce_sys/i.test(f.path))
                || files.find(f => f.kind === 'image');
  const card = $('gamecard');
  const img = $('gcIcon'), text = $('gcText');

  const p = (sfoFile && sfoFile.sfo) || {};
  const id = typeof p.TITLE_ID === 'string' ? p.TITLE_ID.trim() : '';
  resolvedGameName = p.MAINTITLE || p.TITLE || TITLE_DB[id] || '';
  const name = resolvedGameName || '';
  const idLine = id ? id + (TITLE_DB[id] && !p.MAINTITLE && !p.TITLE ? ' · matched from title list' : '') : '';
  const sub = (p.SUBTITLE || p.DETAIL || '').trim();

  $('gcName').textContent = name;
  $('gcName').title = name;
  $('gcName').hidden = !name;
  $('gcId').textContent = idLine;
  $('gcId').hidden = !idLine;
  $('gcSub').textContent = sub;
  $('gcSub').hidden = !sub;
  const hasInfo = !!(name || idLine || sub);
  text.hidden = !hasInfo;

  function syncCardVisible(){
    card.hidden = !(hasInfo || !img.hidden);
  }

  if (!iconFile && !hasInfo){
    card.hidden = true;
    img.hidden = true;
    img.removeAttribute('src');
    return;
  }

  if (iconFile){
    img.onerror = () => { img.hidden = true; img.removeAttribute('src'); syncCardVisible(); };
    img.onload = () => { img.hidden = false; syncCardVisible(); };
    img.hidden = true;
    img.src = fileUrl(iconFile);
    card.hidden = !hasInfo;
    syncCardVisible();
  } else {
    img.hidden = true;
    img.removeAttribute('src');
    card.hidden = !hasInfo;
  }
}

/* ================= state ================= */
const files = [];      // {name, path, bytes, kind:'prf'|'text'|'image'|'binary', ext,
                       //  plainText? (latin-1 of decrypted buffer), entries?, origLength?, dirty}
let current = null;
let activePane = null;
let resolvedGameName = '';

const $ = id => document.getElementById(id);
const fmtSize = n => n < 1024 ? n + ' B' : n < 1048576 ? (n/1024).toFixed(1) + ' KB' : (n/1048576).toFixed(2) + ' MB';

/* ================= file loading ================= */
const IMG_EXT = ['png','jpg','jpeg','bmp','gif','tif','tiff','ico','webp'];
const MIME = { png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg', bmp:'image/bmp',
               gif:'image/gif', ico:'image/x-icon', webp:'image/webp' };
/* OS litter: macOS .DS_Store / AppleDouble ._* / __MACOSX, Windows Thumbs.db & co. */
const JUNK_NAME = /^(\.ds_store|thumbs\.db|desktop\.ini|ehthumbs(_vista)?\.db|\.localized)$/i;
function isJunk(name, path){
  return JUNK_NAME.test(name) || name.startsWith('._') || /(^|\/)__macosx(\/|$)/i.test(path);
}
/* one object URL per file, created lazily, revoked only when the file is removed */
function fileUrl(f){
  if (!f._url) f._url = URL.createObjectURL(new Blob([f.bytes], { type: MIME[f.ext] || 'application/octet-stream' }));
  return f._url;
}
function releaseUrl(f){
  if (f._url){ URL.revokeObjectURL(f._url); f._url = null; }
}
/* identify what image-named bytes actually are, for honest error messages */
function sniffImage(u8){
  const sig = Array.from(u8.subarray(0, 8)).map(b => b.toString(16).padStart(2,'0').toUpperCase()).join(' ');
  if (!u8.length) return { sig, what: 'an empty file (0 bytes) — often caused by dragging a file straight out of an unextracted zip' };
  if (u8[0]===0x89 && u8[1]===0x50 && u8[2]===0x4E && u8[3]===0x47) return { sig, what: 'a valid PNG signature', ok: true };
  if (u8[0]===0xFF && u8[1]===0xD8) return { sig, what: 'JPEG data', ok: true };
  if (u8[0]===0x44 && u8[1]===0x44 && u8[2]===0x53 && u8[3]===0x20) return { sig, what: 'a DDS texture — browsers can\'t display DDS' };
  if (u8[0]===0x42 && u8[1]===0x4D) return { sig, what: 'BMP data', ok: true };
  if (u8[0]===0x47 && u8[1]===0x49 && u8[2]===0x46) return { sig, what: 'GIF data', ok: true };
  if (u8[0]===0x00 && u8[1]===0x00 && u8[2]===0x01 && u8[3]===0x00) return { sig, what: 'ICO data', ok: true };
  return { sig, what: 'unrecognized data (possibly still container-encrypted — see step 1)' };
}
const TXT_EXT = ['txt','cfg','ini','log','json','xml','md'];

async function addFiles(fileList){
  let firstPrf = null, added = 0, skipped = 0;
  for (const f of fileList){
    const name = f.name;
    const path = f.webkitRelativePath || name;
    const ext = (name.split('.').pop() || '').toLowerCase();
    if (isJunk(name, path) || ext === 'zip'){ skipped++; continue; }
    const bytes = new Uint8Array(await f.arrayBuffer());
    const entry = { name, path, bytes, ext, dirty:false, kind:'binary' };

    const dec = name.toLowerCase() === 'param.sfo' ? null : tryDecrypt(bytes);
    if (name.toLowerCase() === 'param.sfo' || ext === 'sfo'){
      const sfo = parseSfo(bytes);
      if (sfo){ entry.kind = 'sfo'; entry.sfo = sfo; }
    } else if (dec){
      entry.kind = 'prf';
      entry.plainText = bytesToLatin1(dec);
      entry.origLength = dec.length;
      entry.entries = parseConfig(entry.plainText);
      if (!firstPrf) firstPrf = entry;
    } else if (IMG_EXT.includes(ext)){
      entry.kind = 'image';
    } else {
      // treat as text if it decodes as mostly printable
      const sample = bytes.subarray(0, 512);
      let printable = 0;
      for (const b of sample) if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127)) printable++;
      if (sample.length && printable / sample.length > 0.92 || TXT_EXT.includes(ext)){
        entry.kind = 'text';
        entry.plainText = bytesToLatin1(bytes);
        entry.origLength = bytes.length;
        if (countSetCommands(entry.plainText) > 0){ entry.entries = parseConfig(entry.plainText); }
      }
    }
    files.push(entry); added++;
  }
  renderFileList();
  updateGameCard();
  if (firstPrf) selectFile(firstPrf);
  else if (added && !current) selectFile(files[files.length - added]);
  if (added) toast(added + ' file' + (added>1?'s':'') + ' loaded' + (skipped ? ' · ' + skipped + ' system/zip file' + (skipped>1?'s':'') + ' skipped' : ''));
  else if (skipped) toast('Nothing loaded — only system or zip files found');
}

/* ================= path helpers ================= */
/* If every file came from the same top-level folder, strip it so the save's own
   structure (profile.prf, sce_sys/param.sfo, ...) is the root — in the list and the zip. */
function commonRoot(){
  if (!files.length) return '';
  let root = null;
  for (const f of files){
    if (!f.path.includes('/')) return '';
    const first = f.path.slice(0, f.path.indexOf('/'));
    if (root === null) root = first;
    else if (first !== root) return '';
  }
  return root + '/';
}
function relPath(f){
  const r = commonRoot();
  return r && f.path.startsWith(r) ? f.path.slice(r.length) : f.path;
}

/* ================= UI: file list ================= */
const EMPTY_NOTE = '<div class="empty-note">Nothing here yet. Load any decrypted PS4/PS5 save — game name and icon are read from <b>sce_sys</b>. Nothing is uploaded anywhere.</div>';
function renderFileList(){
  const box = $('filelist');
  $('clearAll').hidden = files.length === 0;
  $('btnZip').disabled = files.length === 0;
  if (!files.length){ box.innerHTML = EMPTY_NOTE; return; }
  box.innerHTML = '';
  // group by directory (relative to the common save root)
  const groups = new Map();
  for (const f of files){
    const rp = relPath(f);
    const dir = rp.includes('/') ? rp.slice(0, rp.lastIndexOf('/')) : '';
    if (!groups.has(dir)) groups.set(dir, []);
    groups.get(dir).push(f);
  }
  const dirs = [...groups.keys()].sort((a, b) => a === '' ? -1 : b === '' ? 1 : a.localeCompare(b));
  for (const dir of dirs){
    if (dir !== ''){
      const h = document.createElement('div');
      h.className = 'fdir';
      h.innerHTML = '<b>▸</b> ' + dir.replace(/</g,'&lt;') + '/';
      box.appendChild(h);
    }
    for (const f of groups.get(dir)){
      const div = document.createElement('div');
      div.className = 'fitem' + (dir !== '' ? ' nested' : '') + (f === current ? ' active':'') + (f.dirty ? ' dirty':'');
      const tag = f.kind === 'prf' ? 'PRF' : f.kind === 'image' ? 'IMG' : f.kind === 'text' ? 'TXT' : f.kind === 'sfo' ? 'SFO' : 'BIN';
      div.innerHTML = '<span class="tag ' + f.kind + '">' + tag + '</span>' +
        '<span class="name" title="' + f.path.replace(/"/g,'&quot;') + '">' + f.name + '</span>' +
        '<span class="size">' + fmtSize(f.bytes.length) + '</span><span class="dot"></span>' +
        '<button class="fdel" title="Remove from list" aria-label="Remove ' + f.name.replace(/"/g,'&quot;') + '">✕</button>';
      div.onclick = () => selectFile(f);
      div.querySelector('.fdel').onclick = e => { e.stopPropagation(); removeFile(f); };
      box.appendChild(div);
    }
  }
}

/* ================= UI: remove & clear ================= */
function updateTabBar(){
  $('btnClose').disabled = !current;
}
function resetContent(){
  current = null;
  document.querySelectorAll('.pane').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => { t.disabled = t.dataset.pane !== 'help'; t.classList.remove('active'); });
  $('pane-placeholder').style.display = 'flex';
  $('btnApply').disabled = $('btnDecrypted').disabled = $('btnRevert').disabled = true;
  $('stFile').textContent = '—';
  $('meter').hidden = true;
  updateTabBar();
}
function closeFile(){
  if (!current) return;
  resetContent();
  renderFileList();
}
function removeFile(f){
  if (f.dirty && !confirm('Remove ' + f.name + '? It has unsaved edits.')) return;
  releaseUrl(f);
  const i = files.indexOf(f);
  if (i >= 0) files.splice(i, 1);
  if (current === f){
    if (files.length) selectFile(files[Math.min(i, files.length - 1)]);
    else resetContent();
  }
  renderFileList(); updateGameCard();
  toast(f.name + ' removed');
}

/* ================= UI: select + panes ================= */
function selectFile(f){
  current = f;
  renderFileList();
  $('pane-placeholder').style.display = 'none';
  $('stFile').textContent = f.name + ' · ' + fmtSize(f.bytes.length) + (f.kind === 'prf' ? ' · decrypted' : '');

  const has = p => ({
    text:   f.kind === 'prf' || f.kind === 'text',
    hex:    true,
    img:    f.kind === 'image',
    info:   true,
    help:   true
  })[p];

  document.querySelectorAll('.tab').forEach(t => { t.disabled = !has(t.dataset.pane); });
  $('btnApply').disabled = !(f.kind === 'prf' || f.kind === 'text');
  $('btnDecrypted').disabled = f.kind !== 'prf';
  $('btnRevert').disabled = false;

  const preferred = f.kind === 'sfo' ? 'info' : has('img') ? 'img' : has('text') ? 'text' : 'hex';
  showPane(preferred);
  updateTabBar();
}

function showPane(p){
  activePane = p;
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.pane === p));
  document.querySelectorAll('.pane').forEach(el => el.classList.remove('active'));
  $('pane-placeholder').style.display = 'none';
  $('pane-' + p).classList.add('active');
  if (p === 'config') renderConfig();
  if (p === 'text')   renderText();
  if (p === 'hex')    renderHex();
  if (p === 'img')    renderImage();
  if (p === 'info')   renderInfo();
  updateMeter();
}

/* ================= config grid ================= */
function renderConfig(){
  const body = $('cfgBody');
  if (!body) return;
  const f = current; if (!f || !f.entries) return;
  const filter = $('cfgFilter') ? $('cfgFilter').value.trim().toLowerCase() : '';
  body.innerHTML = '';
  let shown = 0;
  f.entries.forEach((e, idx) => {
    if (filter && !(e.key.toLowerCase().includes(filter) || e.value.toLowerCase().includes(filter))) return;
    shown++;
    const tr = document.createElement('tr');
    if (e.value !== e.origValue) tr.classList.add('dirty');
    const delta = e.value.length - e.origValue.length;
    tr.innerHTML = '<td class="cmd">' + e.command + '</td>' +
      '<td class="key"><input aria-label="setting name" spellcheck="false"></td>' +
      '<td class="val"><input aria-label="value of ' + e.key + '" spellcheck="false"></td>' +
      '<td class="len">' + (delta === 0 ? '·' : (delta > 0 ? '+' : '') + delta) + '</td>' +
      '<td class="act"><button class="rowdel" title="Delete this setting" aria-label="Delete ' + e.key + '">' +
      '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 6h18M8 6V4h8v2M6 6l1 15a1 1 0 001 1h8a1 1 0 001-1l1-15"/></svg></button></td>';
    const keyIn = tr.querySelector('.key input');
    keyIn.value = e.key;
    keyIn.onkeydown = ev => { if (ev.key === 'Enter') keyIn.blur(); };
    keyIn.onchange = () => renameKey(f, idx, keyIn.value.trim());
    tr.querySelector('.rowdel').onclick = () => deleteEntry(f, idx);
    const inp = tr.querySelector('.val input');
    inp.value = e.value;
    inp.oninput = () => {
      e.value = inp.value.replace(/[\r\n"]/g, '');
      if (inp.value !== e.value) inp.value = e.value;
      f.dirty = !!f.structDirty || f.entries.some(x => x.value !== x.origValue);
      tr.classList.toggle('dirty', e.value !== e.origValue);
      const d = e.value.length - e.origValue.length;
      tr.querySelector('.len').textContent = d === 0 ? '·' : (d > 0 ? '+' : '') + d;
      renderFileList(); updateMeter();
    };
    body.appendChild(tr);
  });
  $('cfgCount') && ($('cfgCount').textContent = shown + ' / ' + f.entries.length + ' settings');
  const crammed = f.entries.some(e => / (set|seta|bind) /i.test(e.value));
  if ($('btnFormat2')) $('btnFormat2').hidden = !crammed;
}

/* ================= pretty formatter ================= */
/* Profiles often arrive with every command run together on one line, which the
   config grid can't split apart. This puts one command per line — and does it by
   converting the LAST whitespace character before each command into a newline,
   so the byte count is identical and the binary tail never shifts. Quoted values
   (e.g. a bind full of semicolon-separated commands) are left untouched. */
const FMT_KW = /^(seta|sets|set|bind|unbindall|unbind|exec)[ \t]/i;
function formatCommands(text){
  const region = textRegionLength(text);
  const head = text.slice(0, region), tail = text.slice(region);
  let out = '', i = 0, inQ = false;
  while (i < head.length){
    const c = head[i];
    if (c === '"'){ inQ = !inQ; out += c; i++; continue; }
    if (!inQ && (c === ' ' || c === '\t' || c === '\n' || c === '\r')){
      let j = i;
      while (j < head.length && (head[j] === ' ' || head[j] === '\t' || head[j] === '\n' || head[j] === '\r')) j++;
      const ws = head.slice(i, j);
      out += (out.length && FMT_KW.test(head.slice(j, j + 12))) ? ws.slice(0, -1) + '\n' : ws;
      i = j; continue;
    }
    out += c; i++;
  }
  return out + tail;
}
function handleFormatClick(){
  const f = current; if (!f || !(f.kind === 'prf' || f.kind === 'text')) return;
  const before = currentRebuiltText();
  const after = formatCommands(before);
  if (after === before){ toast('Already one command per line'); return; }
  const wasEntries = f.entries ? f.entries.length : 0;
  f.plainText = after;
  f.entries = countSetCommands(f.plainText) ? parseConfig(f.plainText) : f.entries;
  f.structDirty = true; f.dirty = true;
  renderFileList(); renderText(); updateMeter();
  const now = f.entries ? f.entries.length : 0;
  toast('Formatted · ' + now + ' commands' + (now > wasEntries ? ' (was ' + wasEntries + ')' : '') +
        ' · size unchanged (' + after.length + ' B)');
}

/* ================= structural config edits ================= */
/* Commit pending value edits, reparse so offsets are fresh, then splice text. */
function structuralBase(f){
  const text = currentRebuiltText();
  return { text, entries: parseConfig(text) };
}
function commitStructural(f, newText){
  f.plainText = newText;
  f.entries = parseConfig(newText);
  f.structDirty = true; f.dirty = true;
  renderFileList(); renderConfig(); updateMeter();
}
function deleteEntry(f, idx){
  const { text, entries } = structuralBase(f);
  const e = entries[idx]; if (!e) return;
  const ls = text.lastIndexOf('\n', e.matchStart - 1) + 1;
  let le = text.indexOf('\n', e.matchEnd);
  le = le === -1 ? text.length : le + 1;
  commitStructural(f, text.slice(0, ls) + text.slice(le));
  toast(e.command + ' ' + e.key + ' deleted');
}
function renameKey(f, idx, newKey){
  newKey = newKey.replace(/[^A-Za-z0-9_+\-.]/g, '');
  const { text, entries } = structuralBase(f);
  const e = entries[idx];
  if (!e || !newKey || newKey === e.key){ renderConfig(); return; }
  commitStructural(f, text.slice(0, e.keyStart) + newKey + text.slice(e.keyStart + e.keyLen));
}
function addEntry(f){
  const cmd = $('addCmdType').value;
  const ADD_LINES = {
    set:  'set newSetting ""',
    seta: 'seta newSetting ""',
    sets: 'sets newSetting ""',
    bind: 'bind DPAD_UP ""',
    exec: 'exec autoexec.cfg'
  };
  const line = (ADD_LINES[cmd] || ADD_LINES.set) + '\n';
  const { text, entries } = structuralBase(f);
  let insertAt = 0;
  if (entries.length){
    const last = entries[entries.length - 1];
    const nl = text.indexOf('\n', last.matchEnd);
    insertAt = nl === -1 ? text.length : nl + 1;
  }
  let head = text.slice(0, insertAt);
  if (head.length && !head.endsWith('\n')) head += '\n';
  $('cfgFilter').value = '';
  commitStructural(f, head + line + text.slice(insertAt));
  toast(cmd + ' command added');
  const keyIns = document.querySelectorAll('#cfgBody td.key input');
  const target = keyIns[keyIns.length - 1];
  if (target){ target.focus(); target.select(); target.scrollIntoView({ block: 'center' }); }
}

/* ================= raw text ================= */
function normalizeNewlines(s){ return s.replace(/\r\n/g, '\n').replace(/\r/g, '\n'); }

function currentRebuiltText(){
  const f = current;
  return f.entries ? rebuildConfig(f.plainText, f.entries) : f.plainText;
}
function renderText(){
  const f = current; if (!f) return;
  $('rawText').value = currentRebuiltText();
}
function handleTextInput(){
  const f = current; if (!f) return;
  f.plainText = normalizeNewlines($('rawText').value);
  f.entries = countSetCommands(f.plainText) ? parseConfig(f.plainText) : f.entries ? [] : undefined;
  f.dirty = true; f.structDirty = true;
  renderFileList(); updateMeter();
}
function syncTextToEntries(){ /* text edits already re-parsed on input */ }

/* ================= hex view ================= */
function renderHex(){
  const f = current; if (!f) return;
  const u8 = f.kind === 'prf' ? latin1ToBytes(currentRebuiltText()) : f.bytes;
  const max = Math.min(u8.length, 65536);
  let out = '';
  for (let off = 0; off < max; off += 16){
    let hexs = '', asc = '';
    for (let i = 0; i < 16; i++){
      if (off + i < u8.length){
        const b = u8[off + i];
        hexs += b.toString(16).padStart(2,'0').toUpperCase() + ' ';
        asc += (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
      } else { hexs += '   '; asc += ' '; }
      if (i === 7) hexs += ' ';
    }
    out += '<span class="off">' + off.toString(16).padStart(8,'0').toUpperCase() + '</span>  ' +
           hexs + ' <span class="asc">|' + asc.replace(/</g,'&lt;') + '|</span>\n';
  }
  if (u8.length > max) out += '\n… truncated at 64 KB (' + fmtSize(u8.length) + ' total)';
  $('hexView').innerHTML = out;
}

/* ================= image + info ================= */
function renderImage(){
  const f = current; if (!f) return;
  $('imgPrev').innerHTML = '<img alt="">';
  const img = $('imgPrev').querySelector('img');
  img.alt = f.name;
  img.src = fileUrl(f);
}
function renderInfo(){
  const f = current; if (!f) return;
  const md5 = CryptoJS.MD5(u8ToWA(f.bytes)).toString(CryptoJS.enc.Hex).toUpperCase();
  const rows = [
    ['File', f.path],
    ['Size', fmtSize(f.bytes.length) + ' (' + f.bytes.length + ' bytes)'],
    ['Type', f.kind === 'prf' ? 'PRF profile (encrypted)' : f.kind === 'sfo' ? 'PlayStation param.sfo (save metadata)' : f.kind],
    ['MD5 (original bytes)', md5],
  ];
  if (f.kind === 'image'){
    const d = sniffImage(f.bytes);
    rows.push(['Signature', d.sig + ' — ' + d.what]);
  }
  if (f.kind === 'sfo' && f.sfo){
    const id = typeof f.sfo.TITLE_ID === 'string' ? f.sfo.TITLE_ID.trim() : '';
    if (id && TITLE_DB[id]) rows.push(['Known title', TITLE_DB[id] + ' (' + id + ')']);
    for (const [k, v] of Object.entries(f.sfo)) rows.push(['SFO · ' + k, v]);
  }
  if (f.kind === 'prf') rows.push(['Cipher', 'TripleDES-CBC, no padding — key Md8ea20lPcftYwsl496q63x9, IV 0Peyx825 (built in)']);
  if (f.kind === 'prf'){
    rows.push(['Decrypted length', f.origLength + ' bytes']);
    rows.push(['set commands', String(f.entries ? f.entries.length : 0)]);
    rows.push(['Text region', textRegionLength(currentRebuiltText()) + ' bytes (keep below ~1000)']);
  }
  $('infoView').innerHTML = rows.map(([k,v]) =>
    '<dt>' + k + '</dt><dd>' + String(v).replace(/</g,'&lt;') + '</dd>').join('');
}

/* ================= text-region meter ================= */
function updateMeter(){
  const f = current;
  const m = $('meter');
  if (!f || f.kind !== 'prf'){ m.hidden = true; return; }
  m.hidden = false;
  const len = textRegionLength(currentRebuiltText());
  const pct = Math.min(100, len / 1000 * 100);
  $('meterFill').style.width = pct + '%';
  $('meterLbl').textContent = 'text ' + len + ' / 1000 B';
  m.classList.toggle('warn', len > 1000);
}

/* ================= save pipeline (port of MainForm save path) ================= */
function buildOutputBytes(f){
  let buf = latin1ToBytes(f.entries ? rebuildConfig(f.plainText, f.entries) : f.plainText);
  // resize back to original length so the binary tail / padding stays valid
  if (f.origLength > 0 && buf.length !== f.origLength){
    const resized = new Uint8Array(f.origLength);
    resized.set(buf.subarray(0, Math.min(buf.length, f.origLength)));
    buf = resized;
  }
  return buf;
}
function download(bytes, name){
  const url = URL.createObjectURL(new Blob([bytes], { type:'application/octet-stream' }));
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}
function handleApplyClick(){
  const f = current; if (!f) return;
  const plain = buildOutputBytes(f);
  const tlen = textRegionLength(bytesToLatin1(plain));
  if (tlen > 1000 && !confirm('Text region is ' + tlen + ' bytes — the game may reject files over ~1000 bytes. Save anyway?')) return;
  if (f.kind === 'prf'){
    download(prfEncrypt(plain), f.name);
    toast(f.name + ' re-encrypted & downloaded');
  } else {
    download(plain, f.name);
    toast(f.name + ' downloaded');
  }
  f.plainText = bytesToLatin1(plain);
  f.entries = countSetCommands(f.plainText) ? parseConfig(f.plainText) : f.entries;
  f.dirty = false; f.structDirty = false;
  renderFileList();
  if (activePane === 'config') renderConfig();
}
async function handleZipClick(){
  if (!files.length) return;
  if (typeof JSZip === 'undefined'){ toast('Zip library didn\'t load — check your internet connection'); return; }
  const over = files.filter(f => f.kind === 'prf' &&
    textRegionLength(bytesToLatin1(buildOutputBytes(f))) > 1000);
  if (over.length && !confirm('Text region over ~1000 bytes in: ' + over.map(f => f.name).join(', ') + ' — the game may reject these. Zip anyway?')) return;
  const zip = new JSZip();
  const outputs = new Map();
  for (const f of files){
    let bytes;
    if (f.kind === 'prf'){ const plain = buildOutputBytes(f); outputs.set(f, plain); bytes = prfEncrypt(plain); }
    else if (f.kind === 'text'){ bytes = buildOutputBytes(f); outputs.set(f, bytes); }
    else bytes = f.bytes;
    zip.file(relPath(f), bytes);
  }
  const blob = await zip.generateAsync({ type: 'blob', compression: 'DEFLATE' });
  const slug = (resolvedGameName || commonRoot().replace(/\/$/, '') || 'savegame')
    .normalize('NFKD').replace(/[^A-Za-z0-9]+/g, '-').replace(/^-+|-+$/g, '').toLowerCase() || 'savegame';
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = slug + '-save.zip'; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
  for (const [f, plain] of outputs){
    f.plainText = bytesToLatin1(plain);
    if (countSetCommands(f.plainText)) f.entries = parseConfig(f.plainText);
    f.dirty = false; f.structDirty = false;
  }
  renderFileList();
  if (current && activePane === 'config') renderConfig();
  toast(files.length + ' files zipped · ' + slug + '-save.zip');
}
function handleDecryptedClick(){
  const f = current; if (!f || f.kind !== 'prf') return;
  download(buildOutputBytes(f), f.name + '.decrypted.txt');
  toast('Decrypted copy downloaded');
}
function handleRevertClick(){
  const f = current; if (!f) return;
  if (f.dirty && !confirm('Discard all edits to ' + f.name + '?')) return;
  const dec = f.kind === 'prf' ? prfDecrypt(f.bytes) : f.bytes;
  if (f.kind === 'prf' || f.kind === 'text'){
    f.plainText = bytesToLatin1(dec);
    f.entries = countSetCommands(f.plainText) ? parseConfig(f.plainText) : f.entries ? [] : undefined;
  }
  f.dirty = false; f.structDirty = false;
  renderFileList(); showPane(activePane);
  toast('Reloaded original');
}
function handleClearAllClick(){
  if (!files.length) return;
  const dirty = files.filter(f => f.dirty).length;
  if (!confirm('Remove all ' + files.length + ' loaded files' + (dirty ? ' (' + dirty + ' with unsaved edits)' : '') + '?')) return;
  files.forEach(releaseUrl);
  files.length = 0;
  resetContent(); renderFileList(); updateGameCard();
  toast('All files cleared');
}
function handleFileInputChange(e){
  addFiles([...e.target.files]);
  e.target.value = '';
}
function handleFolderInputChange(e){
  const list = [...e.target.files];
  if (!list.length) toast('No files came back — your browser may not support folder picking; try dragging the folder in instead');
  else addFiles(list);
  e.target.value = '';
}
async function handleBodyDrop(e){
  const drop = $('drop');
  e.preventDefault();
  drop.classList.remove('over');
  const items = e.dataTransfer.items;
  const out = [];
  async function walk(entry, prefix){
    if (entry.isFile){
      const file = await new Promise((res, rej) => entry.file(res, rej));
      if (prefix) Object.defineProperty(file, 'webkitRelativePath', { value: prefix + file.name });
      out.push(file);
    } else if (entry.isDirectory){
      const reader = entry.createReader();
      let batch;
      do {
        batch = await new Promise((res, rej) => reader.readEntries(res, rej));
        for (const ent of batch) await walk(ent, prefix + entry.name + '/');
      } while (batch.length);
    }
  }
  const entries = [];
  if (items && items.length && typeof items[0].webkitGetAsEntry === 'function'){
    for (const it of items){
      const en = it.webkitGetAsEntry();
      if (en) entries.push(en);
    }
  }
  if (entries.length){
    for (const en of entries) await walk(en, '');
  } else {
    out.push(...e.dataTransfer.files);
  }
  if (out.length) addFiles(out);
}

/* ================= toast ================= */
let toastTimer;
function toast(msg){
  const t = $('toast');
  t.textContent = msg; t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2400);
}

/* ================= init ================= */
function bindEvents(){
  const drop = $('drop');

  $('clearAll').onclick = handleClearAllClick;
  $('clearAll').onkeydown = e => {
    if (e.key === 'Enter' || e.key === ' '){ e.preventDefault(); handleClearAllClick(); }
  };

  document.querySelectorAll('.tab').forEach(t => {
    t.onclick = () => showPane(t.dataset.pane);
  });
  $('btnClose').onclick = closeFile;

  const cfgFilter = $('cfgFilter');
  if (cfgFilter) cfgFilter.oninput = renderConfig;

  $('btnFormat').onclick = handleFormatClick;

  const btnAddRow = $('btnAddRow');
  if (btnAddRow){
    btnAddRow.onclick = () => {
      if (current && (current.kind === 'prf' || current.kind === 'text')) addEntry(current);
    };
  }
  const btnFormat2 = $('btnFormat2');
  if (btnFormat2) btnFormat2.onclick = () => { handleFormatClick(); renderConfig(); };

  $('rawText').addEventListener('input', handleTextInput);

  $('btnApply').onclick = handleApplyClick;
  $('btnZip').onclick = handleZipClick;
  $('btnDecrypted').onclick = handleDecryptedClick;
  $('btnRevert').onclick = handleRevertClick;

  $('btnPickFiles').onclick = () => $('fileInput').click();
  $('btnPickFolder').onclick = () => $('folderInput').click();
  $('fileInput').onchange = handleFileInputChange;
  $('folderInput').onchange = handleFolderInputChange;

  ['dragover', 'dragenter'].forEach(ev => {
    document.body.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); });
  });
  ['dragleave', 'drop'].forEach(ev => {
    document.body.addEventListener(ev, e => {
      e.preventDefault();
      if (ev === 'dragleave' && e.target !== document.body) return;
      drop.classList.remove('over');
    });
  });
  document.body.addEventListener('drop', handleBodyDrop);
}

document.addEventListener('DOMContentLoaded', bindEvents);
