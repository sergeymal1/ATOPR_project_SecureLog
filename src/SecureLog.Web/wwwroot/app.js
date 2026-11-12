'use strict';

// Підписи лише для наочності: у записі є тільки числові source_id, category і severity.
const HOSTS = [null, 'api-gw-01', 'auth-01', 'db-main-01', 'cache-01', 'queue-01', 'billing-01', 'storage-01', 'monitor-01'];
const CATS = ['net', 'disk', 'auth', 'app', 'db', 'cpu', 'mem', 'sec'];
const LEVELS = ['DEBUG', 'INFO', 'NOTICE', 'WARN', 'ERROR', 'ALERT'];
const CLASSES = ['штатна', 'аномалія', 'інцидент'];
const NODES = ['node-a', 'node-b', 'node-c'];
const LETTERS = ['A', 'B', 'C'];
const MAX_ROWS = 250;

const $ = (s) => document.querySelector(s);
const pad = (n, w = 2) => String(n).padStart(w, '0');
const host = (s) => HOSTS[s] ?? `edge-${pad(s)}`;
const kb = (b) => `${(b / 1024).toFixed(1)} КБ`;
const clock = (ms) => `${pad(Math.floor(ms / 3.6e6))}:${pad(Math.floor(ms / 6e4) % 60)}:${pad(Math.floor(ms / 1000) % 60)}.${pad(ms % 1000, 3)}`;
const grade = (v) => (v >= 0.99 ? 'good' : v >= 0.95 ? 'mid' : 'poor');

let info = null;
let scenario = 'normal';
let filter = 'all';
let busy = false;
let run = null;        // відповідь /api/run
let cursor = 0;        // скільки подій уже надійшло від агентів
let shipped = 0;       // скільки вікон уже відправлено на вузли
let done = false;      // прогін відтворено до кінця й відновлено
let lost = new Set();  // номери подій, яких немає у відновленому журналі
let sent = [];         // по вузлах: надіслано байтів і пакетів
let tampered = [];
let critSeen = 0;
let critCovered = 0;
let frame = 0;
let lastFrame = 0;

async function api(path, body) {
  const res = await fetch(path, body === undefined ? {} : {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error((await res.text()).replace(/^"|"$/g, '') || res.statusText);
  return res.json();
}

function setOn(group, button) {
  for (const b of document.querySelectorAll(`${group} button`)) b.classList.toggle('on', b === button);
}

function setBusy(value) {
  busy = value;
  $('#run').disabled = value;
  $('#restore').disabled = value || !done;
  for (const b of document.querySelectorAll('#scenario button')) b.disabled = value;
  for (const b of document.querySelectorAll('.tamper')) b.disabled = value || !done;
}

function log(html, kind = '', sub = []) {
  const li = document.createElement('li');
  li.className = kind;
  li.innerHTML = html + sub.map((s) => `<div class="sub">${s}</div>`).join('');
  $('#journal').prepend(li);
}

function setKpi(id, value, sub, cls = '') {
  const el = $(`#k${id}`);
  el.textContent = value;
  el.className = cls;
  if (sub !== undefined) $(`#k${id}sub`).textContent = sub;
}

// ── опис сценарію ──────────────────────────────────────────────

function renderNote() {
  const sc = info.scenarios[scenario];
  $('#note').innerHTML =
    `<b>${scenario}</b>: місця ×${sc.budgetFactor} від сирого журналу · втрати ${Math.round(sc.loss * 100)} % · пачка втрат ${sc.burst}` +
    `<span class="sep">|</span>параметри ГА: вікно ${info.window}, поріг NO_COMPRESSION ${info.minGain.toFixed(3)}, коефіцієнт другої копії ${info.secondCopyFactor.toFixed(3)}` +
    `<span class="sep">|</span>перцептрон ${info.model ?? 'не навчено — усі події штатні'}`;
}

// ── відтворення прогону ────────────────────────────────────────

async function start() {
  setBusy(true);
  $('#run').textContent = '… прогін на сервері';
  try {
    run = await api('/api/run', { scenario, seed: Number($('#seed').value) || 0 });
  } catch (e) {
    log(`Помилка прогону: ${e.message}`, 'bad');
    $('#run').textContent = '▶ Запустити';
    setBusy(false);
    return;
  }
  cursor = shipped = critSeen = critCovered = 0;
  done = false;
  lost = new Set();
  sent = run.nodes.map(() => ({ bytes: 0, packets: 0 }));
  tampered = run.nodes.map(() => 0);
  for (const id of ['Q', 'S', 'R', 'T']) setKpi(id, '—', id === 'Q' ? undefined : 'після відновлення');
  $('#run').textContent = '■ відтворення…';
  renderNodes();
  renderWindow();
  lastFrame = performance.now();
  requestAnimationFrame(tick);
}

function tick(now) {
  const speed = Number($('#speed').value);
  // крок за часом, а не за кадрами: у фоновій вкладці кадри рідшають, а швидкість не змінюється
  const step = Math.max(1, Math.round((speed * (now - lastFrame)) / 16.7));
  lastFrame = now;
  cursor = speed === 0 ? run.events.length : Math.min(run.events.length, cursor + step);
  const before = shipped;
  // агент відправляє вікно, щойно воно заповнилось
  while (shipped < run.windows.length && run.windows[shipped].start + run.windows[shipped].count <= cursor) ship(run.windows[shipped++]);
  if (shipped !== before) {
    renderNodes();
    renderWindow();
  }
  renderProgress();
  const last = cursor === run.events.length;
  if (++frame % 2 === 0 || last) renderRows();
  if (last) finish();
  else requestAnimationFrame(tick);
}

function ship(w) {
  w.bytes.forEach((b, k) => {
    sent[k].bytes += b;
    if (b > 0) sent[k].packets++;
  });
  for (let i = w.start; i < w.start + w.count; i++) {
    const e = run.events[i];
    if (!e.crit) continue;
    critSeen++;
    if (e.nodes.length) critCovered++;
  }
}

function renderProgress() {
  setKpi('N', String(cursor), `вікно ${shipped} / ${run.windows.length}`);
  setKpi('B', kb(sent.reduce((s, n) => s + n.bytes, 0)), `сирі записи ${kb(cursor * 16)}`);
  if (!done) $('#kRsub').textContent = `з копією ${critCovered} / ${critSeen} критичних`;
}

function finish() {
  done = true;
  const r = run.result;
  lost = new Set(run.events.flatMap((e, i) => (e.ok ? [] : [i])));
  setKpi('Q', r.q.toFixed(4));
  setKpi('S', r.s.toFixed(3), `${kb(r.storedBytes)} замість ${kb(r.rawBytes)}`);
  setKpi('R', r.r.toFixed(3), `${r.criticalRestored} / ${r.criticalTotal} критичних`, grade(r.r));
  setKpi('T', r.t.toFixed(3), `${r.seconds.toFixed(2)} с на прогін`);
  $('#run').textContent = '▶ Запустити';
  setBusy(false);
  renderNodes();
  renderRows();
  log(`Прогін <b>${scenario}</b>, seed ${$('#seed').value}: Q = ${r.q.toFixed(4)}`, r.criticalRestored === r.criticalTotal ? 'ok' : 'warn', [
    `критичних ${r.criticalRestored} / ${r.criticalTotal}, подій ${r.restored} / ${run.events.length}`,
    `на вузлах ${kb(r.storedBytes)} з бюджету ${kb(r.budgetBytes)}`,
  ]);
}

// ── потік подій ────────────────────────────────────────────────

function matches(e, i) {
  switch (filter) {
    case 'important': return e.crit || e.cls > 0;
    case 'crit': return e.crit;
    case 'lost': return done && lost.has(i);
    default: return true;
  }
}

function state(e, i, isShipped) {
  if (done && !lost.has(i)) return '<span class="st ok">✓ відновлено</span>';
  // ДП не дав події жодної копії — це вибір планувальника, а не втрата на вузлі
  if (done) return e.nodes.length ? '<span class="st bad">✗ втрачено</span>' : '<span class="st warn">поза бюджетом</span>';
  if (!isShipped) return '<span class="st dim">у буфері</span>';
  return e.nodes.length ? `<span class="st sent">надіслано ×${e.nodes.length}</span>` : '<span class="st warn">без копії</span>';
}

function row(e, i, isShipped) {
  const copies = LETTERS.map((l, k) => `<i class="n${k}${isShipped && e.nodes.includes(k) ? ' on' : ''}">${l}</i>`).join('');
  return `<tr class="c${e.cls}">` +
    `<td class="mono dim">${clock(e.t)}</td>` +
    `<td>${host(e.src)}</td>` +
    `<td class="mono">#${e.code}<span class="cat">${CATS[e.cat] ?? e.cat}</span></td>` +
    `<td><span class="lvl l${e.sev}">${LEVELS[e.sev] ?? e.sev}</span>${e.crit ? '<span class="crit-tag">CRIT</span>' : ''}</td>` +
    `<td class="num mono">${(e.metric / 100).toFixed(2)}</td>` +
    `<td><span class="cls k${e.cls}">${CLASSES[e.cls]}</span></td>` +
    `<td class="copies">${copies}</td>` +
    `<td>${state(e, i, isShipped)}</td></tr>`;
}

function renderRows() {
  if (!run) return;
  const w = run.windows[shipped - 1];
  const shippedEnd = w ? w.start + w.count : 0;
  const out = [];
  let count = 0;
  for (let i = cursor - 1; i >= 0; i--) {
    const e = run.events[i];
    if (!matches(e, i)) continue;
    count++;
    if (out.length < MAX_ROWS) out.push(row(e, i, i < shippedEnd));
  }
  const empty = filter === 'lost' && !done ? 'Втрати стануть відомі після відновлення.' : 'Немає подій за цим фільтром.';
  $('#rows').innerHTML = out.join('') || `<tr><td colspan="8" class="empty">${empty}</td></tr>`;
  $('#shown').textContent = count > MAX_ROWS ? `останні ${MAX_ROWS} з ${count}` : `${count} подій`;
}

// ── вузли й вікно ──────────────────────────────────────────────

function renderNodes() {
  $('#nodes').innerHTML = info.reliability.map((rel, k) => {
    const s = sent[k] ?? { bytes: 0, packets: 0 };
    const cap = run ? run.nodes[k].capacity : 0;
    const pct = cap ? Math.min(100, (s.bytes / cap) * 100) : 0;
    let after = '';
    if (done) {
      const missing = s.packets - run.nodes[k].stored;
      after = `<div class="node-after">збережено пакетів ${run.nodes[k].stored} · <span class="${missing ? 'bad' : ''}">втрачено при записі ${missing}</span>` +
        (tampered[k] ? ` · <span class="bad">зіпсовано ${tampered[k]}</span>` : '') + '</div>';
    }
    return `<div class="node n${k}">
      <div class="node-top"><span class="dot"></span><b>${NODES[k]}</b><span class="muted">надійність ${rel.toFixed(2)}</span></div>
      <div class="bar"><i style="width:${pct.toFixed(1)}%"></i></div>
      <div class="node-stats"><span>${kb(s.bytes)}${cap ? ` / ${kb(cap)}` : ''}</span><span>пакетів ${s.packets}</span></div>
      ${after}
      <button class="ghost tamper" data-node="${k}" ${done && !busy ? '' : 'disabled'}>Зіпсувати 1 біт у пакеті</button>
    </div>`;
  }).join('');
}

function renderWindow() {
  const w = run?.windows[shipped - 1];
  if (!w) {
    $('#winLabel').textContent = '';
    $('#window').innerHTML = '<p class="muted small">ДП вирішує, скільки копій (0–3) зробити для кожного запису вікна, щоб уміститися в бюджет бітів, а жадібне розміщення розкладає копії по різних вузлах.</p>';
    return;
  }
  const used = w.budget ? Math.min(100, (w.usedBits / w.budget) * 100) : 0;
  $('#winLabel').textContent = `${shipped} / ${run.windows.length}`;
  $('#window').innerHTML = `
    <div class="row"><span class="muted">записи</span><span class="mono">${w.start + 1}–${w.start + w.count}</span></div>
    <div class="row"><span class="muted">бюджет ДП</span><span class="mono">${w.usedBits} / ${w.budget} біт</span></div>
    <div class="bar"><i style="width:${used.toFixed(1)}%"></i></div>
    <div class="row"><span class="muted">копій на запис</span></div>
    <div class="stack">${w.copies.map((c, r) => `<i class="r${r}" style="flex:${c}" title="${r} коп.: ${c}"></i>`).join('')}</div>
    <div class="legend">${w.copies.map((c, r) => `<span><i class="r${r}"></i>${r}: ${c}</span>`).join('')}</div>
    <div class="row"><span class="muted">batch на вузли</span><span class="mono">${w.bytes.map((b, k) => `${LETTERS[k]} ${b} Б`).join(' · ')}</span></div>`;
}

// ── псування й відновлення ─────────────────────────────────────

async function tamper(k) {
  try {
    const t = await api('/api/tamper', { node: k });
    tampered[k]++;
    log(`${NODES[k]}: у пакеті batch_seq ${t.seq} змінено біт ${t.bit} байта ${t.offset}`, 'warn', ['натисніть «Відновити», щоб перевірити']);
    renderNodes();
  } catch (e) {
    log(e.message, 'bad');
  }
}

async function restore() {
  setBusy(true);
  const password = $('#password').value;
  try {
    const r = await api('/api/restore', { password: password || null });
    lost = new Set(r.lost);
    const nodes = r.nodes.map((codes, k) =>
      `${NODES[k]}: ${Object.entries(codes).map(([c, n]) => `${c} ×${n}`).join(', ') || 'порожньо'}`);
    log(`Відновлено ${r.restored} / ${r.total} подій, критичних ${r.critical} / ${r.criticalTotal}; відхилено реплік ${r.rejected}` +
      (password ? ' (пароль введено вручну)' : ''), r.rejected ? 'warn' : 'ok', nodes);
    renderRows();
  } catch (e) {
    log(e.message, 'bad');
  }
  setBusy(false);
}

// ── атака ──────────────────────────────────────────────────────

function spark(h) {
  if (h.length < 2) return '';
  const W = 300, H = 56, min = Math.min(...h), span = Math.max(...h) - min || 1;
  const pts = h.map((v, i) => `${((i / (h.length - 1)) * W).toFixed(1)},${(H - 4 - ((v - min) / span) * (H - 8)).toFixed(1)}`).join(' ');
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Найкраща пристосованість за поколіннями"><polyline points="${pts}"/></svg>` +
    `<div class="muted small">найкраща пристосованість за ${h.length} поколіннями</div>`;
}

async function attack() {
  const button = $('#attack');
  button.disabled = true;
  button.textContent = 'ГА підбирає ключ…';
  try {
    const a = await api('/api/attack', {});
    const key = a.key.match(/../g), found = a.recovered.match(/../g);
    $('#attackOut').innerHTML = `
      <div class="keyrow"><span class="muted">справжній ключ</span><code>${key.join(' ')}</code></div>
      <div class="keyrow"><span class="muted">знайдений ГА</span><code>${found.map((b, i) => `<span class="${b === key[i] ? 'ok' : 'bad'}">${b}</span>`).join(' ')}</code></div>
      <div class="muted small">збіглося ${a.matched} / ${key.length} байтів за ${a.evaluations} обчислень пристосованості</div>
      ${spark(a.history)}`;
  } catch (e) {
    $('#attackOut').textContent = e.message;
  }
  button.disabled = false;
  button.textContent = 'Запустити атаку';
}

// ── старт ──────────────────────────────────────────────────────

async function init() {
  try {
    info = await api('/api/info');
  } catch (e) {
    $('#note').textContent = `Сервер недоступний: ${e.message}`;
    return;
  }
  renderNote();
  renderNodes();
  renderWindow();
  $('#scenario').addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (!b || busy) return;
    scenario = b.dataset.v;
    setOn('#scenario', b);
    renderNote();
  });
  $('#filters').addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (!b) return;
    filter = b.dataset.f;
    setOn('#filters', b);
    renderRows();
  });
  $('#nodes').addEventListener('click', (e) => {
    const b = e.target.closest('.tamper');
    if (b && !b.disabled) tamper(Number(b.dataset.node));
  });
  $('#run').addEventListener('click', start);
  $('#restore').addEventListener('click', restore);
  $('#attack').addEventListener('click', attack);
}

init();
