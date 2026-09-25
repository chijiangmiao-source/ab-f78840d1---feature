'use strict';

// 值班员页面逻辑：单链逐跳核验 + 乱序委托集合授权求解，证据留存。
// 关键约束：错误草稿不得覆盖上一份有效证据——
// lastValidEvidence / lastValidAuthEvidence 只在收到 ok:true 时更新。

const $ = (id) => document.getElementById(id);

// 上一份有效证据（跨多次核验保留）：单链 / 集合授权各一份
let lastValidEvidence = null;
let lastValidAuthEvidence = null;

function splitObjects(raw) {
  return raw
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function short(s, n = 26) {
  if (!s) return '';
  return s.length <= n * 2 ? s : `${s.slice(0, n)}…${s.slice(-n)}`;
}

function parseNowField(id) {
  const raw = $(id).value.trim();
  if (!raw) return { ok: true };
  if (!/^\d+$/.test(raw)) {
    return { ok: false, message: '评估时刻必须是非负整数 unix 秒' };
  }
  return { ok: true, now: Number(raw) };
}

// ---------- 单链逐跳核验 ----------

async function runVerify() {
  const rootKey = $('rootKey').value.trim();
  const objects = splitObjects($('objects').value);
  const body = { rootKey, objects };
  const now = parseNowField('now');
  if (!now.ok) {
    showLocalError({ code: 'BAD_REQUEST', hop: -1, field: 'now', message: now.message });
    return;
  }
  if (now.now !== undefined) body.now = now.now;

  $('verifyBtn').disabled = true;
  try {
    const resp = await fetch('/api/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const result = await resp.json();
    if (result.ok) {
      lastValidEvidence = result.evidence; // 仅此处覆盖
      renderEvidence(result.evidence);
      hideError();
    } else {
      renderError(result.error);
      if (lastValidEvidence) renderEvidence(lastValidEvidence, true);
    }
  } catch (e) {
    showLocalError({ code: 'NETWORK', hop: -1, field: null, message: `请求失败：${e.message}` });
    if (lastValidEvidence) renderEvidence(lastValidEvidence, true);
  } finally {
    $('verifyBtn').disabled = false;
  }
}

function showLocalError(err) {
  renderError(err);
  if (lastValidEvidence) renderEvidence(lastValidEvidence, true);
}

function hideError() {
  $('errorPanel').hidden = true;
}

function renderError(err) {
  const panel = $('errorPanel');
  const body = $('errorBody');
  body.innerHTML = errorHtml(err);
  panel.hidden = false;
}

function errorHtml(err) {
  const hopText = err.hop === -1 || err.hop == null
    ? '根公钥 / 请求'
    : `第 ${err.hop} 跳${err.hop === 0 ? '（链首）' : ''}`;
  const loc = err.line ? `（行 ${err.line}，列 ${err.col}）` : '';
  return `
    <dl>
      <dt>错误码</dt><dd class="mono">${esc(err.code || 'UNKNOWN')}</dd>
      <dt>定位</dt><dd>${esc(hopText)}${err.field ? ` · 字段 <code>${esc(err.field)}</code>` : ''}${loc}</dd>
      <dt>说明</dt><dd>${esc(err.message || '')}</dd>
    </dl>`;
}

function renderConstraints(c) {
  if (!c) return '未受限（根主体）';
  return `nbf=<b>${c.nbf}</b>，exp=<b>${c.exp}</b>` +
    `，浮标=[${esc(c.aud.map((b) => `"${b}"`).join(', '))}]，` +
    `上限=<b>${c.maxSamples}</b>`;
}

function hopRows(hops) {
  return hops.map((h) => `
    <tr>
      <td>${h.index}</td>
      <td><span class="pill ${h.typ === 'command' ? 'cmd' : ''}">${esc(h.typ)}</span></td>
      <td class="mono" title="${esc(h.signature)}">${esc(short(h.signature, 20))}</td>
      <td class="mono">${esc(h.payloadDigest)}</td>
      <td class="mono" title="iss">${esc(h.issThumbprint.slice(0, 16))}…</td>
      <td class="mono" title="sub">${esc(h.subThumbprint.slice(0, 16))}…</td>
      <td style="font-size:12px">${renderConstraints(h.tightened)}</td>
    </tr>`).join('');
}

function renderEvidence(ev, stale = false) {
  const panel = $('evidencePanel');
  const v = ev.verdict;
  $('verdict').innerHTML = `
    <p class="${v.allow ? 'allow' : 'deny'}">
      ${stale ? '⚠ 当前为<b>上一份有效证据</b>（本次核验被拒绝，证据未被覆盖）<br>' : ''}
      最终结论：${v.allow ? '✅ 准许' : '⛔ 拒绝'} —— ${esc(v.reason)}
    </p>
    <p style="font-size:12.5px;color:#9fb0c3">
      根公钥指纹 <code>${esc(ev.rootKeyThumbprint)}</code> · 评估时刻 ${ev.now}
    </p>`;

  $('hopTable').querySelector('tbody').innerHTML = hopRows(ev.hops);
  $('finalConstraints').innerHTML =
    `<p style="font-size:13px;margin-top:12px">收紧后的最终约束：${renderConstraints(ev.finalConstraints)}</p>`;
  panel.hidden = false;
}

$('verifyBtn').addEventListener('click', runVerify);
$('clearBtn').addEventListener('click', () => {
  $('rootKey').value = '';
  $('objects').value = '';
  $('now').value = '';
  $('errorPanel').hidden = true;
  $('evidencePanel').hidden = true;
  // 注意：清空操作是值班员显式动作，此时一并清除留存证据
  lastValidEvidence = null;
});

// ---------- 乱序委托集合授权求解 ----------

async function runAuthorize() {
  const body = {
    rootKey: $('authRootKey').value.trim(),
    objects: splitObjects($('authObjects').value),
    targetKey: $('targetKey').value.trim(),
    buoy: $('buoy').value.trim(),
  };
  const samplesRaw = $('samples').value.trim();
  if (!/^\d+$/.test(samplesRaw)) {
    showAuthError({ code: 'BAD_REQUEST', hop: -1, field: 'samples', message: '请求采样量必须是正整数' });
    return;
  }
  body.samples = Number(samplesRaw);
  const now = parseNowField('authNow');
  if (!now.ok) {
    showAuthError({ code: 'BAD_REQUEST', hop: -1, field: 'now', message: now.message });
    return;
  }
  if (now.now !== undefined) body.now = now.now;

  $('authorizeBtn').disabled = true;
  try {
    const resp = await fetch('/api/authorize', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const result = await resp.json();
    if (result.ok) {
      lastValidAuthEvidence = result.evidence; // 仅此处覆盖
      renderAuthEvidence(result.evidence);
      $('authErrorPanel').hidden = true;
      $('reachPanel').hidden = true;
    } else {
      renderAuthError(result.error);
      if (result.reachability) renderReachability(result.reachability);
      else $('reachPanel').hidden = true;
      if (lastValidAuthEvidence) renderAuthEvidence(lastValidAuthEvidence, true);
    }
  } catch (e) {
    showAuthError({ code: 'NETWORK', hop: -1, field: null, message: `请求失败：${e.message}` });
  } finally {
    $('authorizeBtn').disabled = false;
  }
}

function showAuthError(err) {
  renderAuthError(err);
  $('reachPanel').hidden = true;
  if (lastValidAuthEvidence) renderAuthEvidence(lastValidAuthEvidence, true);
}

function renderAuthError(err) {
  $('authErrorBody').innerHTML = errorHtml(err);
  $('authErrorPanel').hidden = false;
}

function renderReachability(reach) {
  const targetReached = reach.reached.some((r) => r.subjectThumbprint === reach.targetThumbprint);
  $('reachSummary').innerHTML = `
    <p style="font-size:13px">
      目标主体指纹 <code>${esc(reach.targetThumbprint)}</code> ·
      请求浮标 <code>${esc(reach.buoy)}</code> · 采样量 <code>${reach.samples}</code> ·
      评估时刻 ${reach.now}：不存在满足权限的合法委托路径。${targetReached
        ? '<br>目标主体虽可到达，但到达时的有效约束不准许所请求的浮标 / 采样量（见下表）。'
        : ''}
    </p>`;
  $('reachedTable').querySelector('tbody').innerHTML = reach.reached.map((r) => `
    <tr>
      <td class="mono" title="${esc(r.subjectThumbprint)}">${esc(r.subjectThumbprint.slice(0, 16))}…${r.subjectThumbprint === reach.targetThumbprint ? ' <span class="pill cmd">目标</span>' : ''}</td>
      <td>${r.hops}</td>
      <td style="font-size:12px">${renderConstraints(r.constraints)}</td>
    </tr>`).join('');
  const rows = reach.rejections.map((r) => `
    <tr>
      <td>${r.level}</td>
      <td class="mono" title="${esc(r.fromThumbprint)}">${esc(r.fromThumbprint.slice(0, 16))}…</td>
      <td class="mono" title="${esc(r.payloadDigest)}">${esc(short(r.payloadDigest, 16))}</td>
      <td class="mono">${esc(r.code)}</td>
      <td>${r.field ? `<code>${esc(r.field)}</code>` : ''}</td>
      <td style="font-size:12px">${esc(r.message)}</td>
    </tr>`).join('');
  $('rejectedTable').querySelector('tbody').innerHTML = rows ||
    '<tr><td colspan="6" style="color:#9fb0c3">无被拒委托记录（已到达主体的出边均可接续，或目标根本无入边）</td></tr>';
  $('reachPanel').hidden = false;
}

function renderAuthEvidence(ev, stale = false) {
  const panel = $('authEvidencePanel');
  const v = ev.verdict;
  $('authVerdict').innerHTML = `
    <p class="${v.allow ? 'allow' : 'deny'}">
      ${stale ? '⚠ 当前为<b>上一份有效证据</b>（本次核验被拒绝，证据未被覆盖）<br>' : ''}
      最终结论：${v.allow ? '✅ 准许' : '⛔ 拒绝'} —— ${esc(v.reason)}
    </p>
    <p style="font-size:12.5px;color:#9fb0c3">
      根公钥指纹 <code>${esc(ev.rootKeyThumbprint)}</code> ·
      目标主体指纹 <code>${esc(ev.targetThumbprint)}</code> · 评估时刻 ${ev.now} ·
      路径按跳数再按规范载荷摘要序列稳定选取
    </p>`;
  $('authHopTable').querySelector('tbody').innerHTML = hopRows(ev.hops);
  $('authFinalConstraints').innerHTML =
    `<p style="font-size:13px;margin-top:12px">路径末端有效约束：${renderConstraints(ev.finalConstraints)}</p>`;
  panel.hidden = false;
}

$('authorizeBtn').addEventListener('click', runAuthorize);
$('authClearBtn').addEventListener('click', () => {
  $('authRootKey').value = '';
  $('authObjects').value = '';
  $('targetKey').value = '';
  $('buoy').value = '';
  $('samples').value = '';
  $('authNow').value = '';
  $('authErrorPanel').hidden = true;
  $('authEvidencePanel').hidden = true;
  $('reachPanel').hidden = true;
  // 注意：清空操作是值班员显式动作，此时一并清除留存证据
  lastValidAuthEvidence = null;
});
