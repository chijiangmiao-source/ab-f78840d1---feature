'use strict';

// 值班员页面逻辑：乱序委托集合的授权路径搜索（/api/verify-graph），
// 以及旧的按顺序单链逐跳核验（/api/verify，行为保持兼容）。
// 关键约束：错误草稿不得覆盖上一份有效证据——
// lastValid* 只在收到 ok:true 时更新；两种模式各自留存。

const $ = (id) => document.getElementById(id);

// 各模式上一份有效证据（跨多次核验保留）
let lastValidEvidence = null;   // 委托图模式
let lastValidChainEvidence = null; // 单链模式
let mode = 'graph';

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

function setMode(next) {
  mode = next;
  const graph = mode === 'graph';
  $('modeGraph').classList.toggle('active', graph);
  $('modeChain').classList.toggle('active', !graph);
  $('targetKey').closest('div').style.display = graph ? '' : 'none';
  $('buoy').style.display = graph ? '' : 'none';
  $('samples').style.display = graph ? '' : 'none';
  document.querySelectorAll('label[for="buoy"],label[for="samples"]').forEach((el) => {
    el.style.display = graph ? '' : 'none';
  });
  // 输入区文案随模式切换
  const objectsLabel = document.querySelector('label[for="objects"]');
  objectsLabel.textContent = graph
    ? '委托集合（乱序缓存，每行一份 delegation 规范 JSON；顺序无关，自动去重）'
    : '委托链对象（按顺序，每行一份：委托…→ 末端命令）';
  $('verifyBtn').textContent = graph ? '搜索授权路径' : '逐跳核验';
  // 切模式时隐藏上一模态的结论区（留存数据不清空）
  $('errorPanel').hidden = true;
  $('evidencePanel').hidden = true;
  $('reachedBlock').innerHTML = '';
}

async function runVerify() {
  const rootKey = $('rootKey').value.trim();
  const objects = splitObjects($('objects').value);
  const nowRaw = $('now').value.trim();

  let path;
  let body;
  if (mode === 'graph') {
    path = '/api/verify-graph';
    body = {
      rootKey,
      delegations: objects,
      targetKey: $('targetKey').value.trim(),
      buoy: $('buoy').value.trim(),
      samples: Number($('samples').value),
    };
    const samplesRaw = $('samples').value.trim();
    if (!samplesRaw || !/^\d+$/.test(samplesRaw)) {
      showLocalError({ code: 'BAD_REQUEST', hop: -1, field: '$["samples"]', message: '采样量必须是 ≥1 的整数' });
      return;
    }
  } else {
    path = '/api/verify';
    body = { rootKey, objects };
  }
  if (nowRaw) {
    if (!/^\d+$/.test(nowRaw)) {
      showLocalError({ code: 'BAD_REQUEST', hop: -1, field: 'now', message: '评估时刻必须是非负整数 unix 秒' });
      return;
    }
    body.now = Number(nowRaw);
  }

  $('verifyBtn').disabled = true;
  try {
    const resp = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const result = await resp.json();
    if (result.ok) {
      if (mode === 'graph') {
        lastValidEvidence = result.evidence; // 仅此处覆盖
        renderEvidence(result.evidence, false);
      } else {
        lastValidChainEvidence = result.evidence;
        renderEvidence(result.evidence, false);
      }
      hideError();
    } else {
      renderError(result.error);
      const stale = mode === 'graph' ? lastValidEvidence : lastValidChainEvidence;
      if (stale) renderEvidence(stale, true);
      renderReached(result.unreachable);
    }
  } catch (e) {
    showLocalError({ code: 'NETWORK', hop: -1, field: null, message: `请求失败：${e.message}` });
  } finally {
    $('verifyBtn').disabled = false;
  }
}

function showLocalError(err) {
  renderError(err);
  const stale = mode === 'graph' ? lastValidEvidence : lastValidChainEvidence;
  if (stale) renderEvidence(stale, true);
}

function hideError() {
  $('errorPanel').hidden = true;
  $('reachedBlock').innerHTML = '';
}

function renderError(err) {
  const panel = $('errorPanel');
  const body = $('errorBody');
  const hopText = err.hop === -1 || err.hop == null
    ? '根公钥 / 请求'
    : mode === 'graph'
      ? `到达跳数 ${err.hop}`
      : `第 ${err.hop} 跳${err.hop === 0 ? '（链首）' : ''}`;
  const loc = err.line ? `（行 ${err.line}，列 ${err.col}）` : '';
  body.innerHTML = `
    <dl>
      <dt>错误码</dt><dd class="mono">${esc(err.code || 'UNKNOWN')}</dd>
      <dt>定位</dt><dd>${esc(hopText)}${err.field ? ` · 字段 <code>${esc(err.field)}</code>` : ''}${loc}</dd>
      <dt>说明</dt><dd>${esc(err.message || '')}</dd>
    </dl>`;
  panel.hidden = false;
}

function renderConstraints(c) {
  return `nbf=<b>${c.nbf}</b>，exp=<b>${c.exp}</b>，` +
    `浮标=[${esc(c.aud.map((b) => `"${b}"`).join(', '))}]，` +
    `上限=<b>${c.maxSamples}</b>`;
}

function renderReached(unreachable) {
  const box = $('reachedBlock');
  if (!unreachable || !Array.isArray(unreachable.reached) || unreachable.reached.length === 0) {
    box.innerHTML = '';
    return;
  }
  const rows = unreachable.reached.map((r) => {
    const rej = r.firstRejected
      ? `${esc(rej.code)}${rej.field ? ` · <code>${esc(rej.field)}</code>` : ''}：${esc(rej.message)}`
      : '<span style="color:#4ade80">存在可接续委托（仍在搜索前沿）</span>';
    return `<tr>
      <td class="mono">${esc(r.subjectThumbprint.slice(0, 20))}…</td>
      <td>${r.hops}</td>
      <td style="font-size:12px">${rej}</td>
    </tr>`;
  }).join('');
  box.innerHTML = `
    <h3 style="font-size:13.5px;color:#7fd1ff;margin:16px 0 6px">已到达主体及最先被拒的委托（诊断）</h3>
    <table>
      <thead><tr><th>主体指纹</th><th>到达跳数</th><th>最先被拒委托与限制字段</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
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
      根公钥指纹 <code>${esc(ev.rootKeyThumbprint)}</code>
      ${ev.targetThumbprint ? ` · 目标主体指纹 <code>${esc(ev.targetThumbprint)}</code>` : ''}
      · 评估时刻 ${ev.now}
    </p>`;

  const tbody = $('hopTable').querySelector('tbody');
  tbody.innerHTML = ev.hops.map((h) => `
    <tr>
      <td>${h.index}</td>
      <td><span class="pill ${h.typ === 'command' ? 'cmd' : ''}">${esc(h.typ)}</span></td>
      <td class="mono" title="${esc(h.signature)}">${esc(short(h.signature, 20))}</td>
      <td class="mono">${esc(h.payloadDigest)}</td>
      <td class="mono" title="iss">${esc(h.issThumbprint.slice(0, 16))}…</td>
      <td class="mono" title="sub">${esc(h.subThumbprint.slice(0, 16))}…</td>
      <td style="font-size:12px">${renderConstraints(h.tightened)}</td>
    </tr>`).join('');

  $('finalConstraints').innerHTML =
    `<p style="font-size:13px;margin-top:12px">收紧后的最终约束：${renderConstraints(ev.finalConstraints)}</p>`;
  panel.hidden = false;
}

$('verifyBtn').addEventListener('click', runVerify);
$('modeGraph').addEventListener('click', () => setMode('graph'));
$('modeChain').addEventListener('click', () => setMode('chain'));
$('clearBtn').addEventListener('click', () => {
  $('rootKey').value = '';
  $('objects').value = '';
  $('now').value = '';
  $('targetKey').value = '';
  $('buoy').value = '';
  $('samples').value = '';
  $('errorPanel').hidden = true;
  $('evidencePanel').hidden = true;
  $('reachedBlock').innerHTML = '';
  // 注意：清空操作是值班员显式动作，此时一并清除留存证据
  lastValidEvidence = null;
  lastValidChainEvidence = null;
});

setMode('graph');
