'use strict';

// 乱序委托集合上的授权状态图搜索。
//
// 值班员粘贴的是一批「乱序缓存」的离线委托（不再是排好序的单链）：
//   - 每份委托仍按既有规范 JSON 字节（JCS, RFC 8785）逐份解析、模式校验、
//     用其 iss 公钥逐份验签（与单链核验完全同一套字节与规则）；
//   - 委托构成有向图：边 iss -> sub，携带该跳声明的约束
//     {nbf, exp, aud, maxSamples}；
//   - 不能只按主体名称合并搜索状态：到达同一主体的不同路径可能留下不同的
//     有效时间窗、允许浮标集、采样上限，且后续可接续的委托不同。因此每个
//     主体保留一张「互不支配」的约束状态前沿（Pareto front）。
//
// 单调收紧与支配：
//   沿任意路径约束只能收紧（nbf 单调不降、exp 单调不升、aud 单调缩小、
//   maxSamples 单调不增）。状态 A 支配状态 B ⇔ A 的四项约束逐项宽于或等于
//   B（时间窗包含、浮标集为超集、采样上限不更小）。被支配的较窄状态不可能
//   到达更宽状态到不了的地方，剪枝不损失可达性；约束全等时按「规范载荷摘要
//   序列」字典序保留唯一规范状态，保证重复核验证据路径稳定。
//
// 回环：沿环约束单调收紧；要么至少一项严格收紧（产生新的更窄状态，可接续
// 不同的下游委托），要么全等（被支配/决胜剪枝，环终止）。各分量取值来自
// 有限的委托字段，配合最大路径跳数，工作集必然收敛，精确处理回环。
//
// 成功：在所有可达的目标主体状态中，选择满足「浮标获允许、采样量不超限」
// 的状态，按跳数、再按规范载荷摘要序列确定唯一路径，输出逐跳收紧证据。
// 失败：输出已到达主体，以及从该主体出发、在其全部到达状态下都最先被拒的
// 委托与限制字段。

import crypto from 'node:crypto';
import {
  parseCanonical,
  canonicalBytes,
} from './canonical.js';
import {
  ChainError,
  validateJwk,
  validateObjectSchema,
  importJwk,
  jwkThumbprint,
  sha256Hex,
  LIMITS,
  MAX_OBJECT_BYTES,
} from './chain.js';

// 单次核验允许粘贴的委托份数与证据路径最大跳数（与单链 MAX_CHAIN_LEN 对齐）
const MAX_GRAPH_OBJECTS = 256;
const MAX_PATH_HOPS = 16;

// ---------- 约束：收紧、比较、支配 ----------

function audContains(superset, subset) {
  if (superset.length < subset.length) return false;
  const set = new Set(superset);
  return subset.every((b) => set.has(b));
}

// 比较约束宽窄：
//   返回 1 ：a 宽于 b（至少一项严格更宽，其余不窄）——a 支配 b
//   返回 0 ：逐项全等
//  返回 -1 ：a 不宽于 b（更窄、或不可比较）
function compareWidth(a, b) {
  if (a === null) return b === null ? 0 : 1; // 根状态（宇宙约束）宽于一切
  let wider = false;
  if (a.nbf > b.nbf) return -1;
  if (a.nbf < b.nbf) wider = true;
  if (a.exp < b.exp) return -1;
  if (a.exp > b.exp) wider = true;
  if (a.maxSamples < b.maxSamples) return -1;
  if (a.maxSamples > b.maxSamples) wider = true;
  if (!audContains(a.aud, b.aud)) return -1;
  if (a.aud.length !== b.aud.length) wider = true;
  return wider ? 1 : 0;
}

// 在状态约束 cur（根状态为 null）之后接续委托边 edge：
//   合法 → 返回收紧后的新约束；非法 → 返回 {rejected:{code,field,message}}。
// 检查顺序与单链核验一致：nbf、exp、aud、maxSamples、时效。
function applyEdge(cur, edge, now) {
  const e = edge.constraints;
  if (cur !== null) {
    if (e.nbf < cur.nbf) {
      return { rejected: new ChainError('NOT_TIGHTENED', null, '$["nbf"]',
        `时间窗被放宽：nbf ${e.nbf} 早于到达约束 ${cur.nbf}（只允许收紧）`) };
    }
    if (e.exp > cur.exp) {
      return { rejected: new ChainError('NOT_TIGHTENED', null, '$["exp"]',
        `时间窗被放宽：exp ${e.exp} 晚于到达约束 ${cur.exp}（只允许收紧）`) };
    }
    const curAud = new Set(cur.aud);
    const extra = e.aud.filter((b) => !curAud.has(b));
    if (extra.length > 0) {
      return { rejected: new ChainError('NOT_TIGHTENED', null, '$["aud"]',
        `浮标集合被放宽：新增 ${extra.join(', ')}（只允许收紧为到达集合的子集）`) };
    }
    if (e.maxSamples > cur.maxSamples) {
      return { rejected: new ChainError('NOT_TIGHTENED', null, '$["maxSamples"]',
        `采样上限被放宽：${e.maxSamples} 大于到达上限 ${cur.maxSamples}（只允许收紧）`) };
    }
  }
  if (now < e.nbf) {
    return { rejected: new ChainError('TIME_NOT_YET_VALID', null, '$["nbf"]',
      `委托尚未生效（now=${now} < nbf=${e.nbf}）`) };
  }
  if (now > e.exp) {
    return { rejected: new ChainError('TIME_EXPIRED', null, '$["exp"]',
      `委托已过期（now=${now} > exp=${e.exp}）`) };
  }
  const nextAud = cur === null
    ? [...e.aud]
    : e.aud.filter((b) => cur.aud.includes(b));
  return {
    constraints: {
      nbf: Math.max(cur?.nbf ?? e.nbf, e.nbf),
      exp: Math.min(cur?.exp ?? e.exp, e.exp),
      aud: nextAud,
      maxSamples: Math.min(cur?.maxSamples ?? e.maxSamples, e.maxSamples),
    },
  };
}

// 规范载荷摘要序列字典序比较（每项均为等长十六进制串）
function compareDigestKey(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return a.length - b.length;
}

function errObject(e) {
  return {
    code: e.code,
    hop: e.hop ?? null,
    field: e.field ?? null,
    message: e.message,
    line: e.line ?? null,
    col: e.col ?? null,
  };
}

function fail(e, extra = {}) {
  return { ok: false, error: errObject(e), ...extra };
}

// ---------- 主入口 ----------
// input: { rootKeyText, delegationTexts: string[], targetKeyText,
//          buoy, samples, now? }
export function verifyDelegationGraph(input) {
  const now = input.now === undefined ? Math.floor(Date.now() / 1000) : input.now;
  if (!Number.isInteger(now) || now < 0 || now > LIMITS.INT32_MAX) {
    return fail(new ChainError('SCHEMA', -1, 'now', '评估时刻 now 必须是 int32 区间内的整数秒'));
  }

  // ---- 根公钥 ----
  let rootKey;
  try {
    if (typeof input.rootKeyText !== 'string' || input.rootKeyText.length === 0) {
      throw new ChainError('ROOT_KEY_INVALID', -1, 'rootKey', '根公钥不能为空');
    }
    if (Buffer.byteLength(input.rootKeyText, 'utf8') > MAX_OBJECT_BYTES) {
      throw new ChainError('ROOT_KEY_INVALID', -1, 'rootKey', '根公钥文档过大');
    }
    rootKey = validateJwk(parseCanonical(input.rootKeyText).value, -1, 'rootKey');
  } catch (e) {
    return fail(e instanceof ChainError ? e : normalizeParse(e, -1, 'rootKey'));
  }

  // ---- 目标主体公钥 ----
  let targetKey;
  try {
    if (typeof input.targetKeyText !== 'string' || input.targetKeyText.length === 0) {
      throw new ChainError('TARGET_KEY_INVALID', -1, 'targetKey', '目标主体公钥不能为空');
    }
    if (Buffer.byteLength(input.targetKeyText, 'utf8') > MAX_OBJECT_BYTES) {
      throw new ChainError('TARGET_KEY_INVALID', -1, 'targetKey', '目标主体公钥文档过大');
    }
    targetKey = validateJwk(parseCanonical(input.targetKeyText).value, -1, 'targetKey');
  } catch (e) {
    return fail(e instanceof ChainError ? e : normalizeParse(e, -1, 'targetKey'));
  }

  // ---- 目标浮标 / 采样量 ----
  let buoy;
  let samples;
  try {
    if (typeof input.buoy !== 'string' || input.buoy.length === 0 || input.buoy.length > 128) {
      throw new ChainError('SCHEMA', -1, '$["buoy"]', '目标浮标 buoy 必须是 1..128 字符的非空字符串');
    }
    buoy = input.buoy;
    if (!Number.isInteger(input.samples) || input.samples < 1 || input.samples > LIMITS.INT32_MAX) {
      throw new ChainError('SCHEMA', -1, '$["samples"]', '采样量 samples 必须是 [1, 2^31-1] 内的整数');
    }
    samples = input.samples;
  } catch (e) {
    return fail(e);
  }

  // ---- 委托集合：逐份 JCS 解析 / 模式校验 / 验签 ----
  const texts = input.delegationTexts;
  if (!Array.isArray(texts) || texts.length === 0) {
    return fail(new ChainError('SCHEMA', -1, 'delegations', '委托集合不能为空（至少一份 delegation）'));
  }
  if (texts.length > MAX_GRAPH_OBJECTS) {
    return fail(new ChainError('SCHEMA', -1, 'delegations', `委托过多（>${MAX_GRAPH_OBJECTS} 份）`));
  }

  const edges = [];
  for (let i = 0; i < texts.length; i++) {
    const text = texts[i];
    if (typeof text !== 'string' || text.length === 0) {
      return fail(new ChainError('SCHEMA', i, '$', `第 ${i} 份委托不是非空字符串`));
    }
    if (Buffer.byteLength(text, 'utf8') > MAX_OBJECT_BYTES) {
      return fail(new ChainError('SCHEMA', i, '$', `第 ${i} 份委托文档过大（>${MAX_OBJECT_BYTES} 字节）`));
    }
    let parsed;
    try {
      parsed = parseCanonical(text);
    } catch (e) {
      return fail(normalizeParse(e, i, null));
    }
    let model;
    try {
      model = validateObjectSchema(parsed, i, texts.length, { requireDelegationOnly: true });
    } catch (e) {
      return fail(e);
    }

    const { sig: _sig, ...payload } = parsed.value;
    const payloadBytes = canonicalBytes(payload);
    const payloadDigest = sha256Hex(payloadBytes);

    let sigOk = false;
    try {
      sigOk = crypto.verify('sha256', payloadBytes, {
        key: importJwk(model.iss),
        dsaEncoding: 'ieee-p1363',
      }, model.sigRaw);
    } catch {
      sigOk = false;
    }
    if (!sigOk) {
      return fail(new ChainError('BAD_SIGNATURE', i, '$["sig"]',
        `第 ${i} 份委托签名验证失败（签名与规范载荷摘要不符，载荷 SHA-256=${payloadDigest}）`));
    }

    edges.push({
      iss: model.iss,
      sub: model.sub,
      issTp: jwkThumbprint(model.iss),
      subTp: jwkThumbprint(model.sub),
      signature: model.sig,
      payloadDigest,
      constraints: {
        nbf: model.nbf,
        exp: model.exp,
        aud: [...model.aud].sort(),
        maxSamples: model.maxSamples,
      },
    });
  }

  // 边的规范身份与遍历顺序只取内容摘要，与粘贴顺序无关；
  // 完全相同的委托文本去重（保留一份规范边）。
  const edgeById = new Map();
  for (const edge of edges) {
    if (!edgeById.has(edge.payloadDigest)) edgeById.set(edge.payloadDigest, edge);
  }
  const canonEdges = [...edgeById.values()].sort((a, b) => (a.payloadDigest < b.payloadDigest ? -1 : 1));
  canonEdges.forEach((edge, idx) => { edge.canonicalIndex = idx; });

  const byIssuer = new Map();
  for (const edge of canonEdges) {
    if (!byIssuer.has(edge.issTp)) byIssuer.set(edge.issTp, []);
    byIssuer.get(edge.issTp).push(edge); // canonEdges 已按摘要排序
  }

  const rootTp = jwkThumbprint(rootKey);
  const targetTp = jwkThumbprint(targetKey);

  // ---- 约束状态图工作集（标签修正） ----
  // 每个主体一张互不支配的标签前沿；标签被更宽/同宽更优标签取代即失活。
  let labelSeq = 0;
  const fronts = new Map(); // thumbprint -> { subject, labels: label[] }
  const queue = [];

  const rootLabel = {
    id: labelSeq++, subject: rootKey, subjectTp: rootTp,
    constraints: null, // 根：宇宙约束
    hops: 0, digestKey: [], parent: null, edge: null, active: true,
  };
  fronts.set(rootTp, { subject: rootKey, labels: [rootLabel] });
  queue.push(rootLabel);

  function insertLabel(subject, subjectTp, cNew, hops, digestKey, parent, edge) {
    let entry = fronts.get(subjectTp);
    if (!entry) {
      entry = { subject, labels: [] };
      fronts.set(subjectTp, entry);
    }
    // 回到根主体：根的宇宙状态恒支配一切，直接剪枝（回环终止）
    if (subjectTp === rootTp) return null;

    // 前沿标签同时受「约束宽窄」与「跳数」支配：
    //   旧标签 L 支配新标签 N ⇔ L 约束宽于或等于 N，且 L.hops <= N.hops。
    // 约束全等时取跳数最少；跳数相同再按摘要序列决胜。
    // 更长路径带来的更宽状态虽不能淘汰更短的窄状态（后者给出最短证据），
    // 但仍保留在前沿（它能承载更大的权限）。
    const toDeactivate = [];
    for (const existing of entry.labels) {
      const cmp = compareWidth(existing.constraints, cNew);
      if (cmp === 1) {
        if (existing.hops <= hops) return null;       // 更宽且不更长 → 新状态被支配
        continue;                                      // 更宽但更长：两者都保留
      }
      if (cmp === 0) {
        if (existing.hops < hops) return null;
        if (existing.hops === hops) {
          if (compareDigestKey(existing.digestKey, digestKey) <= 0) return null;
          toDeactivate.push(existing);                 // 同跳数全等，新路径更优 → 取代
        } else {
          toDeactivate.push(existing);                 // 全等约束但新路径更短 → 取代
        }
      } else if (compareWidth(cNew, existing.constraints) === 1) {
        if (hops <= existing.hops) toDeactivate.push(existing); // 新状态更宽且不更长 → 旧状态失效
        // 新状态更宽但更长：互不支配，共存
      }
      // 不可比较 → 共存于前沿
    }
    for (const l of toDeactivate) l.active = false;
    entry.labels = entry.labels.filter((l) => l.active);
    const label = {
      id: labelSeq++, subject, subjectTp,
      constraints: cNew, hops, digestKey, parent, edge, active: true,
    };
    entry.labels.push(label);
    queue.push(label);
    return label;
  }

  while (queue.length > 0) {
    const label = queue.shift();
    if (!label.active) continue;
    if (label.hops >= MAX_PATH_HOPS) continue;

    const outgoing = byIssuer.get(label.subjectTp);
    if (!outgoing) continue;
    for (const edge of outgoing) {
      const res = applyEdge(label.constraints, edge, now);
      if (res.rejected) continue; // 拒绝边在收敛后的诊断阶段统一汇总
      insertLabel(
        edge.sub, edge.subTp, res.constraints,
        label.hops + 1, [...label.digestKey, edge.payloadDigest],
        label, edge,
      );
    }
  }

  // ---- 目标判定 ----
  const targetEntry = fronts.get(targetTp);
  const feasibleGoals = [];
  if (targetEntry) {
    for (const label of targetEntry.labels) {
      if (!label.active || label.constraints === null) continue; // 目标即根：零跳不构成授权
      if (label.constraints.aud.includes(buoy) && samples <= label.constraints.maxSamples) {
        feasibleGoals.push(label);
      }
    }
  }
  feasibleGoals.sort((a, b) => (a.hops - b.hops) || compareDigestKey(a.digestKey, b.digestKey));

  if (feasibleGoals.length > 0) {
    return buildSuccess(feasibleGoals[0], { rootKey, rootTp, now, buoy, samples, targetKey, targetTp });
  }

  // ---- 失败：目标不可达 / 权限不足，附已到达主体与最先被拒委托 ----
  const reached = buildReachedDiagnostics(fronts, byIssuer, now);

  // 目标可达但这项权限不足：沿用单链末端限制码，定位到目标到达状态的跳数
  if (targetEntry) {
    const canonical = [...targetEntry.labels]
      .filter((l) => l.active && l.constraints !== null)
      .sort((a, b) => (a.hops - b.hops) || compareDigestKey(a.digestKey, b.digestKey))[0];
    if (canonical) {
      if (!canonical.constraints.aud.includes(buoy)) {
        return fail(new ChainError('BUOY_NOT_ALLOWED', canonical.hops, '$["aud"]',
          `目标主体虽可达，但其最宽到达状态不允许浮标 "${buoy}"`),
          { unreachable: { targetThumbprint: targetTp, reached } });
      }
      return fail(new ChainError('SAMPLES_EXCEEDED', canonical.hops, '$["maxSamples"]',
        `目标主体虽可达，但其最宽到达状态采样上限 ${canonical.constraints.maxSamples} < 请求 ${samples}`),
        { unreachable: { targetThumbprint: targetTp, reached } });
    }
  }

  return fail(new ChainError('TARGET_UNREACHABLE', -1, 'targetKey',
    targetTp === rootTp
      ? '目标主体即根公钥：不存在经委托取得权限的路径（零跳不构成授权）'
      : '目标主体不可达：不存在一条签名有效、逐跳收紧且在评估时刻有效的委托路径'),
    { unreachable: { targetThumbprint: targetTp, reached } });
}

// ---------- 成功证据 ----------
function buildSuccess(goalLabel, ctx) {
  const edges = [];
  for (let l = goalLabel; l.parent !== null; l = l.parent) edges.push(l.edge);
  edges.reverse();

  const hopEvidence = [];
  let cur = null;
  for (let i = 0; i < edges.length; i++) {
    const edge = edges[i];
    const res = applyEdge(cur, edge, ctx.now);
    cur = res.constraints;
    hopEvidence.push({
      index: i,
      delegationIndex: edge.canonicalIndex,
      typ: 'delegation',
      issThumbprint: edge.issTp,
      subThumbprint: edge.subTp,
      signature: edge.signature,
      payloadDigest: edge.payloadDigest,
      tightened: { nbf: cur.nbf, exp: cur.exp, aud: [...cur.aud], maxSamples: cur.maxSamples },
    });
  }

  return {
    ok: true,
    evidence: {
      now: ctx.now,
      rootKeyThumbprint: ctx.rootTp,
      targetThumbprint: ctx.targetTp,
      hops: hopEvidence,
      finalConstraints: { nbf: cur.nbf, exp: cur.exp, aud: [...cur.aud], maxSamples: cur.maxSamples },
      verdict: {
        allow: true,
        buoy: ctx.buoy,
        samples: ctx.samples,
        reason: `授权路径核验通过：目标主体经 ${edges.length} 跳合法委托取得浮标 "${ctx.buoy}" 采样 ${ctx.samples} 次的权限`,
      },
    },
  };
}

// ---------- 失败诊断：已到达主体 + 最先被拒委托 ----------
function buildReachedDiagnostics(fronts, byIssuer, now) {
  const out = [];
  for (const [tp, entry] of fronts) {
    const active = entry.labels.filter((l) => l.active);
    const canonical = [...active]
      .sort((a, b) => (a.hops - b.hops) || compareDigestKey(a.digestKey, b.digestKey))[0];
    const item = {
      subjectThumbprint: tp,
      hops: canonical.hops,
      firstRejected: null,
    };
    const outgoing = byIssuer.get(tp);
    if (!outgoing || outgoing.length === 0) {
      item.firstRejected = { code: 'NO_OUTGOING_DELEGATION', field: null, message: '该主体未签发任何委托' };
    } else {
      // 根主体的规范状态为 null（宇宙约束），applyEdge 同样适用：跳过收紧检查、
      // 只验时效。任一到达状态能接续该委托就不算被拒。
      for (const edge of outgoing) {
        const accepted = active.some((l) => !applyEdge(l.constraints, edge, now).rejected);
        if (accepted) continue;
        // 全部到达状态都拒绝：报告规范状态下的限制字段
        const r = applyEdge(canonical.constraints, edge, now).rejected;
        item.firstRejected = {
          code: r.code,
          field: r.field,
          message: r.message,
          delegationDigest: edge.payloadDigest,
          delegationIndex: edge.canonicalIndex,
        };
        break; // 按规范摘要序的第一份被拒委托
      }
    }
    out.push(item);
  }
  // 稳定展示：先按跳数、再按主体指纹
  out.sort((a, b) => (a.hops - b.hops) || (a.subjectThumbprint < b.subjectThumbprint ? -1 : 1));
  return out;
}

function normalizeParse(e, hop, field) {
  if (e instanceof ChainError) return e;
  const ne = new ChainError(e.code || 'JSON_SYNTAX', hop, field || e.field || null, e.message);
  if (e.line !== undefined) ne.line = e.line;
  if (e.col !== undefined) ne.col = e.col;
  if (e.pos !== undefined) ne.pos = e.pos;
  return ne;
}

export {
  MAX_GRAPH_OBJECTS,
  MAX_PATH_HOPS,
  compareWidth,
  applyEdge,
};
