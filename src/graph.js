'use strict';

// 乱序离线委托集合的授权状态图求解。
//
// 值班员粘贴：根公钥 + 乱序缓存的委托集合 + 目标主体公钥 + 浮标 + 采样量 + 评估时刻，
// 求解「目标主体能否经任意合法委托路径取得这项权限」。
//
// 模型：
//   - 每份委托仍按同一套规范 JSON 字节逐份验签（与链式核验一致）；
//   - 授权状态 = (主体, 有效约束 {nbf, exp, aud, maxSamples})，根主体初始状态为 TOP（未受限）；
//     不能只按主体名称合并状态：到达同一主体的有效时间窗 / 浮标集 / 采样上限不同，
//     后续可接续的委托也不同；
//   - 沿边（委托）传播时约束只允许收紧：nbf 不提前、exp 不延后、aud 为子集、
//     maxSamples 不更大；由于收紧单调，新状态的有效约束即该委托自身约束；
//   - 回环精确处理：绕环回到同一主体的状态必然不宽于先前状态，被支配剪枝，
//     搜索因此在有限状态图上终止（状态数 ≤ 委托份数 + 1）；
//   - 支配：仅在同一主体上“更宽的有效约束”（四个维度全部不窄）支配较窄状态，
//     不可比的状态（如时间窗更宽但浮标集更窄）各自保留；
//   - 路径选取：按跳数升序、再按规范载荷摘要序列字典序稳定选取——
//     相同委托集合与查询条件重复核验必得同一条证据路径，与粘贴顺序无关。
//
// 目标不可达时，返回已到达主体及从其出发最先被拒的委托与限制字段。

import {
  jwkThumbprint,
  ChainError,
  validateJwk,
  validateObjectSchema,
  verifySignature,
  payloadDigestOf,
  normalizeError,
  fail,
  parseCanonical,
  LIMITS,
  MAX_SET_SIZE,
  MAX_OBJECT_BYTES,
  MAX_BUOY_ID_LEN,
} from './model.js';

const TOP = null; // 根主体初始有效约束：未受限

function constraintsOf(model) {
  return { nbf: model.nbf, exp: model.exp, aud: [...model.aud].sort(), maxSamples: model.maxSamples };
}

function constraintsView(cons) {
  if (cons === TOP) return null;
  return { nbf: cons.nbf, exp: cons.exp, aud: [...cons.aud], maxSamples: cons.maxSamples };
}

function stateKey(subThumb, cons) {
  if (cons === TOP) return `${subThumb}|TOP`;
  return `${subThumb}|${cons.nbf}|${cons.exp}|${cons.maxSamples}|${JSON.stringify(cons.aud)}`;
}

// a 是否支配 b（同一主体上 a 的有效约束在所有维度不窄于 b）
function dominates(a, b) {
  if (a === TOP) return true;
  if (b === TOP) return false;
  return a.nbf <= b.nbf && a.exp >= b.exp && a.maxSamples >= b.maxSamples
    && b.aud.every((x) => a.aud.includes(x));
}

// 当前有效约束 -> 委托的收紧检查；返回首个被放宽的字段，或 null（合法收紧）
function firstWidenedField(cons, m) {
  if (cons === TOP) return null;
  if (m.nbf < cons.nbf) {
    return { field: '$["nbf"]', message: `有效期起早于当前已收紧约束（${m.nbf} < ${cons.nbf}），时间窗只允许收紧` };
  }
  if (m.exp > cons.exp) {
    return { field: '$["exp"]', message: `有效期止晚于当前已收紧约束（${m.exp} > ${cons.exp}），时间窗只允许收紧` };
  }
  const extra = m.aud.filter((b) => !cons.aud.includes(b));
  if (extra.length > 0) {
    return { field: '$["aud"]', message: `浮标集合超出当前已收紧约束（新增：${extra.join(', ')}），浮标集合只允许收紧` };
  }
  if (m.maxSamples > cons.maxSamples) {
    return { field: '$["maxSamples"]', message: `采样上限大于当前已收紧约束（${m.maxSamples} > ${cons.maxSamples}），采样上限只允许收紧` };
  }
  return null;
}

function allows(cons, buoy, samples) {
  if (cons === TOP) return true;
  return cons.aud.includes(buoy) && samples <= cons.maxSamples;
}

// 路径优先级：先跳数，再规范载荷摘要序列字典序
function cmpPriority(a, b) {
  if (a.hops !== b.hops) return a.hops - b.hops;
  const n = Math.min(a.seq.length, b.seq.length);
  for (let i = 0; i < n; i++) {
    if (a.seq[i] < b.seq[i]) return -1;
    if (a.seq[i] > b.seq[i]) return 1;
  }
  return a.seq.length - b.seq.length;
}

// 主入口：乱序委托集合授权求解。
// input: { rootKeyText, objectTexts: string[], targetKeyText, buoy, samples, now? }
// 返回 { ok:true, evidence }；
//      { ok:false, error }（输入非法，与链式核验同形）；
//      { ok:false, error:{code:'NO_AUTHORIZING_PATH',...}, reachability }（目标不可达）。
function authorizeSet(input) {
  const now = input.now === undefined ? Math.floor(Date.now() / 1000) : input.now;
  if (!Number.isInteger(now) || now < 0 || now > LIMITS.INT32_MAX) {
    return fail(new ChainError('SCHEMA', -1, 'now', '评估时刻 now 必须是 int32 区间内的整数秒'));
  }

  // ---- 根公钥 / 目标主体公钥 ----
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
    return fail(normalizeError(e, -1, 'rootKey'));
  }

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
    return fail(normalizeError(e, -1, 'targetKey'));
  }

  // ---- 查询条件：浮标 / 采样量 ----
  const buoy = input.buoy;
  if (typeof buoy !== 'string' || buoy.length === 0 || buoy.length > MAX_BUOY_ID_LEN) {
    return fail(new ChainError('SCHEMA', -1, 'buoy', 'buoy 必须是非空字符串（目标浮标）'));
  }
  const samples = input.samples;
  if (!Number.isInteger(samples) || samples < 1 || samples > LIMITS.INT32_MAX) {
    return fail(new ChainError('SCHEMA', -1, 'samples', 'samples 必须是 [1, 2^31-1] 区间内的整数（请求采样量）'));
  }

  // ---- 委托集合：逐份解析、模式校验、验签 ----
  const texts = input.objectTexts;
  if (!Array.isArray(texts)) {
    return fail(new ChainError('SCHEMA', -1, 'objects', '委托集合必须是数组（可为空）'));
  }
  if (texts.length > MAX_SET_SIZE) {
    return fail(new ChainError('SCHEMA', -1, 'objects', `委托集合过大（>${MAX_SET_SIZE} 份）`));
  }

  const edgesByText = new Map(); // 去重：相同规范文本只保留首份
  for (let i = 0; i < texts.length; i++) {
    const text = texts[i];
    if (typeof text !== 'string' || text.length === 0) {
      return fail(new ChainError('SCHEMA', i, '$', `集合第 ${i} 份不是非空字符串`));
    }
    if (edgesByText.has(text)) continue; // 缓存重复，忽略
    if (Buffer.byteLength(text, 'utf8') > MAX_OBJECT_BYTES) {
      return fail(new ChainError('SCHEMA', i, '$', `集合第 ${i} 份文档过大（>${MAX_OBJECT_BYTES} 字节）`));
    }
    let parsed;
    try {
      parsed = parseCanonical(text);
    } catch (e) {
      return fail(normalizeError(e, i, null));
    }
    let model;
    try {
      model = validateObjectSchema(parsed, i, { allowCommand: false });
    } catch (e) {
      return fail(normalizeError(e, i, null));
    }
    const { payloadBytes, payloadDigest } = payloadDigestOf(parsed.value);
    // 逐份验签（同一套规范 JSON 字节）；签名无效者不中断求解，作为不可用边记录
    const sigOk = verifySignature(model.iss, payloadBytes, model.sigRaw);
    edgesByText.set(text, {
      model,
      digest: payloadDigest,
      issThumb: jwkThumbprint(model.iss),
      subThumb: jwkThumbprint(model.sub),
      sigOk,
    });
  }
  const edges = [...edgesByText.values()];

  // 邻接表：签发者指纹 -> 委托边（按规范载荷摘要排序，保证与粘贴顺序无关）
  const adjacency = new Map();
  for (const e of edges) {
    const list = adjacency.get(e.issThumb) || [];
    list.push(e);
    adjacency.set(e.issThumb, list);
  }
  for (const list of adjacency.values()) {
    list.sort((a, b) => (a.digest < b.digest ? -1 : a.digest > b.digest ? 1
      : a.model.sig < b.model.sig ? -1 : a.model.sig > b.model.sig ? 1 : 0));
  }

  const rootThumb = jwkThumbprint(rootKey);
  const targetThumb = jwkThumbprint(targetKey);

  // ---- 授权状态图搜索（按 (跳数, 摘要序列) 优先级出队）----
  const pq = [];
  const best = new Map(); // stateKey -> 最优状态对象（身份比较识别陈旧项）
  const settledExact = new Set();
  const settledBySubject = new Map(); // subThumb -> 已定居有效约束数组（支配判定）
  const reached = []; // 已到达主体（不可达报告用）
  const rejections = []; // 最先被拒的委托（按搜索顺序，逐份去重）
  const rejectedDigests = new Set();

  function pushState(state) {
    const key = stateKey(state.subThumb, state.cons);
    if (settledExact.has(key)) return;
    const known = best.get(key);
    if (known && cmpPriority(known, state) <= 0) return;
    best.set(key, state);
    pq.push(state);
  }

  function recordRejection(level, fromThumb, edge, code, field, message) {
    if (rejectedDigests.has(edge.digest)) return; // 同一委托只保留最先一次被拒
    rejectedDigests.add(edge.digest);
    rejections.push({ level, fromThumbprint: fromThumb, payloadDigest: edge.digest, code, field, message });
  }

  pushState({ subThumb: rootThumb, cons: TOP, hops: 0, seq: [], path: [] });

  while (pq.length > 0) {
    let mi = 0;
    for (let i = 1; i < pq.length; i++) {
      if (cmpPriority(pq[i], pq[mi]) < 0) mi = i;
    }
    const cur = pq.splice(mi, 1)[0];
    const key = stateKey(cur.subThumb, cur.cons);
    if (settledExact.has(key)) continue;
    if (best.get(key) !== cur) continue; // 陈旧项：已有更优路径到达该状态
    settledExact.add(key);

    const settledCons = settledBySubject.get(cur.subThumb) || [];
    if (settledCons.some((c) => dominates(c, cur.cons))) continue; // 被更宽状态支配（含回环）
    settledCons.push(cur.cons);
    settledBySubject.set(cur.subThumb, settledCons);
    reached.push({ subjectThumbprint: cur.subThumb, hops: cur.hops, constraints: constraintsView(cur.cons) });

    // 目标判定：到达目标主体且有效约束准许所请求权限
    if (cur.subThumb === targetThumb && allows(cur.cons, buoy, samples)) {
      const hops = cur.path.map((p, i) => ({
        index: i,
        typ: 'delegation',
        issThumbprint: p.edge.issThumb,
        subThumbprint: p.edge.subThumb,
        signature: p.edge.model.sig,
        payloadDigest: p.edge.digest,
        tightened: constraintsView(p.cons),
      }));
      const finalConstraints = constraintsView(cur.cons);
      return {
        ok: true,
        evidence: {
          now,
          rootKeyThumbprint: rootThumb,
          targetThumbprint: targetThumb,
          hops,
          pathDigests: [...cur.seq],
          finalConstraints,
          verdict: {
            allow: true,
            buoy,
            samples,
            reason: hops.length === 0
              ? '目标主体即根主体：无需委托即拥有全部权限'
              : `授权路径核验通过：目标主体经 ${hops.length} 跳合法委托路径取得浮标 "${buoy}" 采样 ${samples} 次的权限`,
          },
        },
      };
    }

    // 扩展：当前主体签发的每份委托（顺序确定）；
    // 拒绝原因报告顺序与链式核验一致：签名 → 收紧 → 时效
    for (const e of adjacency.get(cur.subThumb) || []) {
      const level = cur.hops + 1;
      if (!e.sigOk) {
        recordRejection(level, cur.subThumb, e, 'BAD_SIGNATURE', '$["sig"]',
          `签名验证失败（签名与规范载荷摘要不符，载荷 SHA-256=${e.digest}）`);
        continue;
      }
      const widened = firstWidenedField(cur.cons, e.model);
      if (widened) {
        recordRejection(level, cur.subThumb, e, 'NOT_TIGHTENED', widened.field, widened.message);
        continue;
      }
      if (now < e.model.nbf) {
        recordRejection(level, cur.subThumb, e, 'TIME_NOT_YET_VALID', '$["nbf"]',
          `委托尚未生效（now=${now} < nbf=${e.model.nbf}）`);
        continue;
      }
      if (now > e.model.exp) {
        recordRejection(level, cur.subThumb, e, 'TIME_EXPIRED', '$["exp"]',
          `委托已过期（now=${now} > exp=${e.model.exp}）`);
        continue;
      }
      const cons = constraintsOf(e.model);
      // 入队前支配预检：绕环回到已到达主体且约束不更宽时不必入队
      const settledNext = settledBySubject.get(e.subThumb) || [];
      if (settledNext.some((c) => dominates(c, cons))) continue;
      pushState({
        subThumb: e.subThumb,
        cons,
        hops: level,
        seq: [...cur.seq, e.digest],
        path: [...cur.path, { edge: e, cons }],
      });
    }
  }

  // ---- 目标不可达：报告已到达主体与最先被拒的委托 ----
  return {
    ok: false,
    error: {
      code: 'NO_AUTHORIZING_PATH',
      hop: null,
      field: null,
      message: `目标主体不可达：不存在使其取得浮标 "${buoy}" 采样 ${samples} 次权限的合法委托路径`,
      line: null,
      col: null,
    },
    reachability: {
      now,
      buoy,
      samples,
      rootKeyThumbprint: rootThumb,
      targetThumbprint: targetThumb,
      reached,
      rejections,
    },
  };
}

export { authorizeSet };
