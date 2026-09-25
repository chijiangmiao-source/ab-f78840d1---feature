'use strict';

// 受限委托链逐跳核验。
//
// 链对象（每份均为规范 JSON，键按 JCS 顺序）：
//   委托  delegation: { aud, exp, iss, maxSamples, nbf, sig, sub, typ }
//   命令  command:    { aud, buoy, exp, iss, maxSamples, nbf, samples, sig, sub, typ }
//   - iss/sub: P-256 JWK { crv:"P-256", kty:"EC", x, y }（base64url，无填充）
//   - nbf/exp: 有效期（unix 秒，int32 区间内的整数）
//   - aud:     允许浮标集合（非空字符串数组，元素唯一）
//   - maxSamples: 采样上限（int32 区间内的整数，>=0）
//   - sig:     对“去掉 sig 成员后的规范 JSON 字节”的 ECDSA P-256/SHA-256
//              签名（IEEE-P1363 r||s，base64url 无填充）
//   末端命令额外字段：buoy（目标浮标）、samples（请求采样量，>=1）
//
// 链规则：
//   1. 链首 iss 必须等于根公钥；其后每跳 iss 必须等于上一跳 sub；
//   2. 每跳仅允许收紧：nbf 不提前、exp 不延后、aud 为上一跳子集、
//      maxSamples 不大于上一跳；
//   3. 每跳在评估时刻必须处于有效期内；
//   4. 末端命令的 buoy 须获全部上游 aud 允许，samples 不超过任一 maxSamples；
//   5. 任一失败即拒绝，并定位首个限制字段或签名失败跳。
//
// 单份对象的模式校验 / 验签等共享逻辑见 model.js；
// 乱序委托集合的授权状态图求解见 graph.js。

import {
  b64urlEncode,
  b64urlDecode,
  sha256Hex,
  jwkThumbprint,
  jwkEquals,
  ChainError,
  validateJwk,
  validateObjectSchema,
  verifySignature,
  payloadDigestOf,
  normalizeError,
  fail,
  parseCanonical,
  LIMITS,
  MAX_CHAIN_LEN,
  MAX_OBJECT_BYTES,
} from './model.js';

// 主入口：核验整条链。
// input: { rootKeyText, objectTexts: string[], now?: number(秒) }
// 返回 { ok:true, evidence } 或 { ok:false, error:{code,hop,field,message,line,col} }
function verifyChain(input) {
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
    const parsed = parseCanonical(input.rootKeyText);
    rootKey = validateJwk(parsed.value, -1, 'rootKey');
  } catch (e) {
    return fail(normalizeError(e, -1, 'rootKey'));
  }

  // ---- 链对象 ----
  const texts = input.objectTexts;
  if (!Array.isArray(texts) || texts.length === 0) {
    return fail(new ChainError('SCHEMA', -1, 'objects', '委托链不能为空（至少一份末端命令）'));
  }
  if (texts.length > MAX_CHAIN_LEN) {
    return fail(new ChainError('SCHEMA', -1, 'objects', `链过长（>${MAX_CHAIN_LEN} 跳）`));
  }

  const hops = [];
  for (let i = 0; i < texts.length; i++) {
    const text = texts[i];
    if (typeof text !== 'string' || text.length === 0) {
      return fail(new ChainError('SCHEMA', i, '$', `第 ${i} 跳不是非空字符串`));
    }
    if (Buffer.byteLength(text, 'utf8') > MAX_OBJECT_BYTES) {
      return fail(new ChainError('SCHEMA', i, '$', `第 ${i} 跳文档过大（>${MAX_OBJECT_BYTES} 字节）`));
    }
    let parsed;
    try {
      parsed = parseCanonical(text);
    } catch (e) {
      return fail(normalizeError(e, i, null));
    }
    let model;
    try {
      model = validateObjectSchema(parsed, i, { total: texts.length });
    } catch (e) {
      return fail(normalizeError(e, i, null));
    }

    // 规范载荷字节 = 去掉 sig 后的 JCS 字节（与签发时同一套字节）
    const { payloadBytes, payloadDigest } = payloadDigestOf(parsed.value);

    // 1) 逐跳验签（用本跳 iss 的公钥）
    if (!verifySignature(model.iss, payloadBytes, model.sigRaw)) {
      return fail(new ChainError('BAD_SIGNATURE', i, '$["sig"]',
        `第 ${i} 跳签名验证失败（签名与规范载荷摘要不符，载荷 SHA-256=${payloadDigest}）`));
    }

    // 2) 链式签发关系
    if (i === 0) {
      if (!jwkEquals(model.iss, rootKey)) {
        return fail(new ChainError('ISSUER_NOT_ROOT', 0, '$["iss"]',
          '链首签发者不等于根公钥（iss 与 rootKey 的 JWK 不一致）'));
      }
    } else if (!jwkEquals(model.iss, hops[i - 1].model.sub)) {
      return fail(new ChainError('ISSUER_MISMATCH', i, '$["iss"]',
        `第 ${i} 跳委托并非由前一主体签发（iss ≠ 第 ${i - 1} 跳 sub）`));
    }

    // 3) 收紧检查（仅允许收紧，定位首个违规字段）
    if (i > 0) {
      const prev = hops[i - 1].model;
      if (model.nbf < prev.nbf) {
        return fail(new ChainError('NOT_TIGHTENED', i, '$["nbf"]',
          `第 ${i} 跳有效期起早于上一跳（${model.nbf} < ${prev.nbf}），时间窗只允许收紧`));
      }
      if (model.exp > prev.exp) {
        return fail(new ChainError('NOT_TIGHTENED', i, '$["exp"]',
          `第 ${i} 跳有效期止晚于上一跳（${model.exp} > ${prev.exp}），时间窗只允许收紧`));
      }
      const prevAud = new Set(prev.aud);
      const extra = model.aud.filter((b) => !prevAud.has(b));
      if (extra.length > 0) {
        return fail(new ChainError('NOT_TIGHTENED', i, '$["aud"]',
          `第 ${i} 跳浮标集合超出上一跳允许范围（新增：${extra.join(', ')}），浮标集合只允许收紧`));
      }
      if (model.maxSamples > prev.maxSamples) {
        return fail(new ChainError('NOT_TIGHTENED', i, '$["maxSamples"]',
          `第 ${i} 跳采样上限大于上一跳（${model.maxSamples} > ${prev.maxSamples}），采样上限只允许收紧`));
      }
    }

    // 4) 有效期（评估时刻须落在每跳时间窗内）
    if (now < model.nbf) {
      return fail(new ChainError('TIME_NOT_YET_VALID', i, '$["nbf"]',
        `第 ${i} 跳尚未生效（now=${now} < nbf=${model.nbf}）`));
    }
    if (now > model.exp) {
      return fail(new ChainError('TIME_EXPIRED', i, '$["exp"]',
        `第 ${i} 跳已过期（now=${now} > exp=${model.exp}）`));
    }

    hops.push({ model, payloadDigest, sig: model.sig });
  }

  // ---- 末端命令：浮标须获全部上游允许、采样量不超过任一上限 ----
  const last = hops[hops.length - 1].model;
  if (last.typ !== 'command') {
    return fail(new ChainError('SCHEMA', hops.length - 1, '$["typ"]', '链末端必须是 command 对象'));
  }
  for (let j = 0; j < hops.length; j++) {
    if (!hops[j].model.aud.includes(last.buoy)) {
      return fail(new ChainError('BUOY_NOT_ALLOWED', j, '$["aud"]',
        `末端浮标 "${last.buoy}" 未获第 ${j} 跳允许（不在该跳 aud 集合内）`));
    }
  }
  for (let j = 0; j < hops.length; j++) {
    if (last.samples > hops[j].model.maxSamples) {
      return fail(new ChainError('SAMPLES_EXCEEDED', j, '$["maxSamples"]',
        `采样量 ${last.samples} 超过第 ${j} 跳采样上限 ${hops[j].model.maxSamples}`));
    }
  }

  // ---- 汇总证据 ----
  const hopEvidence = [];
  let curAud = null;
  let curNbf = 0;
  let curExp = LIMITS.INT32_MAX;
  let curCap = LIMITS.INT32_MAX;
  for (let i = 0; i < hops.length; i++) {
    const m = hops[i].model;
    curAud = curAud === null ? [...m.aud] : curAud.filter((b) => m.aud.includes(b));
    curNbf = Math.max(curNbf, m.nbf);
    curExp = Math.min(curExp, m.exp);
    curCap = Math.min(curCap, m.maxSamples);
    hopEvidence.push({
      index: i,
      typ: m.typ,
      issThumbprint: jwkThumbprint(m.iss),
      subThumbprint: jwkThumbprint(m.sub),
      signature: hops[i].sig,
      payloadDigest: hops[i].payloadDigest,
      tightened: { nbf: curNbf, exp: curExp, aud: [...curAud], maxSamples: curCap },
    });
  }

  return {
    ok: true,
    evidence: {
      now,
      rootKeyThumbprint: jwkThumbprint(rootKey),
      hops: hopEvidence,
      finalConstraints: { nbf: curNbf, exp: curExp, aud: curAud, maxSamples: curCap },
      verdict: {
        allow: true,
        buoy: last.buoy,
        samples: last.samples,
        reason: `链核验通过：准许浮标 "${last.buoy}" 采样 ${last.samples} 次`,
      },
    },
  };
}

export {
  verifyChain,
  b64urlEncode,
  b64urlDecode,
  jwkThumbprint,
  sha256Hex,
  LIMITS,
  MAX_CHAIN_LEN,
};
