'use strict';

// 链式核验与集合授权共用的链对象模型：
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
// 本模块只做单份对象的模式校验、规范载荷摘要与验签；
// 链规则见 chain.js，授权状态图求解见 graph.js。

import crypto from 'node:crypto';
import {
  parseCanonical,
  canonicalBytes,
  requireBoundedInteger,
  LIMITS,
} from './canonical.js';

const MAX_CHAIN_LEN = 16;
const MAX_SET_SIZE = 64;
const MAX_OBJECT_BYTES = 64 * 1024;
const MAX_BUOYS = 256;
const MAX_BUOY_ID_LEN = 128;

function b64urlEncode(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) return null;
  let b = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b.length % 4) b += '=';
  return Buffer.from(b, 'base64');
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function jwkThumbprint(jwk) {
  // RFC 7638 所需成员按字典序的规范 JSON
  const canon = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  return sha256Hex(Buffer.from(canon, 'utf8'));
}

function jwkEquals(a, b) {
  return a && b && a.kty === b.kty && a.crv === b.crv && a.x === b.x && a.y === b.y;
}

class ChainError extends Error {
  constructor(code, hop, field, message, extra = {}) {
    super(message);
    this.code = code;
    this.hop = hop;
    this.field = field;
    Object.assign(this, extra);
  }
}

function isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

// 校验 P-256 JWK 形状；返回规范化后的 {kty,crv,x,y}
function validateJwk(value, hop, field) {
  if (!isPlainObject(value)) {
    throw new ChainError('SCHEMA', hop, field, `${field} 必须是 JWK 对象`);
  }
  const keys = Object.keys(value).sort();
  const want = ['crv', 'kty', 'x', 'y'];
  if (keys.length !== 4 || !want.every((k, i) => keys[i] === k)) {
    throw new ChainError('SCHEMA', hop, field,
      `${field} 必须恰好包含成员 crv,kty,x,y（实际：${keys.join(',')}）`);
  }
  if (value.kty !== 'EC') {
    throw new ChainError('SCHEMA', hop, `${field}["kty"]`, `${field} 的 kty 必须为 "EC"`);
  }
  if (value.crv !== 'P-256') {
    throw new ChainError('SCHEMA', hop, `${field}["crv"]`, `${field} 的 crv 必须为 "P-256"`);
  }
  for (const coord of ['x', 'y']) {
    const v = value[coord];
    if (typeof v !== 'string') {
      throw new ChainError('SCHEMA', hop, `${field}["${coord}"]`, `${field} 的 ${coord} 必须是 base64url 字符串`);
    }
    const raw = b64urlDecode(v);
    if (raw === null || raw.length !== 32 || b64urlEncode(raw) !== v) {
      throw new ChainError('SCHEMA', hop, `${field}["${coord}"]`,
        `${field} 的 ${coord} 必须是 32 字节的规范 base64url（无填充）`);
    }
  }
  return { kty: 'EC', crv: 'P-256', x: value.x, y: value.y };
}

function validateAud(value, hop) {
  const field = '$["aud"]';
  if (!Array.isArray(value) || value.length === 0) {
    throw new ChainError('SCHEMA', hop, field, 'aud 必须是非空数组（允许浮标集合）');
  }
  if (value.length > MAX_BUOYS) {
    throw new ChainError('SCHEMA', hop, field, `aud 元素过多（>${MAX_BUOYS}）`);
  }
  const seen = new Set();
  for (let i = 0; i < value.length; i++) {
    const b = value[i];
    if (typeof b !== 'string' || b.length === 0 || b.length > MAX_BUOY_ID_LEN) {
      throw new ChainError('SCHEMA', hop, `$["aud"][${i}]`, `浮标标识必须是 1..${MAX_BUOY_ID_LEN} 字符的字符串`);
    }
    if (seen.has(b)) {
      throw new ChainError('SCHEMA', hop, `$["aud"][${i}]`, `aud 中浮标标识重复："${b}"`);
    }
    seen.add(b);
  }
  return value;
}

// 校验单个链对象的模式与整数边界；返回规范化字段。
// opts.total 提供时，command 仅允许位于该位置（链式核验）；
// opts.allowCommand === false 时（委托集合），command 一律拒绝。
function validateObjectSchema(parsed, index, { total = null, allowCommand = true } = {}) {
  const hop = index;
  const obj = parsed.value;
  const numbers = parsed.numbers;
  if (!isPlainObject(obj)) {
    throw new ChainError('SCHEMA', hop, '$', `第 ${index} 跳必须是 JSON 对象`);
  }
  const typ = obj.typ;
  if (typ !== 'delegation' && typ !== 'command') {
    throw new ChainError('SCHEMA', hop, '$["typ"]', 'typ 必须是 "delegation" 或 "command"');
  }
  if (typ === 'command' && !allowCommand) {
    throw new ChainError('SCHEMA', hop, '$["typ"]',
      '委托集合中不允许 command 对象（浮标 / 采样量由查询条件给出）');
  }
  if (typ === 'command' && total !== null && index !== total - 1) {
    throw new ChainError('SCHEMA', hop, '$["typ"]', 'command 对象只能位于链末端');
  }
  const required = ['aud', 'exp', 'iss', 'maxSamples', 'nbf', 'sig', 'sub', 'typ'];
  if (typ === 'command') required.push('buoy', 'samples');
  for (const k of required) {
    if (!(k in obj)) {
      throw new ChainError('SCHEMA', hop, '$', `缺少必需成员 "${k}"`);
    }
  }
  const allowed = new Set(required);
  for (const k of Object.keys(obj)) {
    if (!allowed.has(k)) {
      throw new ChainError('SCHEMA', hop, `$["${k}"]`, `不允许的额外成员 "${k}"（疑似内容被改写）`);
    }
  }

  const iss = validateJwk(obj.iss, hop, '$["iss"]');
  const sub = validateJwk(obj.sub, hop, '$["sub"]');

  const nbf = requireBoundedInteger(numbers, '$["nbf"]', {
    min: 0, max: LIMITS.INT32_MAX, label: '有效期起 nbf ',
  });
  const exp = requireBoundedInteger(numbers, '$["exp"]', {
    min: 0, max: LIMITS.INT32_MAX, label: '有效期止 exp ',
  });
  if (nbf >= exp) {
    throw new ChainError('SCHEMA', hop, '$["nbf"]', `有效期无效：nbf(${nbf}) 必须早于 exp(${exp})`);
  }
  const maxSamples = requireBoundedInteger(numbers, '$["maxSamples"]', {
    min: 0, max: LIMITS.INT32_MAX, label: '采样上限 maxSamples ',
  });
  const aud = validateAud(obj.aud, hop);

  if (typeof obj.sig !== 'string') {
    throw new ChainError('SCHEMA', hop, '$["sig"]', 'sig 必须是 base64url 字符串');
  }
  const sigRaw = b64urlDecode(obj.sig);
  if (sigRaw === null || sigRaw.length !== 64 || b64urlEncode(sigRaw) !== obj.sig) {
    throw new ChainError('SCHEMA', hop, '$["sig"]',
      'sig 必须是 64 字节 P1363 签名的规范 base64url（无填充）');
  }

  let buoy;
  let samples;
  if (typ === 'command') {
    if (typeof obj.buoy !== 'string' || obj.buoy.length === 0 || obj.buoy.length > MAX_BUOY_ID_LEN) {
      throw new ChainError('SCHEMA', hop, '$["buoy"]', 'buoy 必须是非空字符串（目标浮标）');
    }
    buoy = obj.buoy;
    samples = requireBoundedInteger(numbers, '$["samples"]', {
      min: 1, max: LIMITS.INT32_MAX, label: '采样量 samples ',
    });
  }

  return { typ, iss, sub, nbf, exp, aud, maxSamples, sig: obj.sig, sigRaw, buoy, samples };
}

function importJwk(jwk) {
  return crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk' });
}

// 用 iss 公钥对规范载荷字节验签（ECDSA P-256/SHA-256，P1363）
function verifySignature(issJwk, payloadBytes, sigRaw) {
  try {
    return crypto.verify('sha256', payloadBytes, {
      key: importJwk(issJwk),
      dsaEncoding: 'ieee-p1363',
    }, sigRaw);
  } catch {
    return false;
  }
}

// 规范载荷字节 = 去掉 sig 后的 JCS 字节（与签发时同一套字节）
function payloadDigestOf(parsedValue) {
  const { sig, ...payload } = parsedValue;
  const payloadBytes = canonicalBytes(payload);
  return { payloadBytes, payloadDigest: sha256Hex(payloadBytes) };
}

function normalizeError(e, hop, field) {
  if (e instanceof ChainError) return e;
  const code = e.code || 'JSON_SYNTAX';
  const err = new ChainError(code, hop, field || e.field || null, e.message);
  if (e.line !== undefined) err.line = e.line;
  if (e.col !== undefined) err.col = e.col;
  if (e.pos !== undefined) err.pos = e.pos;
  return err;
}

function fail(err) {
  return {
    ok: false,
    error: {
      code: err.code,
      hop: err.hop,
      field: err.field ?? null,
      message: err.message,
      line: err.line ?? null,
      col: err.col ?? null,
    },
  };
}

export {
  b64urlEncode,
  b64urlDecode,
  sha256Hex,
  jwkThumbprint,
  jwkEquals,
  ChainError,
  isPlainObject,
  validateJwk,
  validateAud,
  validateObjectSchema,
  importJwk,
  verifySignature,
  payloadDigestOf,
  normalizeError,
  fail,
  parseCanonical,
  LIMITS,
  MAX_CHAIN_LEN,
  MAX_SET_SIZE,
  MAX_OBJECT_BYTES,
  MAX_BUOYS,
  MAX_BUOY_ID_LEN,
};
