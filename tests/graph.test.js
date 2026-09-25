'use strict';

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { authorizeSet } from '../src/graph.js';
import { canonicalize, parseCanonical } from '../src/canonical.js';
import {
  generateKeyPair,
  issueDelegation,
  rootKeyDocument,
} from '../src/sign.js';

const NOW = 1790000000;

function digestOf(text) {
  const { sig, ...payload } = parseCanonical(text).value;
  return crypto.createHash('sha256')
    .update(Buffer.from(canonicalize(payload), 'utf8'))
    .digest('hex');
}

function shuffle(arr, seed) {
  // 确定性伪随机打乱（测试可复现）
  const a = [...arr];
  let s = seed;
  for (let i = a.length - 1; i > 0; i--) {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    const j = s % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// 标准场景：root -> a -> t（宽），root -> b -> t（窄且含 buoy-02），回环 a->b, b->a
function scenario() {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const b = generateKeyPair();
  const t = generateKeyPair();
  const dRa = issueDelegation({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600, aud: ['buoy-01', 'buoy-02'], maxSamples: 100,
  }, root.privateJwk);
  const dAt = issueDelegation({
    iss: a.publicJwk, sub: t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800, aud: ['buoy-01'], maxSamples: 80,
  }, a.privateJwk);
  const dRb = issueDelegation({
    iss: root.publicJwk, sub: b.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600, aud: ['buoy-01', 'buoy-02'], maxSamples: 100,
  }, root.privateJwk);
  const dBt = issueDelegation({
    iss: b.publicJwk, sub: t.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800, aud: ['buoy-01', 'buoy-02'], maxSamples: 10,
  }, b.privateJwk);
  const dAb = issueDelegation({
    iss: a.publicJwk, sub: b.publicJwk,
    nbf: NOW - 900, exp: NOW + 900, aud: ['buoy-01'], maxSamples: 50,
  }, a.privateJwk);
  const dBa = issueDelegation({
    iss: b.publicJwk, sub: a.publicJwk,
    nbf: NOW - 800, exp: NOW + 800, aud: ['buoy-01'], maxSamples: 40,
  }, b.privateJwk);
  return {
    keys: { root, a, b, t },
    rootKeyText: rootKeyDocument(root.publicJwk),
    targetKeyText: rootKeyDocument(t.publicJwk),
    d: { dRa, dAt, dRb, dBt, dAb, dBa },
  };
}

function query(sc, objects, { buoy = 'buoy-01', samples = 10, now = NOW, targetKeyText } = {}) {
  return authorizeSet({
    rootKeyText: sc.rootKeyText,
    objectTexts: objects,
    targetKeyText: targetKeyText ?? sc.targetKeyText,
    buoy, samples, now,
  });
}

test('乱序集合：按跳数最少选路，与粘贴顺序无关', () => {
  const sc = scenario();
  // buoy-01 / 10 次：root->b->t（上限 10）与 root->a->t（上限 80）均为 2 跳可行
  const objects = shuffle([sc.d.dRa, sc.d.dAt, sc.d.dRb, sc.d.dBt, sc.d.dAb, sc.d.dBa], 7);
  const r = query(sc, objects, { buoy: 'buoy-01', samples: 10 });
  assert.equal(r.ok, true, JSON.stringify(r.error));
  assert.equal(r.evidence.hops.length, 2);
  // 两条 2 跳路径中按摘要序列字典序取小
  const p1 = [digestOf(sc.d.dRa), digestOf(sc.d.dAt)];
  const p2 = [digestOf(sc.d.dRb), digestOf(sc.d.dBt)];
  const want = JSON.stringify(p1) <= JSON.stringify(p2) ? p1 : p2;
  assert.deepEqual(r.evidence.pathDigests, want);
  assert.equal(r.evidence.verdict.allow, true);
  assert.equal(r.evidence.verdict.buoy, 'buoy-01');
  // 逐跳收紧证据：末端有效约束 = 最后一跳委托约束
  const last = r.evidence.hops[r.evidence.hops.length - 1];
  assert.deepEqual(r.evidence.finalConstraints, last.tightened);
});

test('同跳数路径按规范载荷摘要序列字典序稳定选取', () => {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const b = generateKeyPair();
  const t = generateKeyPair();
  const mk = (iss, sub, prv) => issueDelegation({
    iss: iss.publicJwk, sub: sub.publicJwk,
    nbf: NOW - 100, exp: NOW + 100, aud: ['x'], maxSamples: 10,
  }, prv);
  const dRa = mk(root, a, root.privateJwk);
  const dAt = mk(a, t, a.privateJwk);
  const dRb = mk(root, b, root.privateJwk);
  const dBt = mk(b, t, b.privateJwk);
  const input = {
    rootKeyText: rootKeyDocument(root.publicJwk),
    targetKeyText: rootKeyDocument(t.publicJwk),
    buoy: 'x', samples: 5, now: NOW,
  };
  const r1 = authorizeSet({ ...input, objectTexts: [dRa, dAt, dRb, dBt] });
  const r2 = authorizeSet({ ...input, objectTexts: [dBt, dRb, dAt, dRa] });
  assert.equal(r1.ok, true);
  const p1 = [digestOf(dRa), digestOf(dAt)];
  const p2 = [digestOf(dRb), digestOf(dBt)];
  const want = JSON.stringify(p1) <= JSON.stringify(p2) ? p1 : p2;
  assert.deepEqual(r1.evidence.pathDigests, want);
  // 相同集合与查询条件重复核验得到同一条证据路径
  assert.deepEqual(r2.evidence.pathDigests, r1.evidence.pathDigests);
  assert.deepEqual(r2.evidence.hops, r1.evidence.hops);
});

test('回环委托被支配剪枝：求解终止且结果正确', () => {
  const sc = scenario();
  // 含回环 a->b、b->a；目标 buoy-02 只能经 root->b->t（a 路径 aud 不含 buoy-02）
  const objects = [sc.d.dBa, sc.d.dAb, sc.d.dBt, sc.d.dRb, sc.d.dAt, sc.d.dRa];
  const r = query(sc, objects, { buoy: 'buoy-02', samples: 10 });
  assert.equal(r.ok, true, JSON.stringify(r.error));
  assert.equal(r.evidence.hops.length, 2);
  assert.deepEqual(r.evidence.pathDigests, [digestOf(sc.d.dRb), digestOf(sc.d.dBt)]);
});

test('到达同一主体的有效约束不同：不以主体名合并，窄状态被宽状态支配', () => {
  const root = generateKeyPair();
  const s = generateKeyPair();
  const m = generateKeyPair();
  const t = generateKeyPair();
  // 到 s 的两条路径：宽（aud {x,y}）与窄（aud {x}）
  const dWide1 = issueDelegation({
    iss: root.publicJwk, sub: s.publicJwk,
    nbf: NOW - 100, exp: NOW + 100, aud: ['x', 'y'], maxSamples: 100,
  }, root.privateJwk);
  const dNarrow1 = issueDelegation({
    iss: root.publicJwk, sub: m.publicJwk,
    nbf: NOW - 100, exp: NOW + 100, aud: ['x'], maxSamples: 100,
  }, root.privateJwk);
  const dNarrow2 = issueDelegation({
    iss: m.publicJwk, sub: s.publicJwk,
    nbf: NOW - 90, exp: NOW + 90, aud: ['x'], maxSamples: 90,
  }, m.privateJwk);
  // s -> t 的委托 aud {x,y}：只对宽状态是收紧，对窄状态是放宽
  const dSt = issueDelegation({
    iss: s.publicJwk, sub: t.publicJwk,
    nbf: NOW - 50, exp: NOW + 50, aud: ['x', 'y'], maxSamples: 50,
  }, s.privateJwk);
  const input = {
    rootKeyText: rootKeyDocument(root.publicJwk),
    targetKeyText: rootKeyDocument(t.publicJwk),
    buoy: 'y', samples: 10, now: NOW,
  };
  const r = authorizeSet({ ...input, objectTexts: [dNarrow2, dSt, dNarrow1, dWide1] });
  assert.equal(r.ok, true, JSON.stringify(r.error));
  // 只有经宽状态（root->s 直达 1 跳）才能接续 dSt：路径共 2 跳
  assert.equal(r.evidence.hops.length, 2);
  assert.deepEqual(r.evidence.pathDigests, [digestOf(dWide1), digestOf(dSt)]);
});

test('不可比约束状态各自保留（一维更宽不足以支配）', () => {
  const root = generateKeyPair();
  const s = generateKeyPair();
  const t1 = generateKeyPair();
  const t2 = generateKeyPair();
  // s 的两个不可比状态：{aud:{x,y}, cap:10} 与 {aud:{x}, cap:100}
  const dA = issueDelegation({
    iss: root.publicJwk, sub: s.publicJwk,
    nbf: NOW - 100, exp: NOW + 100, aud: ['x', 'y'], maxSamples: 10,
  }, root.privateJwk);
  const dB = issueDelegation({
    iss: root.publicJwk, sub: s.publicJwk,
    nbf: NOW - 100, exp: NOW + 100, aud: ['x'], maxSamples: 100,
  }, root.privateJwk);
  // 仅 aud 宽的状态可接续的委托（需要 y）
  const dTo1 = issueDelegation({
    iss: s.publicJwk, sub: t1.publicJwk,
    nbf: NOW - 50, exp: NOW + 50, aud: ['y'], maxSamples: 5,
  }, s.privateJwk);
  // 仅上限宽的状态可接续的委托（需要 cap>=50）
  const dTo2 = issueDelegation({
    iss: s.publicJwk, sub: t2.publicJwk,
    nbf: NOW - 50, exp: NOW + 50, aud: ['x'], maxSamples: 50,
  }, s.privateJwk);
  const base = {
    rootKeyText: rootKeyDocument(root.publicJwk),
    objectTexts: [dTo2, dA, dTo1, dB],
    now: NOW,
  };
  const r1 = authorizeSet({ ...base, targetKeyText: rootKeyDocument(t1.publicJwk), buoy: 'y', samples: 5 });
  assert.equal(r1.ok, true, JSON.stringify(r1.error));
  assert.deepEqual(r1.evidence.pathDigests, [digestOf(dA), digestOf(dTo1)]);
  const r2 = authorizeSet({ ...base, targetKeyText: rootKeyDocument(t2.publicJwk), buoy: 'x', samples: 50 });
  assert.equal(r2.ok, true, JSON.stringify(r2.error));
  assert.deepEqual(r2.evidence.pathDigests, [digestOf(dB), digestOf(dTo2)]);
});

test('篡改签名的委托不中断求解；不可达时列入最先被拒（BAD_SIGNATURE）', () => {
  const sc = scenario();
  const tampered = (() => {
    const v = parseCanonical(sc.d.dRb, { requireOrderedKeys: false }).value;
    v.maxSamples = 999; // 改写已签名内容但不重签
    return canonicalize(v);
  })();
  // 好路径仍在：root->a->t
  let r = query(sc, [tampered, sc.d.dRa, sc.d.dAt], { buoy: 'buoy-01', samples: 10 });
  assert.equal(r.ok, true, JSON.stringify(r.error));
  assert.equal(r.evidence.hops.length, 2);
  // 只剩篡改委托可达目标：不可达，且其出现在被拒列表
  r = query(sc, [tampered], { buoy: 'buoy-01', samples: 10 });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'NO_AUTHORIZING_PATH');
  const rej = r.reachability.rejections.find((x) => x.code === 'BAD_SIGNATURE');
  assert.ok(rej, '被拒列表应含 BAD_SIGNATURE');
  assert.equal(rej.field, '$["sig"]');
  assert.equal(rej.payloadDigest, digestOf(tampered));
});

test('目标不可达：报告已到达主体与最先被拒委托及限制字段', () => {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const t = generateKeyPair();
  const dRa = issueDelegation({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 100, exp: NOW + 100, aud: ['x'], maxSamples: 10,
  }, root.privateJwk);
  // a -> t 的委托放宽了浮标集合（新增 y）
  const dAt = issueDelegation({
    iss: a.publicJwk, sub: t.publicJwk,
    nbf: NOW - 100, exp: NOW + 100, aud: ['x', 'y'], maxSamples: 10,
  }, a.privateJwk);
  const r = authorizeSet({
    rootKeyText: rootKeyDocument(root.publicJwk),
    objectTexts: [dAt, dRa],
    targetKeyText: rootKeyDocument(t.publicJwk),
    buoy: 'x', samples: 1, now: NOW,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'NO_AUTHORIZING_PATH');
  // 已到达主体：根（0 跳）与 a（1 跳）
  assert.equal(r.reachability.reached.length, 2);
  assert.equal(r.reachability.reached[0].hops, 0);
  assert.equal(r.reachability.reached[0].constraints, null);
  assert.equal(r.reachability.reached[1].hops, 1);
  // 最先被拒：dAt 在 aud 字段放宽
  assert.equal(r.reachability.rejections.length, 1);
  const rej = r.reachability.rejections[0];
  assert.equal(rej.code, 'NOT_TIGHTENED');
  assert.equal(rej.field, '$["aud"]');
  assert.equal(rej.level, 2);
  assert.equal(rej.payloadDigest, digestOf(dAt));
});

test('过期与未生效委托列入被拒（TIME_EXPIRED / TIME_NOT_YET_VALID）', () => {
  const root = generateKeyPair();
  const t1 = generateKeyPair();
  const t2 = generateKeyPair();
  const dOld = issueDelegation({
    iss: root.publicJwk, sub: t1.publicJwk,
    nbf: NOW - 500, exp: NOW - 400, aud: ['x'], maxSamples: 10,
  }, root.privateJwk);
  const dFuture = issueDelegation({
    iss: root.publicJwk, sub: t2.publicJwk,
    nbf: NOW + 400, exp: NOW + 500, aud: ['x'], maxSamples: 10,
  }, root.privateJwk);
  const r1 = authorizeSet({
    rootKeyText: rootKeyDocument(root.publicJwk), objectTexts: [dOld],
    targetKeyText: rootKeyDocument(t1.publicJwk), buoy: 'x', samples: 1, now: NOW,
  });
  assert.equal(r1.ok, false);
  assert.equal(r1.reachability.rejections[0].code, 'TIME_EXPIRED');
  assert.equal(r1.reachability.rejections[0].field, '$["exp"]');
  const r2 = authorizeSet({
    rootKeyText: rootKeyDocument(root.publicJwk), objectTexts: [dFuture],
    targetKeyText: rootKeyDocument(t2.publicJwk), buoy: 'x', samples: 1, now: NOW,
  });
  assert.equal(r2.ok, false);
  assert.equal(r2.reachability.rejections[0].code, 'TIME_NOT_YET_VALID');
  assert.equal(r2.reachability.rejections[0].field, '$["nbf"]');
});

test('到达目标但有效约束不准许权限：不可达', () => {
  const sc = scenario();
  // root->a->t 有效约束 aud={buoy-01}：请求 buoy-02 不可达（b 路径上限仅 10）
  const r = query(sc, [sc.d.dRa, sc.d.dAt], { buoy: 'buoy-02', samples: 10 });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'NO_AUTHORIZING_PATH');
  // 采样量超过路径末端有效约束上限
  const r2 = query(sc, [sc.d.dRa, sc.d.dAt], { buoy: 'buoy-01', samples: 81 });
  assert.equal(r2.ok, false);
  // 恰好等于上限则准许
  const r3 = query(sc, [sc.d.dRa, sc.d.dAt], { buoy: 'buoy-01', samples: 80 });
  assert.equal(r3.ok, true);
});

test('目标即根主体：0 跳准许，空集合亦可', () => {
  const root = generateKeyPair();
  const rootKeyText = rootKeyDocument(root.publicJwk);
  const r = authorizeSet({
    rootKeyText, objectTexts: [], targetKeyText: rootKeyText,
    buoy: 'anything', samples: 999, now: NOW,
  });
  assert.equal(r.ok, true);
  assert.equal(r.evidence.hops.length, 0);
  assert.equal(r.evidence.finalConstraints, null);
  assert.equal(r.evidence.verdict.allow, true);
});

test('相同委托重复粘贴被去重；集合过大被拒绝', () => {
  const sc = scenario();
  const dup = [sc.d.dRa, sc.d.dRa, sc.d.dAt, sc.d.dAt];
  const r = query(sc, dup, { buoy: 'buoy-01', samples: 10 });
  assert.equal(r.ok, true);
  assert.equal(r.evidence.hops.length, 2);
  // 超过 MAX_SET_SIZE
  const big = Array.from({ length: 65 }, () => sc.d.dRa);
  const r2 = query(sc, big);
  assert.equal(r2.ok, false);
  assert.equal(r2.error.code, 'SCHEMA');
});

test('输入校验：command 混入集合 / 非法目标公钥 / 非法采样量与浮标', () => {
  const sc = scenario();
  // command 混入
  const cmd = JSON.parse(JSON.stringify(parseCanonical(sc.d.dAt).value));
  cmd.typ = 'command';
  cmd.buoy = 'buoy-01';
  cmd.samples = 1;
  const cmdText = canonicalize(cmd);
  let r = query(sc, [sc.d.dRa, cmdText]);
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'SCHEMA');
  assert.equal(r.error.hop, 1);
  // 目标公钥非法
  r = query(sc, [sc.d.dRa], { targetKeyText: '{"crv":"P-256"}' });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'SCHEMA');
  r = query(sc, [sc.d.dRa], { targetKeyText: '' });
  assert.equal(r.error.code, 'TARGET_KEY_INVALID');
  // 采样量 / 浮标非法
  r = query(sc, [sc.d.dRa], { samples: 0 });
  assert.equal(r.error.code, 'SCHEMA');
  assert.equal(r.error.field, 'samples');
  r = query(sc, [sc.d.dRa], { samples: 1.5 });
  assert.equal(r.error.code, 'SCHEMA');
  r = query(sc, [sc.d.dRa], { buoy: '' });
  assert.equal(r.error.code, 'SCHEMA');
  assert.equal(r.error.field, 'buoy');
  // 委托文本本身不规范（键序）
  r = query(sc, ['{"typ":"delegation","aud":["x"]}']);
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'KEY_ORDER');
  assert.equal(r.error.hop, 0);
});

test('委托集合求解仍逐份按规范字节验签（键序被破坏即拒绝）', () => {
  const sc = scenario();
  const v = parseCanonical(sc.d.dRa, { requireOrderedKeys: false }).value;
  const entries = [['sig', v.sig], ['aud', v.aud], ['exp', v.exp], ['iss', v.iss],
    ['maxSamples', v.maxSamples], ['nbf', v.nbf], ['sub', v.sub], ['typ', v.typ]];
  const reordered = '{' + entries.map(([k, val]) => `${JSON.stringify(k)}:${JSON.stringify(val)}`).join(',') + '}';
  const r = query(sc, [reordered, sc.d.dAt]);
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'KEY_ORDER');
});
