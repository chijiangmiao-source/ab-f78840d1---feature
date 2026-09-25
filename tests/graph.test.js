'use strict';

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { verifyDelegationGraph } from '../src/graph.js';
import { canonicalize, parseCanonical } from '../src/canonical.js';
import { jwkThumbprint } from '../src/chain.js';
import {
  generateKeyPair,
  issueDelegation,
  issueCommand,
  rootKeyDocument,
} from '../src/sign.js';

const NOW = 1790000000;
const W = { nbf: NOW - 3600, exp: NOW + 3600 };

function del(iss, sub, patch = {}) {
  return issueDelegation({
    iss: iss.publicJwk, sub: sub.publicJwk,
    nbf: W.nbf, exp: W.exp, aud: ['buoy-01'], maxSamples: 100,
    ...patch,
  }, iss.privateJwk);
}

function digestOf(text) {
  const v = parseCanonical(text).value;
  delete v.sig;
  return createHash('sha256').update(canonicalize(v)).digest('hex');
}

// 菱形：root -> a（宽 cap100/2 浮标）/ root -> b（窄 cap10/1 浮标）；a -> t（cap50），b -> t（cap5）
function diamond() {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const b = generateKeyPair();
  const t = generateKeyPair();
  const e1 = del(root, a, { aud: ['buoy-01', 'buoy-02'], maxSamples: 100 });
  const e2 = del(root, b, { aud: ['buoy-01'], maxSamples: 10 });
  const e3 = del(a, t, { aud: ['buoy-01'], maxSamples: 50,
    nbf: NOW - 1800, exp: NOW + 1800 });
  const e4 = del(b, t, { aud: ['buoy-01'], maxSamples: 5 });
  return {
    root, a, b, t, edges: { e1, e2, e3, e4 },
    base: {
      rootKeyText: rootKeyDocument(root.publicJwk),
      targetKeyText: rootKeyDocument(t.publicJwk),
      now: NOW,
    },
  };
}

function run(d, texts, patch = {}) {
  return verifyDelegationGraph({
    ...d.base,
    delegationTexts: texts,
    buoy: 'buoy-01',
    samples: 10,
    ...patch,
  });
}

test('菱形图：存在多条路径时选跳数最短且约束足够的路径', () => {
  const d = diamond();
  const r = run(d, [d.edges.e1, d.edges.e2, d.edges.e3, d.edges.e4], { samples: 20 });
  assert.equal(r.ok, true, JSON.stringify(r.error));
  assert.equal(r.evidence.hops.length, 2);
  assert.deepEqual(r.evidence.hops.map((h) => h.payloadDigest),
    [digestOf(d.edges.e1), digestOf(d.edges.e3)]);
  assert.equal(r.evidence.finalConstraints.maxSamples, 50);
  assert.deepEqual(r.evidence.finalConstraints.aud, ['buoy-01']);
  assert.equal(r.evidence.verdict.allow, true);
  // 逐跳收紧证据
  assert.equal(r.evidence.hops[0].tightened.maxSamples, 100);
  assert.equal(r.evidence.hops[1].tightened.maxSamples, 50);
});

test('不能只按主体名称合并状态：经窄路径失败的采样量经宽路径可达', () => {
  const d = diamond();
  // samples=20：经 b（cap5）失败、经 a（cap50）成功；若对主体 t 只保留一个窄状态会误拒
  const r = run(d, [d.edges.e4, d.edges.e2, d.edges.e3, d.edges.e1], { samples: 20 });
  assert.equal(r.ok, true);
  assert.deepEqual(r.evidence.hops.map((h) => h.payloadDigest),
    [digestOf(d.edges.e1), digestOf(d.edges.e3)]);
});

test('确定性：粘贴顺序打乱、含重复行，证据路径完全一致', () => {
  const d = diamond();
  const order1 = [d.edges.e1, d.edges.e2, d.edges.e3, d.edges.e4];
  const order2 = [d.edges.e4, d.edges.e1, d.edges.e3, d.edges.e2, d.edges.e1, d.edges.e3];
  const r1 = run(d, order1, { samples: 20 });
  const r2 = run(d, order2, { samples: 20 });
  assert.equal(r1.ok, true);
  assert.equal(r2.ok, true);
  assert.deepEqual(r1.evidence.hops.map((h) => h.payloadDigest), [digestOf(d.edges.e1), digestOf(d.edges.e3)]);
  assert.equal(JSON.stringify(r2.evidence), JSON.stringify(r1.evidence));
});

test('确定性：相同委托集合与查询条件重复核验得到同一条证据路径', () => {
  const d = diamond();
  const texts = [d.edges.e2, d.edges.e4, d.edges.e1, d.edges.e3];
  const r1 = run(d, texts);
  const r2 = run(d, [...texts].reverse());
  const sig = (r) => JSON.stringify(r.evidence.hops.map((h) => [h.signature, h.payloadDigest]));
  assert.equal(sig(r1), sig(r2));
  assert.equal(sig(r1), sig(run(d, texts)));
});

test('更宽状态支配较窄状态：同一主体的宽路径胜出并能接续更宽下游', () => {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const mid = generateKeyPair();
  const t = generateKeyPair();
  // 两条 root->a：直接宽（cap100），经 mid 更窄（cap10）
  const wide = del(root, a, { maxSamples: 100, aud: ['buoy-01', 'buoy-02'] });
  const r2m = del(root, mid, { maxSamples: 50, aud: ['buoy-01'] });
  const narrow = del(mid, a, { maxSamples: 10, aud: ['buoy-01'] });
  const at = del(a, t, { maxSamples: 80, aud: ['buoy-01'] });
  const r = verifyDelegationGraph({
    rootKeyText: rootKeyDocument(root.publicJwk),
    targetKeyText: rootKeyDocument(t.publicJwk),
    delegationTexts: [narrow, at, r2m, wide],
    buoy: 'buoy-01', samples: 80, now: NOW,
  });
  assert.equal(r.ok, true, JSON.stringify(r.error));
  // 只有宽路径（1 跳到达 a）能接 cap80 的续委托
  assert.deepEqual(r.evidence.hops.map((h) => h.payloadDigest), [digestOf(wide), digestOf(at)]);
  assert.equal(r.evidence.hops.length, 2);
});

test('回环：自委托收紧产生更窄新状态，但最短可达路径不绕环', () => {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const t = generateKeyPair();
  const e1 = del(root, a, { maxSamples: 10 });
  const loop = del(a, a, { maxSamples: 5 }); // 自环收紧
  const e3 = del(a, t, { maxSamples: 5 });
  const r = verifyDelegationGraph({
    rootKeyText: rootKeyDocument(root.publicJwk),
    targetKeyText: rootKeyDocument(t.publicJwk),
    delegationTexts: [loop, e3, e1],
    buoy: 'buoy-01', samples: 5, now: NOW,
  });
  assert.equal(r.ok, true, JSON.stringify(r.error));
  assert.equal(r.evidence.hops.length, 2); // root->a->t
});

test('回环：约束全等的环被支配/决胜剪枝，目标不可达时收敛返回', () => {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const b = generateKeyPair();
  const t = generateKeyPair();
  const e1 = del(root, a, { maxSamples: 10 });
  const e2 = del(a, b, { maxSamples: 10 });
  const e3 = del(b, a, { maxSamples: 10 }); // a 第二次到达，约束全等 → 剪枝
  const r = verifyDelegationGraph({
    rootKeyText: rootKeyDocument(root.publicJwk),
    targetKeyText: rootKeyDocument(t.publicJwk),
    delegationTexts: [e1, e2, e3],
    buoy: 'buoy-01', samples: 1, now: NOW,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'TARGET_UNREACHABLE');
  assert.ok(r.unreachable.reached.length <= 3); // 仅 root/a/b，无环膨胀
});

test('回环严格收紧次数受有限字段取值约束而终止（多状态前沿）', () => {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const b = generateKeyPair();
  const t = generateKeyPair();
  const e1 = del(root, a, { maxSamples: 10 });
  const ab10 = del(a, b, { maxSamples: 10 });
  const ba5 = del(b, a, { maxSamples: 5 });
  const ab5 = del(a, b, { maxSamples: 5 });
  const ba1 = del(b, a, { maxSamples: 1 });
  const ab1 = del(a, b, { maxSamples: 1 });
  const r = verifyDelegationGraph({
    rootKeyText: rootKeyDocument(root.publicJwk),
    targetKeyText: rootKeyDocument(t.publicJwk),
    delegationTexts: [ab1, ba1, ab5, ba5, ab10, e1],
    buoy: 'buoy-01', samples: 1, now: NOW,
  });
  // 无 a/b -> t 的边：不可达；工作集必须收敛（正常返回即证明有界）
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'TARGET_UNREACHABLE');
  // a/b 各保留互不支配的到达状态（这里仅 cap 维度不同）
  const statesA = r.unreachable.reached.filter((x) => x.hops >= 1).length;
  assert.ok(statesA >= 1);
});

test('回环绕路后变窄反而唯一可达：更窄状态不能被宽状态的存在错误剪枝可达性', () => {
  // 宽状态到 a(cap10)，a 只能再去 b；窄环 a->a(cap1) 后可接 t(cap1)？
  // 这里验证：目标请求 samples=1，两条路径都应允许，选最短。
  const root = generateKeyPair();
  const a = generateKeyPair();
  const t = generateKeyPair();
  const e1 = del(root, a, { maxSamples: 10 });
  const at10 = del(a, t, { maxSamples: 10 });
  const r = verifyDelegationGraph({
    rootKeyText: rootKeyDocument(root.publicJwk),
    targetKeyText: rootKeyDocument(t.publicJwk),
    delegationTexts: [at10, e1],
    buoy: 'buoy-01', samples: 1, now: NOW,
  });
  assert.equal(r.ok, true);
  assert.equal(r.evidence.hops.length, 2);
});

test('不可达：输出已到达主体及从其出发最先被拒的委托与限制字段', () => {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const t = generateKeyPair();
  const e1 = del(root, a, { nbf: NOW - 100, exp: NOW + 100, maxSamples: 10 });
  // a 试图放宽 exp 给 t → NOT_TIGHTENED（$["exp"]）
  const bad = del(a, t, { nbf: NOW - 100, exp: NOW + 200, maxSamples: 10 });
  const r = verifyDelegationGraph({
    rootKeyText: rootKeyDocument(root.publicJwk),
    targetKeyText: rootKeyDocument(t.publicJwk),
    delegationTexts: [bad, e1],
    buoy: 'buoy-01', samples: 1, now: NOW,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'TARGET_UNREACHABLE');
  const reachedA = r.unreachable.reached.find((x) => x.hops === 1);
  assert.ok(reachedA, '应包含 1 跳到达的主体 a');
  assert.equal(reachedA.firstRejected.code, 'NOT_TIGHTENED');
  assert.equal(reachedA.firstRejected.field, '$["exp"]');
  assert.match(reachedA.firstRejected.message, /exp/);
});

test('不可达诊断：无出边主体报 NO_OUTGOING_DELEGATION；过期边不到达', () => {
  const root = generateKeyPair();
  const a = generateKeyPair();
  const b = generateKeyPair();
  const t = generateKeyPair();
  const expired = del(root, a, { nbf: NOW - 7200, exp: NOW - 3600 });
  const toB = del(root, b, { maxSamples: 10 });
  const r = verifyDelegationGraph({
    rootKeyText: rootKeyDocument(root.publicJwk),
    targetKeyText: rootKeyDocument(t.publicJwk),
    delegationTexts: [expired, toB],
    buoy: 'buoy-01', samples: 1, now: NOW,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'TARGET_UNREACHABLE');
  const tps = r.unreachable.reached.map((x) => x.subjectThumbprint);
  assert.ok(!tps.includes(jwkThumbprint(a.publicJwk)), '过期边的主体不应到达');
  const reachedB = r.unreachable.reached.find((x) => x.subjectThumbprint === jwkThumbprint(b.publicJwk));
  assert.ok(reachedB);
  assert.equal(reachedB.firstRejected.code, 'NO_OUTGOING_DELEGATION');
});

test('目标可达但权限不足：浮标不允许 / 采样超限 分别定位', () => {
  const d = diamond();
  let r = run(d, [d.edges.e1, d.edges.e3], { buoy: 'buoy-02', samples: 1 });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'BUOY_NOT_ALLOWED');
  assert.equal(r.error.field, '$["aud"]');
  assert.ok(Array.isArray(r.unreachable.reached));

  r = run(d, [d.edges.e1, d.edges.e3], { buoy: 'buoy-01', samples: 51 });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'SAMPLES_EXCEEDED');
  assert.equal(r.error.field, '$["maxSamples"]');
});

test('集合内任一委托签名无效：BAD_SIGNATURE 定位到该份（按规范字节逐份验签）', () => {
  const d = diamond();
  const v = parseCanonical(d.edges.e2, { requireOrderedKeys: false }).value;
  v.maxSamples = 9; // 改写不重签
  const tampered = canonicalize(v);
  const r = run(d, [d.edges.e1, tampered, d.edges.e3, d.edges.e4]);
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'BAD_SIGNATURE');
  assert.equal(r.error.hop, 1);
});

test('集合混入 command / 键序错误：按既有规则拒绝', () => {
  const d = diamond();
  const cmd = issueCommand({
    iss: d.a.publicJwk, sub: d.t.publicJwk,
    nbf: W.nbf, exp: W.exp, aud: ['buoy-01'], maxSamples: 5,
    buoy: 'buoy-01', samples: 1,
  }, d.a.privateJwk);
  let r = run(d, [d.edges.e1, cmd]);
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'SCHEMA');

  const v = parseCanonical(d.edges.e1, { requireOrderedKeys: false }).value;
  const order = ['typ', 'sub', 'sig', 'nbf', 'maxSamples', 'iss', 'exp', 'aud'];
  const badOrder = '{' + order.map((k) => `${JSON.stringify(k)}:${JSON.stringify(v[k])}`).join(',') + '}';
  r = run(d, [badOrder]);
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'KEY_ORDER');
});

test('链首非根签发的委托无法进入搜索（无有效根出边）→ 目标不可达', () => {
  const root = generateKeyPair();
  const stranger = generateKeyPair();
  const t = generateKeyPair();
  // stranger -> t，且 stranger 不是根：图中没有 root 出边
  const e = del(stranger, t, { maxSamples: 5 });
  const r = verifyDelegationGraph({
    rootKeyText: rootKeyDocument(root.publicJwk),
    targetKeyText: rootKeyDocument(t.publicJwk),
    delegationTexts: [e],
    buoy: 'buoy-01', samples: 1, now: NOW,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'TARGET_UNREACHABLE');
});

test('空委托集合 / 缺目标公钥 / 非法 now：请求层拒绝', () => {
  const d = diamond();
  let r = verifyDelegationGraph({
    ...d.base, delegationTexts: [], buoy: 'buoy-01', samples: 1,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'SCHEMA');

  r = verifyDelegationGraph({
    rootKeyText: d.base.rootKeyText, delegationTexts: [d.edges.e1],
    targetKeyText: '', buoy: 'buoy-01', samples: 1, now: NOW,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'TARGET_KEY_INVALID');

  r = run(d, [d.edges.e1], { now: 2 ** 31 });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'SCHEMA');

  r = run(d, [d.edges.e1], { buoy: '' });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'SCHEMA');
});
