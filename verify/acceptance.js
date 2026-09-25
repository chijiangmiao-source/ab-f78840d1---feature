#!/usr/bin/env node
'use strict';

// 一次性验收服务 verify：
//   1. 复核合法链的逐跳证据（每跳签名、规范载荷摘要、收紧约束、准许结论）；
//   2. 复核乱序委托集合授权求解（状态图 / 回环支配 / 稳定选路 / 不可达报告）；
//   3. 复核越权链的拒绝（浮标未获上游允许 / 采样量超限 / 约束放宽），定位跳与字段；
//   4. 复核篡改签名 / 改写载荷的拒绝（BAD_SIGNATURE）；
//   5. 复核结构性错误（重复键、键序不规范、不安全 / 越界整数、非有限数、链首非根公钥）；
//   6. 运行相关代码测试（node --test tests/）与页面构建检查；
//   7. 启动本机服务做健康地址 API/HTTP 冒烟；GATEWAY_URL 存在时再冒烟对端。
//
// 执行完毕即退出：0 全部通过，1 存在验收失败，2 执行异常。

import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { verifyChain } from '../src/chain.js';
import { authorizeSet } from '../src/graph.js';
import { canonicalize, parseCanonical } from '../src/canonical.js';
import {
  generateKeyPair,
  issueDelegation,
  issueCommand,
  rootKeyDocument,
  buildValidChain,
} from '../src/sign.js';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NOW = 1790000000;

let passed = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failures.push(`${name}${detail ? ` —— ${detail}` : ''}`);
    console.log(`  ✗ ${name}${detail ? ` —— ${detail}` : ''}`);
  }
}

function expectReject(name, input, code, hop = null, field = null) {
  const r = verifyChain(input);
  const good = !r.ok && r.error.code === code
    && (hop === null || r.error.hop === hop)
    && (field === null || r.error.field === field);
  check(`${name}（code=${code}${hop === null ? '' : `, hop=${hop}`}${field ? `, field=${field}` : ''}）`,
    good, good ? '' : `实际=${JSON.stringify(r.ok ? r.evidence.verdict : r.error)}`);
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// 用指定私钥对“值对象（含 sig 键）”重签，返回新的规范 JSON 文本
function resign(value, privateJwk) {
  const { sig: _sig, ...payload } = value;
  const key = crypto.createPrivateKey({ key: privateJwk, format: 'jwk' });
  const sigBuf = crypto.sign('sha256', Buffer.from(canonicalize(payload), 'utf8'),
    { key, dsaEncoding: 'ieee-p1363' });
  const sigB64 = sigBuf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return canonicalize({ ...payload, sig: sigB64 });
}

// ---------- 1) 合法链逐跳证据 ----------
function sectionValidChain() {
  console.log('\n[1/7] 合法链逐跳证据复核');
  const root = generateKeyPair();
  const a = generateKeyPair();
  const b = generateKeyPair();
  const d1 = issueDelegation({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600,
    aud: ['buoy-01', 'buoy-02', 'buoy-03'], maxSamples: 200,
  }, root.privateJwk);
  const d2 = issueDelegation({
    iss: a.publicJwk, sub: b.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800,
    aud: ['buoy-01', 'buoy-02'], maxSamples: 80,
  }, a.privateJwk);
  const cmd = issueCommand({
    iss: b.publicJwk, sub: b.publicJwk,
    nbf: NOW - 600, exp: NOW + 600,
    aud: ['buoy-01'], maxSamples: 50,
    buoy: 'buoy-01', samples: 40,
  }, b.privateJwk);
  const input = { rootKeyText: rootKeyDocument(root.publicJwk), objectTexts: [d1, d2, cmd], now: NOW };
  const r = verifyChain(input);
  check('合法三跳链准许', r.ok, !r.ok ? JSON.stringify(r.error) : '');
  if (!r.ok) return;

  const e = r.evidence;
  check('证据含 3 跳', e.hops.length === 3);
  check('链首签发者指纹等于根公钥指纹', e.hops[0].issThumbprint === e.rootKeyThumbprint);
  check('每跳签名非空且为 64 字节 P1363 的 base64url（86 字符）',
    e.hops.every((h) => /^[A-Za-z0-9_-]{86}$/.test(h.signature)));
  check('每跳规范载荷摘要为 64 位十六进制',
    e.hops.every((h) => /^[0-9a-f]{64}$/.test(h.payloadDigest)));

  // 独立复算每跳摘要（不依赖 verifyChain 内部）
  let digestOk = true;
  for (let i = 0; i < 3; i++) {
    const parsed = parseCanonical(input.objectTexts[i]);
    const { sig: _s, ...payload } = parsed.value;
    const want = sha256Hex(Buffer.from(canonicalize(payload), 'utf8'));
    if (want !== e.hops[i].payloadDigest) digestOk = false;
  }
  check('每跳规范载荷摘要可由规范字节独立复算', digestOk);

  check('收紧后浮标集合为交集 [buoy-01]', JSON.stringify(e.finalConstraints.aud) === '["buoy-01"]');
  check('收紧后时间窗为各跳交集 [NOW-600, NOW+600]',
    e.finalConstraints.nbf === NOW - 600 && e.finalConstraints.exp === NOW + 600);
  check('收紧后采样上限为最小值 50', e.finalConstraints.maxSamples === 50);
  check('最终准许结论携带浮标与采样量',
    e.verdict.allow === true && e.verdict.buoy === 'buoy-01' && e.verdict.samples === 40);
}

// ---------- 2) 乱序委托集合授权（状态图 / 回环 / 支配 / 稳定选路 / 不可达） ----------
function digestOfText(text) {
  const { sig: _s, ...payload } = parseCanonical(text).value;
  return sha256Hex(Buffer.from(canonicalize(payload), 'utf8'));
}

function sectionSetAuthorization() {
  console.log('\n[2/7] 乱序委托集合授权求解复核');
  const root = generateKeyPair();
  const a = generateKeyPair();
  const b = generateKeyPair();
  const t = generateKeyPair();
  const rootKeyText = rootKeyDocument(root.publicJwk);
  const targetKeyText = rootKeyDocument(t.publicJwk);

  // 两条可行路径：root->a->t（宽，仅 buoy-01）与 root->b->t（窄，含 buoy-02）；
  // 另有回环 a->b、b->a 与一份篡改委托。
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
  const tampered = (() => {
    const v = parseCanonical(dRb, { requireOrderedKeys: false }).value;
    v.maxSamples = 999; // 改写已签名内容但不重签
    return canonicalize(v);
  })();

  const ask = (objects, buoy, samples, target = targetKeyText) => authorizeSet({
    rootKeyText, objectTexts: objects, targetKeyText: target, buoy, samples, now: NOW,
  });

  // 2a. 乱序 + 回环 + 篡改委托共存：buoy-02/10 只能经 root->b->t（2 跳）
  const objects = [dBa, tampered, dBt, dAb, dAt, dRb, dRa];
  const r1 = ask(objects, 'buoy-02', 10);
  check('乱序集合含回环与篡改委托：命中 root->b->t 两跳路径',
    r1.ok && r1.evidence.hops.length === 2
    && r1.evidence.pathDigests[0] === digestOfText(dRb)
    && r1.evidence.pathDigests[1] === digestOfText(dBt),
    r1.ok ? '' : JSON.stringify(r1.error));
  if (r1.ok) {
    check('路径逐跳收紧证据：末端有效约束 = 最后一跳委托约束',
      JSON.stringify(r1.evidence.finalConstraints)
      === JSON.stringify(r1.evidence.hops[1].tightened));
    check('证据携带目标主体指纹与准许结论',
      r1.evidence.targetThumbprint.length === 64
      && r1.evidence.verdict.allow === true && r1.evidence.verdict.buoy === 'buoy-02');
  }

  // 2b. 确定性：相同集合与查询条件、不同粘贴顺序 → 同一条证据路径
  const shuffled = [dRa, dRb, dAt, dBt, dAb, dBa, tampered];
  const r2 = ask(shuffled, 'buoy-02', 10);
  check('重复核验与粘贴顺序无关：同一证据路径',
    r2.ok && JSON.stringify(r2.evidence) === JSON.stringify(r1.evidence));

  // 2c. 同跳数按规范载荷摘要序列字典序选路（buoy-01/10 有两条 2 跳路径）
  const r3 = ask([dAt, dBt, dRb, dRa], 'buoy-01', 10);
  const pA = [digestOfText(dRa), digestOfText(dAt)];
  const pB = [digestOfText(dRb), digestOfText(dBt)];
  const want = JSON.stringify(pA) <= JSON.stringify(pB) ? pA : pB;
  check('同跳数按摘要序列稳定选路',
    r3.ok && JSON.stringify(r3.evidence.pathDigests) === JSON.stringify(want),
    r3.ok ? `实际=${JSON.stringify(r3.evidence.pathDigests)}` : JSON.stringify(r3.error));

  // 2d. 支配：到达同一主体的较窄状态不能替代较宽状态接续委托
  //     （root->b->t 上限 10；请求 50 次只能经 root->a->t 上限 80）
  const r4 = ask([dRa, dAt, dRb, dBt], 'buoy-01', 50);
  check('采样量 50 越过窄路径上限：选中 root->a->t（宽状态可接续）',
    r4.ok && r4.evidence.pathDigests[0] === digestOfText(dRa)
    && r4.evidence.pathDigests[1] === digestOfText(dAt),
    r4.ok ? '' : JSON.stringify(r4.error));

  // 2e. 目标不可达：报告已到达主体与最先被拒委托及限制字段
  const orphan = generateKeyPair();
  const r5 = ask([dRa, dAt, tampered], 'buoy-01', 10, rootKeyDocument(orphan.publicJwk));
  check('目标不可达 → NO_AUTHORIZING_PATH',
    !r5.ok && r5.error.code === 'NO_AUTHORIZING_PATH');
  if (!r5.ok && r5.reachability) {
    check('不可达报告含已到达主体（根 0 跳起）',
      r5.reachability.reached.length >= 2
      && r5.reachability.reached[0].hops === 0
      && r5.reachability.reached[0].constraints === null);
    check('篡改委托列入最先被拒（BAD_SIGNATURE，字段 $["sig"]）',
      r5.reachability.rejections.some((x) => x.code === 'BAD_SIGNATURE'
        && x.field === '$["sig"]' && x.payloadDigest === digestOfText(tampered)));
  }

  // 2f. 过期委托列入被拒并定位限制字段
  const dOld = issueDelegation({
    iss: root.publicJwk, sub: t.publicJwk,
    nbf: NOW - 5000, exp: NOW - 4000, aud: ['buoy-01'], maxSamples: 100,
  }, root.privateJwk);
  const r6 = ask([dOld], 'buoy-01', 1);
  check('过期委托不可达且列入被拒（TIME_EXPIRED，字段 $["exp"]）',
    !r6.ok && r6.error.code === 'NO_AUTHORIZING_PATH'
    && r6.reachability.rejections.length === 1
    && r6.reachability.rejections[0].code === 'TIME_EXPIRED'
    && r6.reachability.rejections[0].field === '$["exp"]');

  // 2g. 集合中混入 command / 非规范文本 → 与链式核验同形的输入错误
  const r7 = ask(['{"typ":"delegation","aud":["x"]}'], 'buoy-01', 1);
  check('非规范委托文本被拒绝并定位（KEY_ORDER, hop=0）',
    !r7.ok && r7.error.code === 'KEY_ORDER' && r7.error.hop === 0);
}


// ---------- 3) 越权链 ----------
function sectionOverPrivileged() {
  console.log('\n[3/7] 越权链拒绝复核');

  // 3a. 末端浮标未获上游允许（第 0 跳允许 buoy-01/02，末端命令仅允许 buoy-01，
  //     命令请求 buoy-02 → 首个限制跳为末端 hop=1）
  let c = buildValidChain({ now: NOW, buoys: ['buoy-01', 'buoy-02'], maxSamples: 100, samples: 5 });
  let v = parseCanonical(c.objectTexts[1], { requireOrderedKeys: false }).value;
  v.buoy = 'buoy-02';
  c.objectTexts[1] = resign(v, c.mid.privateJwk);
  expectReject('末端浮标未获全部上游允许', c, 'BUOY_NOT_ALLOWED', 1, '$["aud"]');

  // 3b. 采样量超过最严上限（命令上限 50，请求 51）
  c = buildValidChain({ now: NOW });
  v = parseCanonical(c.objectTexts[1], { requireOrderedKeys: false }).value;
  v.samples = 51;
  c.objectTexts[1] = resign(v, c.mid.privateJwk);
  expectReject('采样量超过任一跳上限', c, 'SAMPLES_EXCEEDED', 1, '$["maxSamples"]');

  // 3c. 中间委托放宽浮标集合
  c = buildValidChain({ now: NOW, buoys: ['buoy-01'] });
  const widened = issueDelegation({
    iss: c.mid.publicJwk, sub: c.mid.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800,
    aud: ['buoy-01', 'intruder-buoy'], maxSamples: 50,
  }, c.mid.privateJwk);
  c.objectTexts.splice(1, 0, widened);
  expectReject('浮标集合被放宽', c, 'NOT_TIGHTENED', 1, '$["aud"]');

  // 3d. 时间窗放宽（exp 延后）
  const root = generateKeyPair();
  const a = generateKeyPair();
  const d1 = issueDelegation({
    iss: root.publicJwk, sub: a.publicJwk,
    nbf: NOW - 100, exp: NOW + 100, aud: ['x'], maxSamples: 5,
  }, root.privateJwk);
  const cmdLate = issueCommand({
    iss: a.publicJwk, sub: a.publicJwk,
    nbf: NOW - 100, exp: NOW + 200, aud: ['x'], maxSamples: 5,
    buoy: 'x', samples: 1,
  }, a.privateJwk);
  expectReject('有效期被放宽', {
    rootKeyText: rootKeyDocument(root.publicJwk), objectTexts: [d1, cmdLate], now: NOW,
  }, 'NOT_TIGHTENED', 1, '$["exp"]');

  // 3e. 链首签发者不是所粘贴根公钥
  c = buildValidChain({ now: NOW });
  c.rootKeyText = rootKeyDocument(generateKeyPair().publicJwk);
  expectReject('链首签发者不等于根公钥', c, 'ISSUER_NOT_ROOT', 0, '$["iss"]');

  // 3f. 委托并非前一主体签发（iss 与签名密钥同时被替换）
  const root2 = generateKeyPair();
  const good = generateKeyPair();
  const mallory = generateKeyPair();
  const dd1 = issueDelegation({
    iss: root2.publicJwk, sub: good.publicJwk,
    nbf: NOW - 3600, exp: NOW + 3600, aud: ['x'], maxSamples: 10,
  }, root2.privateJwk);
  const dd2 = issueDelegation({
    iss: mallory.publicJwk, sub: good.publicJwk,
    nbf: NOW - 1800, exp: NOW + 1800, aud: ['x'], maxSamples: 10,
  }, mallory.privateJwk);
  const cc = issueCommand({
    iss: good.publicJwk, sub: good.publicJwk,
    nbf: NOW - 10, exp: NOW + 100, aud: ['x'], maxSamples: 10,
    buoy: 'x', samples: 1,
  }, good.privateJwk);
  expectReject('委托非前一主体签发', {
    rootKeyText: rootKeyDocument(root2.publicJwk), objectTexts: [dd1, dd2, cc], now: NOW,
  }, 'ISSUER_MISMATCH', 1, '$["iss"]');
}

// ---------- 4) 篡改签名 / 改写载荷 ----------
function sectionTamper() {
  console.log('\n[4/7] 篡改签名与改写载荷拒绝复核');

  let c = buildValidChain({ now: NOW });
  let v = parseCanonical(c.objectTexts[0], { requireOrderedKeys: false }).value;
  v.maxSamples = 200; // 改写已签名内容但不重签
  c.objectTexts[0] = canonicalize(v);
  expectReject('已签名委托内容被改写', c, 'BAD_SIGNATURE', 0, '$["sig"]');

  c = buildValidChain({ now: NOW });
  v = parseCanonical(c.objectTexts[1], { requireOrderedKeys: false }).value;
  v.samples = 49; // 命令内容被改写
  c.objectTexts[1] = canonicalize(v);
  expectReject('已签名命令内容被改写', c, 'BAD_SIGNATURE', 1, '$["sig"]');

  c = buildValidChain({ now: NOW });
  v = parseCanonical(c.objectTexts[0], { requireOrderedKeys: false }).value;
  const sigBuf = Buffer.from(v.sig.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  sigBuf[0] ^= 0x01; // 翻转签名 r 的首字节
  v.sig = sigBuf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  c.objectTexts[0] = canonicalize(v);
  expectReject('签名字段被直接篡改', c, 'BAD_SIGNATURE', 0);
}

// ---------- 5) 结构性 / 数值错误 ----------
function sectionStructural() {
  console.log('\n[5/7] 结构性与数值错误定位复核');
  const cases = [
    { name: '重复键', code: 'DUPLICATE_KEY',
      mutate: (t) => t.replace('"maxSamples":100', '"maxSamples":100,"maxSamples":9') },
    { name: '对象键序不规范', code: 'KEY_ORDER', mutate: (t) => {
      const v = parseCanonical(t, { requireOrderedKeys: false }).value;
      const order = ['typ', 'sub', 'sig', 'nbf', 'maxSamples', 'iss', 'exp', 'aud'];
      return '{' + order.map((k) => `${JSON.stringify(k)}:${JSON.stringify(v[k])}`).join(',') + '}';
    } },
    { name: '越界整数（> int32）', code: 'NUMBER_OUT_OF_RANGE',
      mutate: (t) => t.replace('"maxSamples":100', '"maxSamples":2147483648') },
    { name: '不安全整数（精度丢失）', code: 'NUMBER_UNSAFE_INTEGER',
      mutate: (t) => t.replace('"maxSamples":100', '"maxSamples":9007199254740993') },
    { name: '非有限数（1e999）', code: 'NUMBER_NON_FINITE',
      mutate: (t) => t.replace('"maxSamples":100', '"maxSamples":1e999') },
    { name: '小数字面量用于整数字段', code: 'NUMBER_NOT_INTEGER',
      mutate: (t) => t.replace('"maxSamples":100', '"maxSamples":12.5') },
  ];
  for (const tc of cases) {
    const c = buildValidChain({ now: NOW });
    c.objectTexts[0] = tc.mutate(c.objectTexts[0]);
    const r = verifyChain(c);
    const good = !r.ok && r.error.code === tc.code && r.error.hop === 0 && r.error.line !== null;
    check(`${tc.name} → ${tc.code}（hop=0，定位 行:列=${r.ok ? '-' : `${r.error.line}:${r.error.col}`}）`,
      good, r.ok ? '意外通过' : `实际 code=${r.error.code}`);
  }
}

// ---------- 6) 代码测试 / 页面检查 ----------
function run(cmd, args, timeoutMs = 120000) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd: rootDir, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    const timer = setTimeout(() => {
      err += `\n[verify] 子进程超过 ${timeoutMs}ms 未退出，已终止`;
      child.kill('SIGKILL');
    }, timeoutMs);
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code === null ? 1 : code, out, err });
    });
  });
}

async function sectionTestsAndPage() {
  console.log('\n[6/7] 代码测试与页面构建检查');
  const t = await run(process.execPath, ['--test', '--test-concurrency=2', 'tests/']);
  const testCount = (t.out.match(/# tests (\d+)/) || [])[1];
  const passCount = (t.out.match(/# pass (\d+)/) || [])[1];
  check(`相关代码测试全部通过（tests=${testCount}, pass=${passCount}）`,
    t.code === 0, t.code === 0 ? '' : (t.out + t.err).split('\n').slice(-30).join('\n'));

  const pg = await run(process.execPath, ['scripts/check-page.js']);
  check('页面构建检查通过', pg.code === 0, pg.code === 0 ? '' : (pg.out + pg.err).trim());
}

// ---------- 7) HTTP 冒烟 ----------
function httpRequest(method, urlPath, { port, host = '127.0.0.1', body, baseUrl } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlPath, baseUrl || `http://${host}:${port}`);
    const data = body ? Buffer.from(body) : null;
    const req = http.request({
      hostname: u.hostname, port: u.port || (new URL(baseUrl || 'http://x')).port || 80,
      path: u.pathname, method,
      headers: data ? { 'content-type': 'application/json', 'content-length': data.length } : {},
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function waitForHealth(port, tries = 60) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await httpRequest('GET', '/health', { port });
      if (r.status === 200) return true;
    } catch { /* 尚未就绪 */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}

async function smokeGateway(label, target) {
  console.log(`\n[7/7] 健康地址 API/HTTP 冒烟（${label}）`);

  const health = await httpRequest('GET', '/health', target);
  const healthJson = JSON.parse(health.body);
  check('GET /health → 200 且 status=ok',
    health.status === 200 && healthJson.status === 'ok', `status=${health.status}`);

  const home = await httpRequest('GET', '/', target);
  check('GET / → 200 且返回静态核验页面',
    home.status === 200 && home.body.includes('受限委托链核验'));

  const valid = buildValidChain({ now: Math.floor(Date.now() / 1000) });
  const okResp = await httpRequest('POST', '/api/verify', {
    ...target,
    body: JSON.stringify({ rootKey: valid.rootKeyText, objects: valid.objectTexts, now: valid.now }),
  });
  const okJson = JSON.parse(okResp.body);
  check('POST /api/verify 合法链 → 200，含逐跳证据与准许结论',
    okResp.status === 200 && okJson.ok === true
    && Array.isArray(okJson.evidence?.hops) && okJson.evidence.verdict.allow === true,
    `status=${okResp.status}`);

  const expired = buildValidChain({ now: NOW });
  const expResp = await httpRequest('POST', '/api/verify', {
    ...target,
    body: JSON.stringify({ rootKey: expired.rootKeyText, objects: expired.objectTexts, now: NOW + 100000 }),
  });
  const expJson = JSON.parse(expResp.body);
  check('POST /api/verify 失效链 → 422 TIME_EXPIRED 且定位到跳',
    expResp.status === 422 && expJson.ok === false
    && expJson.error.code === 'TIME_EXPIRED' && expJson.error.hop !== null,
    `status=${expResp.status}`);

  const tampered = buildValidChain({ now: Math.floor(Date.now() / 1000) });
  const pv = parseCanonical(tampered.objectTexts[0], { requireOrderedKeys: false }).value;
  pv.maxSamples += 1;
  tampered.objectTexts[0] = canonicalize(pv);
  const badResp = await httpRequest('POST', '/api/verify', {
    ...target,
    body: JSON.stringify({ rootKey: tampered.rootKeyText, objects: tampered.objectTexts }),
  });
  const badJson = JSON.parse(badResp.body);
  check('POST /api/verify 篡改已签名内容 → 422 BAD_SIGNATURE（hop=0）',
    badResp.status === 422 && badJson.ok === false
    && badJson.error.code === 'BAD_SIGNATURE' && badJson.error.hop === 0,
    `status=${badResp.status}`);

  const dup = buildValidChain({ now: Math.floor(Date.now() / 1000) });
  dup.objectTexts[0] = dup.objectTexts[0].replace('"maxSamples":100', '"maxSamples":100,"maxSamples":9');
  const dupResp = await httpRequest('POST', '/api/verify', {
    ...target,
    body: JSON.stringify({ rootKey: dup.rootKeyText, objects: dup.objectTexts }),
  });
  const dupJson = JSON.parse(dupResp.body);
  check('POST /api/verify 重复键 → 422 DUPLICATE_KEY 且带行列定位',
    dupResp.status === 422 && dupJson.error?.code === 'DUPLICATE_KEY' && dupJson.error.line != null,
    `status=${dupResp.status}`);

  const badReq = await httpRequest('POST', '/api/verify', { ...target, body: 'not-json' });
  check('POST /api/verify 非法请求体 → 400 BAD_REQUEST', badReq.status === 400);

  // ---- 乱序委托集合授权求解冒烟 ----
  const t0 = Math.floor(Date.now() / 1000);
  const sRoot = generateKeyPair();
  const sA = generateKeyPair();
  const sB = generateKeyPair();
  const sT = generateKeyPair();
  const sdRa = issueDelegation({
    iss: sRoot.publicJwk, sub: sA.publicJwk,
    nbf: t0 - 3600, exp: t0 + 3600, aud: ['buoy-01', 'buoy-02'], maxSamples: 100,
  }, sRoot.privateJwk);
  const sdAt = issueDelegation({
    iss: sA.publicJwk, sub: sT.publicJwk,
    nbf: t0 - 1800, exp: t0 + 1800, aud: ['buoy-01'], maxSamples: 80,
  }, sA.privateJwk);
  const sdRb = issueDelegation({
    iss: sRoot.publicJwk, sub: sB.publicJwk,
    nbf: t0 - 3600, exp: t0 + 3600, aud: ['buoy-01'], maxSamples: 100,
  }, sRoot.privateJwk);
  const sdBa = issueDelegation({ // 回环：b -> a
    iss: sB.publicJwk, sub: sA.publicJwk,
    nbf: t0 - 900, exp: t0 + 900, aud: ['buoy-01'], maxSamples: 40,
  }, sB.privateJwk);
  const authBody = {
    rootKey: rootKeyDocument(sRoot.publicJwk),
    objects: [sdBa, sdAt, sdRb, sdRa], // 乱序，含回环
    targetKey: rootKeyDocument(sT.publicJwk),
    buoy: 'buoy-01', samples: 10, now: t0,
  };
  const authResp = await httpRequest('POST', '/api/authorize', {
    ...target, body: JSON.stringify(authBody),
  });
  const authJson = JSON.parse(authResp.body);
  check('POST /api/authorize 乱序集合（含回环）→ 200，两跳路径与准许结论',
    authResp.status === 200 && authJson.ok === true
    && authJson.evidence.hops.length === 2 && authJson.evidence.verdict.allow === true,
    `status=${authResp.status}`);

  const authResp2 = await httpRequest('POST', '/api/authorize', {
    ...target,
    body: JSON.stringify({ ...authBody, objects: [sdRa, sdRb, sdAt, sdBa] }), // 换个粘贴顺序
  });
  const authJson2 = JSON.parse(authResp2.body);
  check('POST /api/authorize 重复核验（换序）→ 同一证据路径',
    authResp2.status === 200
    && JSON.stringify(authJson2.evidence?.pathDigests) === JSON.stringify(authJson.evidence?.pathDigests),
    `status=${authResp2.status}`);

  const orphan = generateKeyPair();
  const unResp = await httpRequest('POST', '/api/authorize', {
    ...target,
    body: JSON.stringify({ ...authBody, targetKey: rootKeyDocument(orphan.publicJwk) }),
  });
  const unJson = JSON.parse(unResp.body);
  check('POST /api/authorize 目标不可达 → 422 NO_AUTHORIZING_PATH 且含已到达主体与被拒委托',
    unResp.status === 422 && unJson.ok === false
    && unJson.error.code === 'NO_AUTHORIZING_PATH'
    && Array.isArray(unJson.reachability?.reached) && unJson.reachability.reached.length >= 1
    && Array.isArray(unJson.reachability?.rejections),
    `status=${unResp.status}`);

  const badAuth = await httpRequest('POST', '/api/authorize', { ...target, body: 'not-json' });
  check('POST /api/authorize 非法请求体 → 400 BAD_REQUEST', badAuth.status === 400);
}

async function main() {
  console.log('=== verify：受限委托链复核一次性验收 ===');
  sectionValidChain();
  sectionSetAuthorization();
  sectionOverPrivileged();
  sectionTamper();
  sectionStructural();
  await sectionTestsAndPage();

  const port = Number(process.env.VERIFY_PORT || 18080);
  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: rootDir,
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  child.stdout.on('data', (d) => { serverLog += d; });
  child.stderr.on('data', (d) => { serverLog += d; });

  let exitCode = 0;
  try {
    const ready = await waitForHealth(port);
    check('验收用临时网关健康就绪', ready, ready ? '' : serverLog.trim());
    if (ready) await smokeGateway('本机临时实例', { port });
    if (process.env.GATEWAY_URL) {
      await smokeGateway(`对端 ${process.env.GATEWAY_URL}`, { port: 0, baseUrl: process.env.GATEWAY_URL });
    }
  } catch (e) {
    failures.push(`HTTP 冒烟异常：${e.stack || e.message}`);
  } finally {
    child.kill('SIGTERM');
    await new Promise((r) => child.on('exit', r));
  }

  console.log('\n=== 验收汇总 ===');
  console.log(`通过 ${passed} 项，失败 ${failures.length} 项`);
  if (failures.length) {
    console.log('失败项：');
    for (const f of failures) console.log(`  - ${f}`);
    exitCode = 1;
  } else {
    console.log('委托链复核验收全部通过 ✅');
  }
  process.exit(exitCode);
}

main().catch((e) => {
  console.error('验收执行异常：', e);
  process.exit(2);
});
