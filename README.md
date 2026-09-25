# 浮标失联应急采样 · 受限委托核验岸站

海洋观测浮标失联时，岸站携带**离线签发的受限委托**下发应急采样命令。本服务提供两种核验：

- **委托图核验（乱序集合）**：值班员粘贴「根公钥 + 一批乱序缓存的委托 + 目标主体公钥 +
  浮标 + 采样量 + 评估时刻」，在**收紧约束单调传播的授权状态图**中搜索该主体能否经
  **任意合法委托路径**取得这项权限；
- **单链核验（旧接口，行为保持兼容）**：粘贴「根公钥 + 按顺序排列的委托 / 末端命令」，
  按**同一套规范 JSON 字节**（JCS，RFC 8785）逐跳验签。

两种核验都确认时间窗、浮标集合、采样上限只允许收紧；对成功展示逐跳证据与准许结论，
对违规给出可定位的拒绝原因。

## 快速开始

### Docker Compose（推荐）

```bash
# 启动静态页面与健康端点（宿主机端口可配置，默认 8080）
docker compose up -d gateway
GATEWAY_PORT=9090 docker compose up -d gateway   # 自定义宿主机端口

curl http://127.0.0.1:8080/health          # {"status":"ok",...}
open  http://127.0.0.1:8080/               # 值班员页面（图核验 / 单链核验两种模式）

# 一次性验收服务（名为 verify）：复核证据/拒绝、乱序委托与回环、跑测试、
# 页面检查、健康冒烟，执行完毕即退出，退出码即验收结果
docker compose run --rm verify; echo "exit=$?"
```

### 本机（Node ≥ 20，零第三方依赖）

```bash
npm start                 # 启动网关（PORT 环境变量可改端口，默认 8080）
npm test                  # 相关代码测试
npm run check:page        # 页面构建检查
./bin/verify              # 一次性验收服务（退出码报告结果）
```

## 链对象格式（每份均为规范 JSON，键按 JCS 顺序）

```json
{"aud":["buoy-01"],"exp":1790003600,"iss":{"crv":"P-256","kty":"EC","x":"…","y":"…"},"maxSamples":50,"nbf":1789996400,"sig":"…","sub":{"crv":"P-256","kty":"EC","x":"…","y":"…"},"typ":"delegation"}
```

| 字段 | 含义 |
| --- | --- |
| `iss` / `sub` | 签发者 / 主体的 P-256 JWK（`crv,kty,x,y`，base64url 无填充） |
| `nbf` / `exp` | 有效期（unix 秒，int32 区间整数，nbf < exp） |
| `aud` | 允许浮标集合（非空字符串数组，元素唯一） |
| `maxSamples` | 采样上限（int32 区间整数，≥0） |
| `sig` | 对「去掉 `sig` 后的规范 JSON 字节」的 ECDSA P-256/SHA-256 签名（P1363 `r‖s`，base64url 无填充） |
| `typ` | `delegation`（委托）或 `command`（末端命令，仅允许在链末） |
| `buoy` / `samples` | 仅末端命令：目标浮标 / 请求采样量（≥1） |

## 链规则

1. 链首 `iss` 必须等于所粘贴的根公钥；其后每跳 `iss` 必须等于上一跳 `sub`；
2. 每跳仅允许收紧：`nbf` 不提前、`exp` 不延后、`aud` 为上一跳子集、`maxSamples` 不大于上一跳；
3. 评估时刻须落在每跳时间窗内；
4. 末端 `buoy` 须获**全部**上游 `aud` 允许，`samples` 不超过**任一** `maxSamples`；
5. 任一失败即拒绝，并定位**首个限制字段或签名失败跳**。

## 授权状态图核验（乱序委托集合）

值班员收到的是一批**乱序缓存**的离线委托，不再是排好序的单链。核验把每份委托视为
有向图的一条边 `iss → sub`，在「收紧约束单调传播」的状态图中搜索：

- **状态不只按主体名称合并**：到达同一主体的不同路径，其有效时间窗、允许浮标集、
  采样上限可能不同，后续能接续的委托也不同。因此每个主体保留一张**互不支配的约束
  状态前沿**（同一主体可同时存在多个不可比较的状态）。
- **单调收紧与支配**：沿任意路径 `nbf` 不降、`exp` 不升、`aud` 缩小、`maxSamples`
  不增。状态 A 支配状态 B ⇔ A 的四项约束逐项宽于或等于 B（时间窗包含、浮标集为超集、
  上限不更小）**且跳数不更多**；被支配的较窄状态不可能到达更宽状态到不了的地方，安全
  剪枝。约束全等时取跳数最少者，再按规范载荷摘要序列决胜。
- **精确处理回环**：沿环约束单调收紧——至少一项严格收紧则产生新的更窄状态（可接续
  不同下游），全等则被支配/决胜剪枝使环终止。各分量取自有限的委托字段取值，配合最大
  路径跳数（16），工作集必然收敛。
- **成功路径稳定展示**：在所有可达的目标主体状态中选出满足「浮标获允许、采样量不超限」
  者，按**跳数**、再按**规范载荷摘要序列**确定**唯一**路径；输出逐跳签名、规范载荷
  摘要与逐跳收紧证据。相同委托集合与查询条件重复核验，必得到同一条证据路径，与粘贴
  顺序无关（完全相同的委托文本自动去重）。
- **目标不可达**：返回已到达主体，以及从该主体出发、在其全部到达状态下都**最先被拒的
  委托与限制字段**（无出边时给 `NO_OUTGOING_DELEGATION`）。目标虽可达但这项权限不足时，
  仍返回 `BUOY_NOT_ALLOWED` / `SAMPLES_EXCEEDED` 并附同样的到达诊断。

每份委托仍以**既有规范 JSON 字节逐份解析、模式校验、用其 `iss` 公钥逐份验签**；集合中
任一委托签名或字节无效即整体拒绝并定位到该份（`hop` 为其在粘贴集合中的序号）。
委托图集合只接受 `typ:"delegation"`；含 `command` 末端的核验请用旧的单链接口。

## 错误定位（`hop` = 跳号，`-1` = 根公钥；附行/列）

| code | 含义 |
| --- | --- |
| `DUPLICATE_KEY` | 重复键 |
| `KEY_ORDER` | 对象键序不规范（未按 JCS 排序） |
| `NUMBER_NON_FINITE` | 非有限数（如 `1e999`） |
| `NUMBER_UNSAFE_INTEGER` | 不安全整数（超出 ±(2^53−1)，精度丢失） |
| `NUMBER_OUT_OF_RANGE` | 越界整数（超出字段允许区间） |
| `NUMBER_NOT_INTEGER` | 整数字段出现小数/指数 |
| `ISSUER_NOT_ROOT` | 链首签发者 ≠ 根公钥 |
| `ISSUER_MISMATCH` | 委托并非前一主体签发 |
| `NOT_TIGHTENED` | 时间窗/浮标集合/采样上限被放宽（`field` 指出首个违规字段） |
| `TIME_NOT_YET_VALID` / `TIME_EXPIRED` | 未生效 / 已过期 |
| `BAD_SIGNATURE` | 签名与规范载荷摘要不符（内容或签名被改写） |
| `BUOY_NOT_ALLOWED` | 末端浮标未获某上游允许（图核验中表示目标可达但该浮标不被最宽到达状态允许） |
| `SAMPLES_EXCEEDED` | 采样量超过某跳上限（图核验中表示目标可达但请求量超过最宽到达状态上限） |
| `TARGET_UNREACHABLE` | 委托图：目标主体经任何合法路径都不可达（附已到达主体诊断） |
| `NO_OUTGOING_DELEGATION` | 委托图诊断码：该已到达主体未签发任何委托（并非完整错误码，仅出现在 `unreachable.reached[].firstRejected` 中） |
| `TARGET_KEY_INVALID` | 目标主体公钥为空 / 过大 / 非法 JWK |
| `SCHEMA` / `JSON_SYNTAX` / `JSON_TRAILING` | 模式或语法错误 |

## API

- `GET /health` → `{"status":"ok",...}`
- `GET /` → 值班员静态页面（含「委托图核验 / 单链核验」两种模式）
- `POST /api/verify`（**旧单链接口，保持兼容**），请求体
  `{"rootKey":"<规范JSON>","objects":["<规范JSON>",…],"now":1790000000?}`
  - 成功：`200 {"ok":true,"evidence":{hops:[{index,typ,signature,payloadDigest,tightened,…}],finalConstraints,verdict}}`
  - 拒绝：`422 {"ok":false,"error":{code,hop,field,message,line,col}}`
- `POST /api/verify-graph`（**乱序委托集合的授权图搜索**），请求体
  `{"rootKey":"<规范JSON>","delegations":["<delegation规范JSON>",…],`
  `"targetKey":"<规范JSON>","buoy":"buoy-01","samples":10,"now":1790000000?}`
  - 成功：`200 {"ok":true,"evidence":{now,rootKeyThumbprint,targetThumbprint,hops,finalConstraints,verdict}}`
    —— `hops[]` 为按跳数/摘要决胜选出的唯一路径，每项含 `signature`、`payloadDigest`、
    `iss/subThumbprint`、`tightened`（逐跳收紧后的 `{nbf,exp,aud,maxSamples}`）。
  - 权限不足：`422` 的 `error.code` 为 `BUOY_NOT_ALLOWED` / `SAMPLES_EXCEEDED`；
  - 不可达：`422`
    ```json
    {"ok":false,"error":{"code":"TARGET_UNREACHABLE",...},
     "unreachable":{"targetThumbprint":"…",
       "reached":[{"subjectThumbprint":"…","hops":1,
         "firstRejected":{"code":"NOT_TIGHTENED","field":"$[\"exp\"]",
           "message":"…","delegationDigest":"…","delegationIndex":0}}]}}
    ```
    `reached[]` 按「到达跳数 → 主体指纹」稳定排序；无出边主体的 `firstRejected.code`
    为 `NO_OUTGOING_DELEGATION`。

页面行为：**错误草稿不覆盖上一份有效证据**——本次核验被拒绝时，上一份有效
证据仍保留展示（标注「上一份有效证据」），仅当新的核验通过时才更新；两种模式各自留存。

## 一次性验收服务 `verify`

`docker compose run --rm verify`（或本机 `./bin/verify`）依次执行：

1. 复核合法链逐跳证据（签名、规范载荷摘要独立复算、收紧约束、准许结论）；
2. 复核越权链拒绝（浮标越权、采样超限、集合/时间窗放宽、链首非根、非前一主体签发）；
3. 复核篡改签名 / 改写载荷的拒绝（`BAD_SIGNATURE`）；
4. 复核结构性与数值错误定位（重复键、键序、不安全/越界整数、非有限数等）；
5. 复核**乱序委托集合的授权图**：最短可行路径选择、粘贴顺序/重复行无关的确定性、
   支配剪枝、回环收紧与全等环终止、不可达诊断、浮标/采样权限不足、集合内坏签名定位；
6. 运行相关代码测试（`node --test`）与页面构建检查；
7. 启动临时网关做健康地址 API/HTTP 冒烟，含 `/api/verify-graph` 换序一致性与不可达诊断
   （`GATEWAY_URL` 存在时再冒烟对端）。

执行完毕即退出：退出码 `0` 全部通过，`1` 存在失败项，`2` 执行异常。

## 目录

```
src/canonical.js   严格规范 JSON（JCS）解析/序列化、整数边界判定
src/chain.js       单链逐跳核验（旧接口，验签/签发关系/收紧/时效/末端检查）+ 共享校验
src/graph.js       乱序委托集合的授权状态图搜索（多状态前沿、支配剪枝、回环、稳定选路）
src/sign.js        离线签发辅助（测试与验收复现完整链路）
src/server.js      零依赖 HTTP 服务（静态页面 /health /api/verify /api/verify-graph）
public/            值班员页面（图/链双模、证据留存、错误草稿独立展示、不可达诊断）
tests/             单元测试（node:test）
scripts/check-page.js  页面构建检查
verify/acceptance.js   一次性验收服务入口
bin/verify             本机可执行验收入口
compose.yaml           gateway（可配置宿主机端口）+ verify（一次性验收）
```
