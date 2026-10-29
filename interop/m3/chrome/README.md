# interop/m3/chrome — R6-2c Chrome SETTINGS / CONNECT 抓包 harness

本目录唯一的职责：让真实 Chrome 走完 QUIC + H3 建连，把 Chrome 实际发出的
H3 SETTINGS 帧与 extended CONNECT 请求 HEADERS 帧**原样落盘**。

边界（必须一直成立）：

- 本目录证明的是“Chrome 实际发出了这些字节”，**不**证明 `rtx-*` 任何实现与
  Chrome 互通。M3-B0–B2 的互通结论属于 R6-3。
- 参考服务端是独立 oracle，只依赖审计基线内的 `quinn` 与
  `web-transport-proto`，不依赖任何 `rtx-*` crate。
- 本目录不实现、也不预埋 `rtx-h3` 的 SETTINGS / QPACK / CONNECT 逻辑；
  fixture 归 R6-2b。

## 目录结构

```
interop/m3/chrome/
├── server/                     # 独立 crate（有自己的 [workspace] 与 Cargo.lock，不在 rtx-rs workspace 内）
│   ├── Cargo.toml
│   └── src/main.rs             # QUIC 握手 + 记录 SETTINGS / CONNECT 原始字节
├── index.html                  # 客户端页面：new WebTransport(url) -> ready -> close
├── page_server.py              # 本地 HTTPS 页面服务（证书运行时生成）
├── run.sh                      # 一键脚本
└── <date>-chrome-<version>/    # 一次真实抓包的落盘结果
    ├── report.md
    ├── chrome-version.txt
    └── capture/
        ├── settings-frame.bin
        ├── connect-headers-frame.bin
        ├── settings-decoded.txt
        ├── server.log
        ├── chrome-console.log
        └── hashes.txt
```

## 依赖

| 依赖 | 用途 | 缺失时行为 |
|---|---|---|
| `cargo` / Rust 工具链 | 构建参考服务端 | `run.sh` 构建失败即退出 |
| `openssl` | 运行时生成自签证书 | 明确报错退出 |
| `python3` | 托管客户端页面的本地 HTTPS 服务 | 明确报错退出 |
| Chrome / Chromium（可 headless 启动） | 真实浏览器 | 打印 `无可用浏览器，抓包未执行` 并以 2 退出 |

浏览器查找顺序：`CHROME_BIN` → PATH 中的 `google-chrome` / `chromium` 等 →
`$HOME/.cache/ms-playwright/chromium-*/chrome-linux64/chrome` 等 Playwright 缓存。

## 运行

```bash
./interop/m3/chrome/run.sh
# 可选：
#   CHROME_BIN=/path/to/chrome
#   QUIC_PORT=4433   PAGE_PORT=8443
#   KEEP_WORK=1      # 失败排障时保留临时目录（证书与日志）
```

脚本顺序：生成运行时自签证书 → 构建参考服务端 → 启动 HTTPS 页面服务 →
启动参考服务端 → 启动 headless Chrome → 等待服务端抓到两帧并正常退出 →
校验帧文件非空且 Chrome 控制台出现 `ready` → 落盘 `hashes.txt` / `report.md`
→ 清理临时目录（证书绝不留存仓库）。无浏览器时脚本在证书生成之前退出，
不会产生空报告。

## 参考服务端行为

1. QUIC 握手（ALPN `h3`，运行时自签证书）。
2. 打开服务端控制流并发送 SETTINGS；SETTINGS 内容由
   `web_transport_proto::Settings::enable_webtransport(1)` 生成，与审计基线内的
   参考服务端一致。
3. 记录客户端控制流上的 SETTINGS 帧原始字节（帧类型 varint + 长度 varint +
   payload），并写 `settings-decoded.txt`（只读解析，供报告使用，不改字节）。
4. 记录请求流上的 HEADERS 帧原始字节（QPACK 编码态，不解码后重编码），
   随后用 QPACK 静态表索引 25（`:status 200`，字节 `[0x00,0x00,0xD9]`）应答
   200，使 Chrome 的 `ready` 正常 resolve。
5. 日志只记帧类型 / 长度 / 时间戳 / SHA-256，不记私钥、证书私钥材料或会话密钥。

## 审计基线对应关系

| 实现 | 锁定的 revision（来自 `DEPENDENCY_AUDIT.md` §1） | 该 revision 下 crate 版本 |
|---|---|---|
| `quinn-rs/quinn` / `quinn-proto` | `9d729c1b6b7ad30d45d40265037eeeb9d98a7420` | `quinn` 0.12.0 |
| `moq-dev/web-transport` / `web-transport-proto` | `d4e4e458da556ac3033c9b63f6db5110d3ab5adc` | `web-transport-proto` 0.6.2 |

两者均以 `rev = "<40 hex>"` 形式钉死在 `server/Cargo.toml`；`server/Cargo.lock`
一并提交以保证可复现。`sha2` 仅用于日志/文件名哈希，不参与任何 QUIC/H3 协议逻辑。

## 重跑时字节为什么会变

- Chrome 每次连接都会换一个 GREASE 设置项（标识符形如 `0x1f * N + 0x21`，
  值随机），所以 `settings-frame.bin` 的 SHA-256 每次不同；非 grease 的设置项
  内容稳定。
- `connect-headers-frame.bin` 含 `origin` 头（页面 origin）；换端口或换页面
  origin 都会改变字节，这是真实抓包应有的行为，不应手工“对齐”。

已提交的 `<date>-chrome-<version>/` 是其中一次真实运行的结果，`report.md`
记录的 SHA-256 与当次字节一一对应。

## 在 xc 上重跑（Chromium 130）

xc 上的既有环境（Playwright chromium-1140 = Chromium 130.0.6723.31）可直接复用：

```bash
# 1) 指定浏览器（路径按 xc 实际缓存位置调整；run.sh 也会自动探测 playwright 缓存）
export CHROME_BIN=/root/.cache/ms-playwright/chromium-1140/chrome-linux/chrome
# 2) 一键跑
./interop/m3/chrome/run.sh
```

产物落在 `interop/m3/chrome/<date>-chrome-130.0.6723.31/`。重跑前先确认
`cargo`、`openssl`、`python3` 可用；xc 上若 Playwright 缓存目录不同，用
`CHROME_BIN` 显式指定即可。预期产物清单与上面“目录结构”一致。

注意：不同 Chrome 版本的 SETTINGS / CONNECT 字节本就可能不同（尤其 grease 与
`sec-webtransport-http3-draft02` 这类版本信号），应以重跑得到的 `report.md`
为准，不要把 TRAE 沙箱的抓包结果当作 Chrome 130 的字节。

## 实测环境注意事项（TRAE 沙箱，Chrome for Testing 156.0.8078.4）

这些是排障时确认过的事实，写在这里避免后续重复踩坑：

- **页面必须走 HTTPS**。`file://` 是 opaque origin，Chrome 会在 45 ms 内直接
  以 “Opening handshake failed” 拒绝，且不发出任何 QUIC 包。
- **`--ignore-certificate-errors` 不覆盖 QUIC**。自签证书必须用
  `--ignore-certificate-errors-spki-list=<SHA-256(SPKI) base64>`，`run.sh` 会
  用 openssl 现场计算；否则 QUIC 握手报 `certificate unknown`。
- **沙箱环境变量里有 HTTP(S) 代理**，Chrome 会读取环境代理设置，导致页面加载
  与 WebTransport 失败；`--no-proxy-server` 是必需的。
- **用 `127.0.0.1` 而不是 `localhost`**：`localhost` 可能解析到 `::1`，而参考
  服务端只监听 IPv4。
- Chrome 156 的 CONNECT 请求带的是历史遗留头
  `sec-webtransport-http3-draft02: 1`，并不携带 `sec-webtransport-http3-draft`
  这类带 draft 号的头；报告如实记录，不做改写。

## 明确不做

`rtx-h3`、SETTINGS/QPACK/CONNECT 实现、M3-B0–B2 互通结论、DATAGRAM/流互通、
基准（P7）、嵌入式移植（P8）均不在本目录范围内。
