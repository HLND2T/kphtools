# 上传服务器

[返回 README](../../README.zh-CN.md)

`upload_server.py` 接收文件上传，校验 PE 文件和 Authenticode 签名，并将通过校验的文件保存到本地磁盘或 Alibaba Cloud OSS。

## 行为

服务器会：

- 接受 `/upload` 的 POST 请求。
- 校验上传文件是否为 PE 文件。
- 验证 `FileDescription` 是否为 `NT Kernel & System`。
- 在调用 LIEF 前预检原始 PE certificate table，然后校验每个 Authenticode 签名。PE authentihash、CMS signer signature、authenticated attributes、countersignature 和 RFC 3161 timestamp 都必须有效。
- 要求实际 signer certificate 的 subject CN 必须精确为 `Microsoft Windows`，issuer CN 必须精确为 `Microsoft Windows Production PCA 2011`。
- 仅使用 `ca/windows_code_signing.pem` 作为 trust-anchor 来源构建 signer 和 timestamp certificate chain。
- 从 `FileResource` 中提取 `OriginalFilename` 和 `FileVersion`。
- 根据 PE header 判断 `x86`、`amd64` 或 `arm64` 架构。
- 通过 `KPHTOOLS_SERVER_STORAGE=disk|oss` 选择存储后端。
- 使用 `{arch}/{FileName}.{FileVersion}/{FileSHA256}/{FileName}` 作为相对于后端的路径保存文件。

客户端必须提供 HTTP POST 上传请求。需要 HTTPS 支持时，请使用 nginx 或 CDN。

## Authenticode 信任策略

生产环境唯一的信任来源是：

```text
ca/windows_code_signing.pem
```

路径相对于 `upload_server.py` 解析，而不是相对于当前工作目录。服务器不会将该 bundle 与系统 CA、Windows certificate store、`certifi`、环境选择的 CA 文件、LIEF 默认值或通过 AIA、HTTP、LDAP 下载的证书合并。

PE 中嵌入的证书可以作为中间证书使用，但除非同一 DER 证书也存在于仓库 bundle 中，否则嵌入证书永远不会作为 trust anchor。多签名文件会逐个签名评估；只要有一个签名完全有效且符合策略即可。无法识别 signer 时，不会回退到第一个嵌入证书。

LIEF `0.17.6` 执行每个签名的 Authenticode 完整性和 authentihash 校验。`asn1crypto` 暴露 timestamp CMS 字段，`cryptography` 校验 timestamp signature、message imprint、RFC 3161 `SigningCertificate`/`SigningCertificateV2` binding、timestamp certificate profile、历史有效期和 certificate path。该补充校验是必需的，因为 LIEF 0.17.x 不会自行报告所有 Microsoft countersignature 的密码学错误。

代码签名 leaf 必须是 end-entity certificate，EKU 必须包含 `codeSigning`；存在 KeyUsage 时，必须允许 digital signature 或 content commitment。RFC 3161 和 PKCS#9 timestamp certificate 必须是 end entity，并带有 critical、仅用于 timestamp 的 EKU；存在 KeyUsage 时必须允许 signing。CA path building 会校验 BasicConstraints、path length、CA KeyUsage、CA EKU restrictions、AKI/SKI matching、有限的 public-key size，并拒绝 verifier 未实现的 critical extension。

所有解析、完整性、身份、timestamp 和 trust 错误都会 fail closed。生产环境拒绝日志包含上传 SHA-256、签名索引和有限的错误类别；不会包含上传字节、PEM block 或完整 certificate structure。

LIEF 解析前后都会进行资源限制。当前策略将 PE certificate table 限制为 8 MiB，单个签名限制为 4 MiB，所有签名 DER 限制为 8 MiB，签名总数限制为 16，嵌套深度限制为 4，每个签名的嵌入证书数限制为 64，每个签名的 timestamp 值限制为 16，并通过每次上传共享的预算限制 certificate-chain 搜索。超过任一限制会在存储前拒绝上传。

本次迁移中以下策略边界是有意保留的：撤销/Windows Disallowed CTL 检查为离线状态，因此不会执行；现有 CA bundle 仍包含多个 public root。Microsoft 身份继续使用之前实现中的 signer/issuer CN 精确匹配策略，而不是固定 Microsoft intermediate fingerprint。CA 最小化或 fingerprint pinning 需要单独的安全评审。

## CA 启动预检

CA bundle 会在初始化存储或绑定端口之前加载一次。启动时会校验每个 PEM certificate block，拒绝截断、非证书或无效 block，按 DER SHA-256 对证书去重，并且只记录：

- 规范化后的 bundle 路径；
- PEM block 数量和唯一证书数量；
- bundle SHA-256。

如果文件缺失、不可读、为空或格式错误，进程以状态码 1 退出且不会开始监听。不会回退到空 bundle 或系统信任。

例如使用磁盘存储、`-symboldir="C:/Symbols"`、`arch=amd64`、`FileName=ntoskrnl.exe` 和 `FileVersion=10.0.22621.741` 时，文件会保存到：

```text
C:/Symbols/amd64/ntoskrnl.exe.10.0.22621.741/8025c442b39a5e8f0ac64045350f0f1128e24f313fa1e32784f9854334188df3/ntoskrnl.exe
```

## 用法

当 `KPHTOOLS_SERVER_STORAGE` 未设置时，默认使用磁盘存储：

```bash
export KPHTOOLS_SERVER_STORAGE=disk
export KPHTOOLS_SYMBOLDIR="$HOME/kphtools/symbols"
cd "$HOME/kphtools"
uv run python upload_server.py [-port=8000]
```

请从包含 `upload_server.py` 和 `ca/windows_code_signing.pem` 的完整 Git checkout 或部署副本运行服务。仓库当前不会构建独立的上传服务器发布工件；tag workflow 只发布 `kphdyn.xml`。

磁盘存储默认使用当前工作目录下的 `symbols`。使用 `-symboldir` 选择其他目录；设置 `KPHTOOLS_SYMBOLDIR` 时它优先。

OSS 存储会直接将上传文件从内存写入 OSS，不会创建本地符号目录：

```bash
export KPHTOOLS_SERVER_STORAGE=oss
export KPHTOOLS_SERVER_OSS_REGION="cn-hangzhou"
export KPHTOOLS_SERVER_OSS_BUCKET="kernel-symbols"
export KPHTOOLS_SERVER_OSS_ENDPOINT="oss-cn-hangzhou-internal.aliyuncs.com"
export KPHTOOLS_SERVER_OSS_PREFIX="symbols"
export OSS_ACCESS_KEY_ID="your-access-key-id"
export OSS_ACCESS_KEY_SECRET="your-access-key-secret"
cd "$HOME/kphtools"
uv run python upload_server.py [-port=8000]
```

## 环境变量

通用服务器变量：

- `KPHTOOLS_SERVER_STORAGE`：`disk` 或 `oss`；默认 `disk`，不区分大小写。
- `KPHTOOLS_SERVER_PORT`：可选监听端口；默认 `8000`。

磁盘存储变量：

- `KPHTOOLS_SYMBOLDIR`：可选符号目录覆盖；默认是当前工作目录下的 `symbols`。

OSS 存储变量：

- `KPHTOOLS_SERVER_OSS_REGION`：必需的 OSS region，例如 `cn-hangzhou`。
- `KPHTOOLS_SERVER_OSS_BUCKET`：必需的 bucket 名称。
- `KPHTOOLS_SERVER_OSS_ENDPOINT`：可选的内部或自定义 endpoint。
- `KPHTOOLS_SERVER_OSS_PREFIX`：可选的 object key 前缀；会去除首尾 `/`。
- `OSS_ACCESS_KEY_ID`：OSS SDK environment credentials provider 必需。
- `OSS_ACCESS_KEY_SECRET`：OSS SDK environment credentials provider 必需。
- `OSS_SESSION_TOKEN`：可选 STS session token。

Windows 命令提示符中的磁盘配置示例：

```bat
set KPHTOOLS_SERVER_STORAGE=disk
set KPHTOOLS_SYMBOLDIR=C:/Symbols
set KPHTOOLS_SERVER_PORT=8000
```

无效的存储模式或缺少模式相关变量，会使服务器在监听前退出。

## 更新 CA bundle

`ca/windows_code_signing.pem` 是安全边界。每次更新都必须进行专门评审，列出每个新增或删除证书的 subject、issuer、serial number、有效期和 SHA-256 fingerprint，以及来源和运行原因。

合并 CA 更新前：

1. 确认没有意外将 end-entity code-signing certificate 添加为 trust anchor。
2. 运行 CA loader、valid-chain、unknown-root、signer/issuer、timestamp 和真实 Microsoft PE 测试。
3. 在部署评审中记录新的 bundle SHA-256。
4. 将更新后的 `ca/` 目录与 `upload_server.py` 一起部署；不要在运行时从系统或网络同步 trust。

## OSS 行为与权限

当 `KPHTOOLS_SERVER_OSS_PREFIX=symbols` 时，示例 object key 为：

```text
symbols/amd64/ntoskrnl.exe.10.0.22621.741/8025c442b39a5e8f0ac64045350f0f1128e24f313fa1e32784f9854334188df3/ntoskrnl.exe
```

OSS 身份需要对配置的 bucket 和 prefix 具有调用 `PutObject` 以及 `HeadObject`/读取对象 metadata 的权限。创建 bucket、生命周期规则、加密、RAM policy 管理，以及迁移或删除已有本地文件，都不在服务器范围内。

上传使用 OSS forbid-overwrite 语义。SHA-derived key 上已存在的对象（包括并发上传冲突）视为幂等成功。`/exists` 使用对象 metadata 并返回 `file_size`，不会下载对象。只有 `NoSuchKey` 会被视为不存在；其他 OSS 错误返回 HTTP 502 和通用消息。

OSS 模式不会回退到磁盘。现有分析工具仍然使用本地 `symbols` 目录，因此这些工具需要的对象必须通过挂载或单独下载获得。

## 检查文件是否存在

```bash
curl "http://localhost:8000/exists?filename=ntoskrnl.exe&arch=amd64&fileversion=10.0.26100.7462&sha256=710cf711b95c30f4fe78ac15026e2aa8c0bc96c2f72b15a09903818219e6c85a"
```

找到文件时的响应：

```json
{"success": true, "message": "File existence checked", "filename": "ntoskrnl.exe", "arch": "amd64", "fileversion": "10.0.26100.7462", "sha256": "710cf711b95c30f4fe78ac15026e2aa8c0bc96c2f72b15a09903818219e6c85a", "exists": true, "path": "amd64/ntoskrnl.exe.10.0.26100.7462/710cf711b95c30f4fe78ac15026e2aa8c0bc96c2f72b15a09903818219e6c85a/ntoskrnl.exe", "file_size": 12993992}
```

找不到文件时的响应：

```json
{"success": true, "message": "File existence checked", "filename": "ntoskrnl.exe", "arch": "amd64", "fileversion": "10.0.26100.7462", "sha256": "710cf711b95c30f4fe78ac15026e2aa8c0bc96c2f72b15a09903818219e6c85a", "exists": false, "path": "amd64/ntoskrnl.exe.10.0.26100.7462/710cf711b95c30f4fe78ac15026e2aa8c0bc96c2f72b15a09903818219e6c85a/ntoskrnl.exe"}
```

## 上传文件

```bash
curl -X POST -H "Content-Type: application/octet-stream" --data-binary "@C:/Windows/System32/ntoskrnl.exe" http://localhost:8000/upload
```

- 必须使用 `Content-Type: application/octet-stream`。
- 文件大小上限为 20 MB。
- 不会覆盖已有目标文件。
- 支持 `X-File-Compressed: gzip` header，此时上传 payload 必须先经过 gzip 压缩。

## 健康检查

```bash
curl "http://localhost:8000/health"
curl "http://localhost:8000/"
```

```json
{"status": "healthy"}
```

## Authenticode 校验测试

单元测试覆盖 CA 解析、trust path、signer identity、LIEF flags、多签名决策、timestamp 完整性和 fail-closed 异常。真实 Microsoft 签名 PE smoke test 为可选测试：

```powershell
$env:KPHTOOLS_AUTHENTICODE_TEST_PE = "C:\Windows\System32\ntoskrnl.exe"
uv run python -m unittest tests.test_upload_server.TestRealAuthenticodeSmoke -v
```

smoke test 接受原始 PE，拒绝 PE 内容、certificate table 和 signer identity 被篡改的文件，并确认被拒绝的上传不会交给存储层。

