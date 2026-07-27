# upload_server LIEF Authenticode 迁移计划

日期：2026-07-27

## 1. 目标

将 `upload_server.py` 的 PE Authenticode 校验从 `signify` 迁移到 LIEF，移除
`signify -> certvalidator -> oscrypto -> libcrypto` 依赖链，解决 Ubuntu 24.04
上旧版 `oscrypto` 无法识别 OpenSSL 3 版本的问题，同时保持现有上传准入规则：

- PE 的 Authenticode 内容摘要和签名必须有效。
- 签名证书必须能建链到项目认可的 CA。
- signer subject CN 必须为 `Microsoft Windows`。
- signer issuer CN 必须为 `Microsoft Windows Production PCA 2011`。
- 任何解析、签名、建链或证书策略错误都必须 fail closed。

生产运行时的唯一可信 CA 来源固定为：

```text
ca/windows_code_signing.pem
```

不得回退或合并系统 CA、Windows certificate store、`certifi`、`mscerts`、环境
变量指定的 CA、LIEF 默认 CA 或网络下载的证书。

## 2. 当前基线

- 仓库提交：`85441e7098e6983d502cadbe202aceb3c6e41ddf`
- 当前签名实现：`upload_server.py::verify_signature`。
- 当前依赖：`signify 0.9.2`，间接依赖 `certvalidator`、`oscrypto` 和 `mscerts`。
- 当前上传流程在保存文件前调用 `verify_signature(file_data)`；返回 `False` 时拒绝
  上传。
- `tests/test_upload_server.py` 当前只 mock `verify_signature()`，没有真实
  Authenticode、信任链或 CA 加载测试。
- CA bundle 当前包含 82 个 PEM certificate block。
- CA bundle 当前 SHA-256：
  `29BF281AE5CA7FBE3D08D9C311640CB34D4AEFB61EEB12B54BA7F1AB63B1B594`。
- `ca/` 当前尚未被 Git 跟踪；实现提交必须将 CA bundle 纳入版本控制和部署产物。

本节的证书数量和 SHA-256 只记录计划基线，不作为永久硬编码的运行时限制。后续如需
更新 CA bundle，必须通过独立 review 展示证书增删清单、原因和回归结果。

## 3. 硬性决策

### 3.1 信任来源

1. 生产代码只从仓库内 `ca/windows_code_signing.pem` 加载可信 CA。
2. CA 路径必须基于 `Path(__file__).resolve().parent` 解析，不能依赖启动时的当前
   工作目录。
3. 不提供环境变量、CLI 参数或隐式默认值来覆盖 CA 路径。
4. CA 文件缺失、不可读、没有证书块或任何证书解析失败时，服务必须在监听端口前
   终止，并输出不包含证书内容的明确错误。
5. 签名中内嵌的证书可以作为建链所需的中间证书，但不能仅因“内嵌在 PE 中”而成为
   信任锚；信任链最终必须落到 `ca/windows_code_signing.pem` 提供的 CA 材料。
6. 不读取 `/etc/ssl/certs`、OpenSSL 默认路径、Windows certificate store、
   `certifi.where()` 或 `mscerts`，也不通过 AIA、HTTP 或 LDAP 下载缺失证书。

### 3.2 签名接受策略

单个上传文件只有在至少存在一个同时满足以下条件的 Authenticode signature 时才可
接受：

1. PE Authenticode authentihash 与签名内摘要一致。
2. CMS/PKCS#7 signer signature 有效，authenticated attributes 和
   countersignature/timestamp 没有导致验证失败。
3. signer certificate 可通过签名内嵌中间证书建链到唯一 CA bundle 中的可信 CA。
4. 实际 signer certificate 的 subject CN 精确等于 `Microsoft Windows`。
5. 实际 signer certificate 的 issuer CN 精确等于
   `Microsoft Windows Production PCA 2011`。

多签名文件按 signature 独立评估；一个完全合格的 signature 即可接受。不得用证书
列表中的第一张证书作为 signer fallback，也不得只凭 subject/issuer 字符串放行。

### 3.3 行为边界

- 保留 `verify_signature(file_data) -> bool` 作为上传流程的稳定 seam，避免扩大
  `UploadHandler` 改动范围。
- 保留现有 `pefile` 用途；本次只替换 Authenticode 实现，不重写版本资源、架构或
  文件名解析。
- 不在本次迁移中增加在线 revocation 检查。若 LIEF 默认执行网络访问，必须显式
  禁用；如果无法禁用，则迁移不得进入生产实现。
- 不改变 signer/issuer CN 白名单。本次可以移除“不匹配时取第一张证书”的旧
  fallback，但不得扩大可接受 signer 范围。
- 不将原始证书、上传文件内容或完整签名结构写入生产日志。

## 4. 目标验证流程

```text
uploaded bytes
    -> LIEF parse PE
    -> enumerate embedded Authenticode signatures
    -> verify per-signature authentihash and CMS integrity
    -> identify the actual signer certificate
    -> build/verify chain using only ca/windows_code_signing.pem
    -> exact subject CN and issuer CN policy
    -> accept if any signature passes; otherwise reject
```

CA bundle 在服务启动阶段加载并校验一次，后续请求复用只读结果。不得在每次上传时
重新读取磁盘，也不得在加载失败后使用空列表或系统默认信任库继续运行。

## 5. 文件范围

- Modify: `upload_server.py`
  - 移除 `SignedPEFile`、`VerificationError` 及 `oscrypto/libcrypto` 专用导入错误
    分支。
  - 增加 LIEF PE/AuthentiCode 校验、CA bundle 加载和 CN 提取辅助逻辑。
  - 在 HTTP server 开始监听前完成 CA preflight。
- Modify: `pyproject.toml`
  - 移除 `signify`，增加经过验证并固定兼容范围的 `lief` 依赖。
- Modify: `uv.lock`
  - 重新锁定依赖，并确认不再解析 `signify`、`certvalidator`、`oscrypto`、
    `mscerts`。
- Modify: `tests/test_upload_server.py`
  - 增加 CA 加载、LIEF 验证、信任链、CN 策略和 fail-closed 测试。
- Add/Track: `ca/windows_code_signing.pem`
  - 作为生产唯一可信 CA bundle 纳入版本控制和部署包。
- Modify: `docs/upload_server.md`
  - 说明 LIEF 校验行为、唯一 CA 来源、CA 缺失时的启动失败和更新流程。
- Modify: `docs/requirements.md`
  - 在 Ubuntu 24.04 smoke test 通过后，移除 `oscrypto` Git workaround；仅在确认
    仓库其他功能不需要 OpenSSL development headers 后再删除对应系统依赖说明。

## 6. 实施任务

### Task 1：建立 LIEF 能力与兼容性基线

**Files:**

- Verify: `upload_server.py`
- Verify: `ca/windows_code_signing.pem`
- Modify: `pyproject.toml`
- Modify: `uv.lock`

- [x] 选择支持项目 Python 3.10+、Windows 和 Ubuntu 24.04 wheels 的 LIEF 版本，
      在 `pyproject.toml` 中固定兼容范围，不使用无上限的浮动依赖。
- [x] 用当前 CA 文件验证 LIEF 能否直接解析包含 `subject=`、`issuer=` 前导文本的
      多证书 PEM bundle。
- [x] 如果 LIEF 不能直接解析该文件，实现确定性的 PEM block splitter：只从同一个
      `ca/windows_code_signing.pem` 提取完整 `BEGIN/END CERTIFICATE` block，不能
      生成或读取第二份信任库。
- [x] 确认当前 82 个 certificate block 全部可解析；重复证书应按 DER fingerprint
      去重，空块、截断块或非证书 PEM block 必须报错。
- [x] 用至少一个真实 Microsoft-signed PE 验证 LIEF 的以下 API 语义：PE 解析、
      多签名枚举、per-signature 检查、authentihash、signer certificate、
      countersignature/timestamp 和 `is_trusted_by(...)`。
- [x] 明确 `Binary.verify_signature()` 与 per-signature API 在多签名场景下的差异；
      如果只能得到文件级聚合结果，必须证明它不会让无效 signature 借由另一个有效
      signature 绕过 signer/issuer 策略。
- [x] 在实现说明中记录所选 LIEF 版本、验证过的 API、返回 flag 含义和 Linux wheel
      运行时依赖。

Task 1 是实现门禁。无法证明“签名完整性检查”和“唯一 CA bundle 建链”可同时实现
时，不得继续删除 `signify`。

### Task 2：实现唯一 CA bundle 加载与启动 preflight

**Files:**

- Modify: `upload_server.py`
- Test: `tests/test_upload_server.py`

- [x] 定义仓库相对常量，例如
      `WINDOWS_CODE_SIGNING_CA_PATH = SCRIPT_DIR / "ca" / "windows_code_signing.pem"`。
- [x] 实现 CA bundle loader，返回不可变或只读复用的 LIEF certificate collection。
- [x] loader 必须检测文件缺失、权限错误、空文件、零证书、损坏 PEM、解析失败和
      重复证书；错误信息包含路径和错误类型，但不打印 PEM 内容。
- [x] 在 `main()` 创建 storage/server 之前执行 CA preflight；preflight 失败应返回
      非零退出码，不能开始监听端口。
- [x] 通过单元测试证明从仓库外 cwd 启动仍读取同一 CA 文件。
- [x] 通过代码检查和测试证明没有系统 CA、`certifi`、`mscerts`、环境变量 CA 或
      网络证书发现 fallback。
- [x] 启动日志只记录 CA bundle 的规范化路径、成功解析的唯一证书数量和文件
      SHA-256，便于部署审计。

### Task 3：用 LIEF 重写 `verify_signature`

**Files:**

- Modify: `upload_server.py`
- Test: `tests/test_upload_server.py`

- [x] 移除 `signify.authenticode` imports 和 `VerificationError` 分支，新增 LIEF
      import；缺失 LIEF 时继续使用明确的依赖安装错误并退出。
- [x] 从内存中的 `file_data` 解析 PE；不得为每次上传创建可被其他进程替换的固定
      临时文件。如 LIEF 版本必须使用文件路径，应使用权限受限、唯一命名且保证清理
      的临时文件，并增加对应安全测试。
- [x] 对每个 signature 独立检查 authentihash、CMS signature、authenticated
      attributes、timestamp/countersignature 和 LIEF verification flags。
- [x] 从 signer info 直接获得或严格匹配 signer certificate；禁止恢复当前的
      “找不到就取第一张 certificate”行为。
- [x] 使用启动阶段加载的 CA collection 校验 signer chain。签名内证书只允许作为
      中间证书，不能改变可信 CA 集合。
- [x] 使用结构化 X.509 name/RDN API 提取 CN；如果 LIEF 仅提供字符串，封装并测试
      RFC 4514 转义、重复 CN、大小写和空白行为，禁止简单 `split("CN=")`。
- [x] subject/issuer CN 使用当前精确、区分大小写的比较值。
- [x] 任意 LIEF exception、未知 verification flag、无签名、无 signer、建链失败、
      CA 不匹配或 CN 不匹配均返回 `False`，并记录可定位但不泄露文件内容的原因。
- [x] 保持 `verify_signature(file_data) -> bool` 和调用方 HTTP 400 行为不变。

### Task 4：补齐签名和信任测试矩阵

**Files:**

- Modify: `tests/test_upload_server.py`
- Optional Add: `tests/fixtures/authenticode/`

- [x] CA loader：正确 bundle、仓库外 cwd、缺失文件、空文件、损坏证书、重复证书
      和单个 block 解析失败。
- [x] PE/signature：无签名 PE、损坏 PE、文件内容被篡改、CMS signature 无效、
      authentihash 不匹配和未知 LIEF flag。
- [x] trust：有效链、未知 root、只存在内嵌 self-signed root、缺失 intermediate、
      系统信任但 bundle 不信任，以及 bundle 信任但系统不信任。
- [x] identity：正确 signer/issuer、错误 signer、错误 issuer、无 CN、重复 CN 和
      certificate 顺序变化。
- [x] multi-signature：一个完全合格 signature 加一个无效 signature、签名有效但
      signer 不合格、多个 signer 中只有一个合格。
- [x] timestamp：当前有效证书、已过期但有有效可信 timestamp、无效 timestamp 和
      timestamp certificate 不受唯一 bundle 信任。
- [x] exception：LIEF parse/check/trust API 抛错时全部 fail closed。
- [x] 使用 mock/fake 覆盖分支逻辑；另增加至少一个真实 Authenticode fixture 或受控
      integration test，证明不是只对模拟对象成立。
- [x] 测试专用 CA/证书只能通过测试依赖注入或 fixture 使用，生产路径不能提供 CA
      override seam；测试不得修改 `ca/windows_code_signing.pem`。

真实 Microsoft PE 如因体积或许可不能提交仓库，应提供显式 opt-in smoke test，接受
本地文件路径并验证预期 signer、issuer、信任链和篡改后拒绝行为。该 smoke test 不
替代可在 CI 中运行的单元测试。

### Task 5：依赖、文档和部署收口

**Files:**

- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Modify: `docs/upload_server.md`
- Modify: `docs/requirements.md`
- Track: `ca/windows_code_signing.pem`

- [x] 移除 `signify`，加入 Task 1 已验证的 LIEF 版本范围并执行 `uv lock`、
      `uv sync`。
- [x] 使用 `uv tree` 确认 `signify`、`certvalidator`、`oscrypto`、`mscerts` 已从
      依赖图消失；如仍由其他依赖引入，记录来源且不得宣称完全移除故障链。
- [x] 文档明确 CA bundle 是生产唯一信任来源，更新它属于安全敏感变更，必须 review
      证书增删和重新运行完整签名测试。
- [x] 文档明确 CA 文件缺失或损坏会阻止服务启动，不存在系统 CA fallback。
- [x] 确认仓库不存在 Docker、systemd、PM2、打包或 upload-server release artifact；
      当前部署方式是包含 `upload_server.py` 和可读 `ca/` 的完整 checkout/source copy。
- [x] 在干净 Ubuntu 24.04 环境确认 LIEF wheel 可安装和导入；验证成功后删除
      `oscrypto` Git workaround。
- [x] 只有在仓库其他功能和 LIEF wheel 均不需要 OpenSSL development headers 时，
      才从 `docs/requirements.md` 删除 `libssl-dev`/`openssl-devel` 安装说明。

### Task 6：回归、平台验证和上线观察

**Files:**

- Verify: `upload_server.py`
- Verify: `tests/test_upload_server.py`
- Verify: `ca/windows_code_signing.pem`

- [x] 运行 upload server 定向测试：

  ```powershell
  uv run python -m unittest tests.test_upload_server -v
  ```

- [x] 运行全量单元测试：

  ```powershell
  uv run python -m unittest discover -s tests
  ```

- [x] 运行格式、静态和语法检查：

  ```powershell
  uv run ruff format --check upload_server.py tests/test_upload_server.py
  uv run ruff check upload_server.py tests/test_upload_server.py
  uv run python -m compileall -q upload_server.py tests
  ```

  仓库没有 Ruff dependency/config；实际门禁使用 `uvx ruff format --check` 和
  `uvx ruff check` 对同一文件执行，并全部通过。

- [x] 检查旧依赖和禁止的 trust fallback 不再存在：

  ```powershell
  uv tree
  rg -n "signify|oscrypto|certvalidator|mscerts|certifi|/etc/ssl|ssl.get_default_verify_paths" upload_server.py pyproject.toml uv.lock docs
  ```

  预期只允许迁移历史或计划文档提及旧依赖；生产代码和活动依赖不得引用这些路径。
  `certifi` 仍由 HTTP/SDK dependencies 间接使用，但 `upload_server.py` 不将其作为
  Authenticode trust source。
- [x] 在 Windows 和 Ubuntu 24.04 分别运行 LIEF/CA import smoke：加载唯一 CA bundle、
      输出证书数量、解析一份 PE，并确认损坏 CA 时启动失败。
- [x] 使用真实 Microsoft-signed `ntoskrnl.exe` 上传成功；分别对 PE 内容、certificate
      table 和 signer identity 制造失配，确认均返回 HTTP 400 且不写入 disk/OSS。
- [x] 启动 `/health` smoke，确认正常 CA 下服务可监听；CA 缺失/损坏时 `main()` 在
      storage/server construction 前以状态 1 退出。仓库没有 PM2/systemd 配置可验证。
- [ ] 上线后观察签名拒绝率、LIEF exception 分类和启动 preflight；异常升高时保留
      样本哈希和错误类别，不记录上传内容。

## 7. CA bundle 更新规则

`ca/windows_code_signing.pem` 是安全边界，不作为普通数据文件静默更新。每次修改必须：

1. 列出新增、删除证书的 subject、issuer、serial number、有效期和 SHA-256
   fingerprint。
2. 说明更新来源和业务原因，不接受运行时从系统或网络自动同步。
3. 检查是否意外加入 end-entity code-signing certificate；如允许某证书作为 trust
   anchor，必须在 review 中明确说明。
4. 重新运行 CA loader、有效链、未知 root、错误 signer/issuer、timestamp 和真实
   Microsoft PE smoke tests。
5. 更新部署审计中记录的 bundle SHA-256；不需要为了证书轮换修改 Python 常量。

## 8. 风险与缓解

1. **LIEF 与 signify 的 timestamp/多签名语义不同。**
   使用真实 Microsoft PE corpus 做迁移前后对照，差异必须在实现 PR 中逐项解释。
2. **LIEF 文件级 verification flag 可能掩盖单个 signature 状态。**
   Task 1 必须验证 per-signature API；无法严格关联 signature、signer 和 trust 结果时
   不上线。
3. **CA bundle 包含多种公共 CA。**
   本次不隐式精简内容，但所有信任只能来自该文件；后续通过独立安全 review 进行
   bundle 最小化。
4. **Linux wheel 或 native runtime 兼容性。**
   Ubuntu 24.04 clean-room smoke 是删除 `oscrypto` workaround 和 OpenSSL 开发包说明
   的前置条件。
5. **CA 文件当前未被 Git 跟踪。**
   没有将该文件纳入提交和部署产物前，迁移不得声明完成。
6. **缺少可提交的真实 Microsoft PE fixture。**
   CI 使用受控 fixture 覆盖行为，外部真实样本 smoke 作为完成门禁并记录样本
   SHA-256，不提交受许可限制的二进制。

## 9. 验收标准

以下条件全部满足后，才能声明 LIEF 迁移完成：

1. `upload_server.py` 不再导入或调用 `signify`、`certvalidator`、`oscrypto` 或
   `mscerts`，`uv tree` 中也不存在这些依赖。
2. Authenticode authentihash、CMS signature、signer certificate、timestamp 和
   verification flag 均按 Task 3 的策略校验。
3. signer chain 只能信任 `ca/windows_code_signing.pem`；系统 CA、默认 CA、环境
   override 和网络发现均不能使原本不受该 bundle 信任的文件通过。
4. subject CN 与 issuer CN 继续精确匹配现有白名单，且不再回退到第一张证书。
5. CA bundle 缺失、损坏、为空或解析不完整时，服务在监听前以非零状态退出。
6. Windows、Ubuntu 24.04 定向测试、全量 unittest、Ruff、compileall 和真实 PE
   smoke 全部通过；无法执行的关键验证不得以“完成”表述。
7. `docs/upload_server.md`、`docs/requirements.md` 和部署流程与实际依赖、CA 路径、
   启动失败语义一致。
8. `ca/windows_code_signing.pem` 已被 Git 跟踪并包含在生产部署产物中。

## 10. 建议提交顺序

1. `test(upload): add Authenticode trust policy matrix`
2. `feat(upload): load repository Windows code-signing CA bundle`
3. `refactor(upload): migrate Authenticode verification to LIEF`
4. `chore(deps): replace signify with LIEF`
5. `docs(upload): document LIEF and CA trust policy`

每个提交应包含对应定向验证；提交信息结尾追加：

```text
Co-Authored-By: Codex
```

## 11. Implementation record

实施日期：2026-07-27

### 11.1 Dependency and API decisions

- Selected `lief>=0.17.6,<0.18`; Windows and Ubuntu 24.04 wheels were installed and imported successfully.
- LIEF is used for in-memory PE parsing, per-signature `Signature.check()`, per-signature `Binary.verify_signature(signature)`, signer selection, nested-signature discovery, and authentihash verification.
- LIEF 0.17.x does not fail every Microsoft countersignature cryptographic error. The implementation therefore uses `asn1crypto>=1.5.1,<2` to parse timestamp CMS and `cryptography>=47,<48` to verify RFC 3161/PKCS#9 signatures, message imprints, ESS `SigningCertificate` binding, certificate profiles, and the repository-only trust path.
- `signify`, `certvalidator`, `oscrypto`, and `mscerts` were removed from the active dependency graph. The Ubuntu OpenSSL development-header and `oscrypto` source workaround documentation was removed after the clean-room wheel smoke passed.

### 11.2 CA and trust implementation

- The only runtime trust source is `Path(__file__).resolve().parent / "ca/windows_code_signing.pem"`.
- The tracked bundle contains 82 PEM blocks, 46 unique DER certificates, and 36 duplicates. Its trailing blank line was normalized without changing any PEM block; the tracked bundle SHA-256 is `4C0BAB3E51710D7A78B7F24166EA3BD69AC70828697E6946945E391E57F7943E` (the section 2 hash remains the pre-normalization baseline).
- Startup preflight runs before storage construction and port binding. Missing, unreadable, empty, truncated, non-certificate, or invalid certificate material exits with status 1 without a trust fallback.
- Signer and timestamp chains use only embedded intermediates plus the repository anchors. The custom path builder enforces CA constraints and purpose restrictions, rejects unsupported critical constraints, handles self-issued path-length semantics, indexes normalized subject names with AKI/SKI preference, and applies shared per-upload search/verification budgets.

### 11.3 Signature policy and hardening

- `verify_signature(file_data) -> bool` and the upload HTTP 400 contract remain unchanged.
- The actual CMS signer must be unique and present exactly once in the embedded certificate collection; there is no first-certificate fallback.
- Code-signing and timestamp end-entity BasicConstraints, EKU, and optional KeyUsage are validated. RFC 3161 tokens require a valid `SigningCertificate` or `SigningCertificateV2` binding. PKCS#9 countersignatures reject the forbidden `content-type` attribute.
- The raw PE certificate table is bounded before LIEF parsing. Signature count, nested count/depth, individual and total DER size, embedded certificate count/size, timestamp count, public-key size, certificate parsing, chain states, and parent-edge signature verification are bounded and fail closed.
- Production rejection logs contain only the uploaded SHA-256, signature index, and fixed error category or exception type.

### 11.4 Verification evidence

- Windows directed suite: 68 tests passed; the opt-in real-PE test is skipped when its environment variable is absent.
- Full repository suite: 478 tests passed with 1 opt-in skip. `uv sync --frozen`, `uv lock --check`, `uvx ruff format --check`, full `uvx ruff check`, `compileall`, `uv tree`, and `git diff --check` passed.
- Windows real sample: `C:\Windows\System32\ntoskrnl.exe`, version `10.0.26100.8875`, SHA-256 `41cdca29ad3c9e3efa1912dccd04757ebcb3553ac515a279e5dd8d9290e7e030`.
- The real sample was accepted. PE-content, certificate-table, and signer-identity tampering were rejected; rejected uploads returned HTTP 400 and did not reach storage.
- Ubuntu 24.04.4 LTS clean-room: `uv sync --frozen`, LIEF `0.17.6`, the 68-test suite, and the same real-PE smoke all passed from a temporary project copy.
- `/health` returned `{"success":true,"message":"OK","status":"healthy"}` after CA preflight and a real local port bind.

### 11.5 Deployment and residual risks

- The repository has no Docker, systemd, PM2, PyInstaller, or dedicated upload-server release artifact. The supported deployment is currently a complete Git checkout or source copy containing both `upload_server.py` and the tracked `ca/` directory; the tag workflow continues to publish only `kphdyn.xml`.
- The plan intentionally does not add online revocation or Windows Disallowed CTL checks. Revoked-but-otherwise-valid signer or TSA certificates remain a documented residual risk.
- The existing CA bundle contains multiple public roots and the signer identity policy still uses exact subject/issuer CN values. Bundle minimization or Microsoft intermediate fingerprint pinning is intentionally deferred to a separate security review, as specified in section 8.
- Post-deployment rejection-rate and exception-category observation cannot occur before this PR is deployed. It remains an operational follow-up and must not be represented as pre-merge verification evidence.
