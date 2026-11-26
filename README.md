# GitHub Access · GitHub 账号访问平台

一个 JavaScript Worker 文件承载页面和 API，使用 Cloudflare D1 保存数据，无前端构建、无运行时第三方依赖。

## 功能

- **管理员**：密钥登录、三行文本录入、TXT 批量导入、搜索、延期、删除。
- **使用方**：密钥登录，查看全部账号，一键复制账号、密码、动态验证码。
- 账号默认有效 **2 小时**；到期后双方仍可查看、复制账号密码，使用方无法再获取验证码。管理员可重新授权。
- 点击「延期 2h」将到期时间设置为**点击时刻 + 2 小时**，连续点击不累计；原到期时间更晚时也会被重置。
- 管理员与使用方登录默认各保留 **7 天**，从登录成功起计算，不随操作续期，可分别修改配置。
- 按录入日期倒序分组，同一天按录入顺序编号；搜索保留编号，延期不改变分组和编号。
- 验证码自动刷新并显示倒计时，支持移动端与明暗模式。

## 部署前准备

1. 一个 Cloudflare 账号，以及可用的 Workers、D1 服务。
2. 三个互相独立的机密：`ADMIN_KEY`、`USER_KEY`、`ENCRYPTION_KEY`。
3. 生成随机值。以下命令**分别执行**，保存输出，勿提交到 Git：

```sh
# ADMIN_KEY：至少 32 个字符
openssl rand -hex 32

# USER_KEY：至少 32 个字符，不能与 ADMIN_KEY 相同
openssl rand -hex 32

# ENCRYPTION_KEY：必须是 32 字节随机数据的 Base64 编码
openssl rand -base64 32
```

`ADMIN_KEY` 交给提供方，`USER_KEY` 交给使用方。`ENCRYPTION_KEY` 仅部署者保管，必须单独备份。

## 方式一：Cloudflare 控制台部署

不需要本地安装 Node.js 或 Wrangler，只需仓库中的 `worker.js` 和 `schema.sql`。

1. 在 Cloudflare 控制台进入 **Workers & Pages → Create application**，创建一个 Worker，例如 `github-access`。控制台名称可能随版本略有不同。
2. 打开 Worker 的代码编辑器，将默认代码**全部替换**为本仓库 `worker.js`，保存并部署。使用 ES Module 格式，不要包裹 `addEventListener`。
3. 在 **Storage & databases → D1** 创建数据库，例如 `github-access-db`。
4. 打开数据库的 SQL 控制台，执行 `schema.sql` 全部内容。若控制台不支持一次执行多个语句，逐条执行；成功后应有 `accounts` 和 `login_attempts` 两张表。
5. 回到 Worker，进入 **Bindings → Add binding → D1 database**，变量名填写 **`DB`**，选择刚创建的数据库。
6. 进入 Worker **Settings → Variables and Secrets**，添加以下三个 **Secret**（加密变量），填入刚生成的值：

   | 名称 | 内容 |
   | --- | --- |
   | `ADMIN_KEY` | 管理员登录密钥，至少 32 个字符 |
   | `USER_KEY` | 使用方登录密钥，至少 32 个字符，与管理密钥不同 |
   | `ENCRYPTION_KEY` | 32 字节随机密钥的 Base64 编码 |

7. 保存绑定、机密并重新部署，使新版本生效。若有兼容日期设置，使用 `2026-04-08`；命令行配置也采用该日期，便于兼容已有的 Wrangler 安装。
8. 打开 Worker 的 HTTPS 地址。选择管理员身份，输入 `ADMIN_KEY` 登录并录入测试账号，再退出，使用 `USER_KEY` 验证查看功能。

## 方式二：Wrangler 命令行部署

需要 Node.js **22.13 或更新版本**、npm 和本仓库文件。命令在仓库根目录执行。

```sh
# 登录 Cloudflare
npx wrangler login

# 创建 D1
npx wrangler d1 create github-access-db
```

将输出中的 `database_id` 填入 `wrangler.toml`，替换 `REPLACE_WITH_YOUR_D1_DATABASE_ID`。绑定名保持 `DB`，数据库名称保持与创建结果一致。

```toml
name = "github-access"
main = "worker.js"
compatibility_date = "2026-04-08"
workers_dev = true

[[d1_databases]]
binding = "DB"
database_name = "github-access-db"
database_id = "替换为你的数据库 UUID"
```

初始化远程数据库：

```sh
npx wrangler d1 execute github-access-db --remote --file=schema.sql
```

先发布 Worker，再逐个设置远程 Secrets。设置完成前，页面可以打开，但不能登录。

```sh
npx wrangler deploy
npx wrangler secret put ADMIN_KEY
npx wrangler secret put USER_KEY
npx wrangler secret put ENCRYPTION_KEY
```

每条 `secret put` 命令会提示输入值。三项设置完后，打开部署输出的 HTTPS 地址即可使用。

## 录入和 TXT 导入

管理员点击「录入账号」，将信息粘贴到文本框；也可点击「导入 TXT」读取本地文件，再点击「确认录入」。文件读取后不会自动提交，可先检查内容。

每条账号占**连续三行**：GitHub 用户名、密码、TOTP 种子。记录之间可以有空行，也可以直接连续排列：

```text
github-user-one
password-one
JBSWY3DPEHPK3PXP

github-user-two
password-two
JBSWY3DPEHPK3PXP
```

以上为格式示例，请替换为真实信息。

- TXT 使用 **UTF-8** 编码，支持 BOM、Windows 和 Unix 换行。
- 账号填写 GitHub **用户名**，不是邮箱或网址；账号前后空白会移除。
- 密码前后空格原样保留，不要额外缩进；字段本身不能换行。
- TOTP 填写 Base32 种子，不是当前六位验证码、恢复码或二维码图片。接受大小写和分隔空格；支持 SHA-1、六位数字、30 秒周期。
- 默认每批最多 **100** 条、文本大小 **256 KB**。本次录入的所有账号共用表单中的有效时长，默认 2 小时。
- 任意记录缺失、种子无效或账号重复时，**整批不导入**并提示原因。重复账号判断不区分大小写，已有账号不会被覆盖。
- 管理员需要更换账密或种子时，删除旧记录后重新录入；无需增加额外编辑流程。

## 修改配置

修改 `worker.js` 最顶部的 `CONFIG`，保存并重新部署：

```js
export const CONFIG = Object.freeze({
  DEFAULT_ACCOUNT_HOURS: 2,  // 新录入账号默认有效时长
  EXTEND_HOURS: 2,          // 延期按钮：当前时间 + 此小时数
  ADMIN_SESSION_DAYS: 7,    // 管理员登录有效期，天
  USER_SESSION_DAYS: 7,     // 使用方登录有效期，天
  TIME_ZONE: 'Asia/Shanghai',
  MAX_IMPORT_ACCOUNTS: 100,
  MAX_IMPORT_BYTES: 256 * 1024,
  MAX_REQUEST_BYTES: 512 * 1024,
  MAX_ACCOUNT_HOURS: 24 * 365,
  LOGIN_ATTEMPTS: 10,
  LOGIN_WINDOW_SECONDS: 15 * 60,
});
```

时长应为正数。单次导入上限建议不超过 100，以适配 D1 查询参数限制；增大文本上限时同时调整请求体上限，为 JSON 转义留出余量。

登录时长从成功登录起算；缩短配置会缩短已有会话的实际可用时间，延长配置不会延长已经签发的会话，需要重新登录。账号默认时长仅影响新录入，修改时区仅影响之后录入记录的日期分组，不重排历史记录。

## 本地运行与测试

本地 D1 与远程 D1 相互独立：

```sh
cp .dev.vars.example .dev.vars
```

编辑 `.dev.vars`，将三个占位值替换为真实随机值。该文件已经加入 `.gitignore`，不要上传或提交。

```sh
npx wrangler d1 execute github-access-db --local --file=schema.sql
npx wrangler dev
```

打开 Wrangler 输出的本地地址。会话 Cookie 带有 `Secure`，现代浏览器通常将 `localhost` 视为可信开发环境；若登录后无法保持会话，请使用 `npx wrangler dev --local-protocol https` 并在浏览器中信任本地证书。生产环境始终使用 HTTPS。

测试无需安装依赖：

```sh
npm test
```

测试使用 Node 内置测试工具和 SQLite，覆盖三行解析、真实 SQL 事务回滚、重复检测、TOTP 标准向量、加密、权限、登录有效期、过期验证码和延期规则。Node 22 的 SQLite 模块可能打印实验性警告，不影响测试。

## 数据与密钥维护

- 密码和 TOTP 种子通过 AES-GCM 加密后写入 D1，随机 IV，并绑定账号及字段；用户名和时间信息明文保存。
- TOTP 种子仅在服务端解密生成验证码，查询接口不返回种子。
- 登录通过签名 Cookie 保存，带 `HttpOnly`、`Secure`、`SameSite=Strict`，浏览器本地存储只保存主题选择。
- 敏感接口禁用缓存；写操作校验同源来源；默认每个 IP、每种角色在一个 15 分钟窗口内最多尝试登录 10 次。
- 如需更换登录密钥，控制台修改对应 Secret 或重新运行 `wrangler secret put ADMIN_KEY` / `USER_KEY`；对应角色旧会话将失效。
- 退出会清除当前浏览器 Cookie；如需使所有使用方重新登录，更换 `USER_KEY`。
- **不要直接更换已有数据的 `ENCRYPTION_KEY`**，否则旧数据无法解密。首版不提供加密密钥迁移；确需更换时，先备份原数据库与原密钥，再用原始账号资料重新录入到使用新密钥的空数据库。

备份远程 D1：

```sh
npx wrangler d1 export github-access-db --remote --output=github-access.backup.sql
```

恢复时推荐先创建一个**新 D1 数据库**，将备份导入空库：

```sh
npx wrangler d1 create github-access-restored
npx wrangler d1 execute github-access-restored --remote --file=github-access.backup.sql
```

将 Worker 的 `DB` 绑定切换到恢复后的数据库，同时保留备份对应的 `ENCRYPTION_KEY`，重新部署并验证。备份文件和加密密钥分开保管；恢复确认前保留原数据库。

## 常见问题

| 问题 | 排查方法 |
| --- | --- |
| 服务配置不完整 | 确认 D1 绑定名为 `DB`；两个登录密钥长度至少 32 且不相同；加密密钥是 32 字节随机数据的 Base64 |
| 请求失败，请检查部署配置 | 确认在正确的数据库执行了 `schema.sql`；已有数据时确认加密密钥没有改变 |
| 密钥正确但无法登录 | 确认选择的身份、Secret 名称和部署环境；检查输入是否包含多余空格 |
| 登录尝试过于频繁 | 等待当前限速窗口结束；共享出口 IP 的用户会共用对应角色的额度 |
| 验证码不被接受 | 确认种子属于该账号，采用标准 SHA-1 / 六位 / 30 秒配置，并尝试下一周期验证码 |
| 页面仍显示已删除账号 | 点击刷新；前台页面也会约每分钟同步列表 |
| 复制失败 | 使用 HTTPS 并允许浏览器剪贴板权限 |
| TXT 中文乱码 | 将文件另存为 UTF-8 后重试 |
| 更改了源码但页面没有更新 | 重新部署到正在访问的 Worker；用 Wrangler 部署时确认 `main = "worker.js"` |

## 文件说明

| 文件 | 用途 |
| --- | --- |
| `worker.js` | 唯一运行时源文件，包含页面、接口和配置 |
| `schema.sql` | D1 初始化表和索引，可重复执行 |
| `wrangler.toml` | 命令行部署配置示例 |
| `.dev.vars.example` | 本地 Secrets 格式示例 |
| `test/worker.test.js` | 零第三方依赖测试 |

实现保持最小范围：原生 Web Crypto、内嵌页面和 D1；录入与 TXT 导入复用同一解析流程，未引入前端框架、注册体系或额外存储后端。
