# Typecho Passkey 登录插件

一个为 Typecho 博客系统添加 Passkey (WebAuthn/FIDO2) 登录功能的插件。

## 功能特性

- ✅ 使用 Passkey 免密码登录
- ✅ 每个账户支持多个 Passkey
- ✅ Passkey 重命名管理
- ✅ 安全标准实现（WebAuthn Level 1）
- ✅ 支持 Windows Hello、Touch ID、Android 指纹等生物识别
- ✅ 支持安全密钥（YubiKey 等）

## 系统要求

- Typecho 1.2.0+ 
- PHP 7.3+
  - 必需：openssl 扩展
  - 推荐：sodium 扩展 (PHP 7.2+ 内置)
- MySQL 5.7+ / PostgreSQL / SQLite
- HTTPS（Passkey 功能强制要求；HTTP 请求会被拒绝）
- 现代浏览器（Chrome 67+、Firefox 60+、Safari 13+、Edge 79+）

## 安装步骤

1. **下载插件**
   ```bash
   git clone https://github.com/your-repo/typecho-passkey.git
   ```

2. **复制插件到 Typecho 插件目录**
   ```bash
   cp -r typecho-passkey /path/to/typecho/usr/plugins/Passkey
   ```

3. **启用插件**
   - 登录 Typecho 后台
   - 进入「控制台」→「插件」
   - 找到「Passkey」，点击「启用」

4. **注册 Passkey**
   - 进入「控制台」→「Passkey 管理」
   - 点击「注册新 Passkey」
   - 输入名称（如「我的 iPhone」「办公室电脑」）
   - 按提示完成生物识别

## 使用方法

### 登录

1. 访问 Typecho 登录页面 (`/admin/login.php`)
2. 点击「🔑 使用 Passkey 登录」按钮
3. 使用您的设备完成生物识别（指纹/面部/密码）
4. 自动登录后台

### 管理 Passkey

1. 登录后台
2. 进入「控制台」→「Passkey 管理」
3. 查看已注册的 Passkey 列表
4. 可以重命名或删除 Passkey

## 文件结构

```
Passkey/
├── LICENSE                 # Apache License 2.0
├── README.md               # 本文档
├── AGENTS.md               # 开发约定（开发者优先阅读）
├── Plugin.php              # 插件主入口
├── Passkey_Auth.php        # 认证 Action
├── Passkey_Register.php    # 注册 Action
├── Passkey_Delete.php      # 删除 Action
├── Passkey_Rename.php      # 重命名 Action
├── admin/
│   └── passkey.php         # 管理页面
├── assets/
│   └── js/
│       └── passkey.js      # 前端 WebAuthn 处理
└── Utils/
    ├── Crypto.php          # 加密工具类 (Sodium/OpenSSL)
    └── WebAuthn.php        # WebAuthn 工具类
```

## 开发约定

开发新功能时请先阅读 [AGENTS.md](AGENTS.md)，了解项目编码规范、安全要求和最佳实践。

> 💡 **提示**: 如果 `AGENTS.local.md` 文件存在，请优先遵循该文件中的约定。

## 技术细节

### 安全特性

- **随机数**：使用 Sodium 或 PHP CSPRNG 生成挑战
- **签名验证**：使用 OpenSSL 验证 ECDSA P-256 (ES256)
- **挑战 - 响应**：挑战绑定会话、五分钟过期且只能使用一次
- **来源校验**：验证 HTTPS Origin、RP ID 和用户验证标志
- **注册格式**：接受 ES256 公钥和 `none` attestation
- **计数器验证**：检测并阻止克隆 Authenticator
- **HTTPS 强制**：HTTP 站点配置和非 HTTPS 同源请求都会被拒绝

### 数据存储

Passkey 信息存储在 `typecho_passkeys` 表中：

| 字段 | 类型 | 说明 |
|------|------|------|
| id | INT | 自增 ID |
| uid | INT | 用户 ID |
| credential_id | VARCHAR(255) | WebAuthn 凭证 ID |
| public_key | TEXT | PEM 格式的 P-256 公钥 |
| name | VARCHAR(255) | 用户自定义名称 |
| counter | BIGINT | 签名计数器 |
| created_at | INT | 创建时间戳 |
| last_used_at | INT | 最后使用时间戳 |

## 注意事项

1. **HTTPS 要求**：Passkey 功能始终要求 HTTPS；HTTP 和 localhost 明文 HTTP 均不允许
2. **浏览器兼容**：确保用户使用支持 WebAuthn 的现代浏览器
3. **备份 Passkey**：建议用户注册多个 Passkey 以防设备丢失
4. **备用登录**：保留密码登录作为备用方案

## 安全建议

1. 始终使用 HTTPS
2. 定期备份数据库
3. 监控异常登录尝试
4. 为用户提供 Passkey 安全教育

## 故障排除

### 点击按钮无反应
- 检查浏览器是否支持 WebAuthn（访问 https://webauthn.io 测试）
- 确认浏览器已启用生物识别/安全密钥权限

### 注册失败
- 检查 HTTPS 配置
- 确认服务器时间准确
- 查看浏览器控制台错误

### 登录失败
- 确认使用的是已注册的 Passkey
- 检查计数器同步问题（尝试重新注册）

## 开发计划

- [ ] 支持多设备同步 Passkey
- [ ] 批量管理功能
- [ ] 登录日志记录
- [ ] 管理员强制用户绑定 Passkey
- [ ] 支持 Attestation 格式验证

# 最终版本测试报告

## 测试结果

```
=== Typecho Passkey 加密库检测 ===

1. Sodium 扩展检测:
   ✅ Sodium 已启用
   版本：1.0.17

2. OpenSSL 扩展检测:
   ✅ OpenSSL 已启用
   版本：OpenSSL 1.1.1b  26 Feb 2019

3. 功能测试:
   ✅ 随机数生成 - Sodium 原生
   ✅ 哈希生成 - Blake2b
   ✅ HMAC 生成 - Sodium CryptoAuth

4. 核心功能:
   ✅ Base64Url 编解码
   ✅ COSE <-> PEM 转换
   ✅ 签名验证 (Sodium → OpenSSL 降级)

系统状态：🎉 优先使用 Sodium，自动降级 OpenSSL
```

## 文件清单

- ✅ `Utils/Crypto.php` - 统一加密接口（Sodium 优先）
- ✅ `Utils/WebAuthn.php` - WebAuthn 工具类
- ✅ `Passkey_Auth.php` - 认证逻辑
- ✅ `Passkey_Register.php` - 注册逻辑
- ✅ `Passkey_Delete.php` - 删除管理
- ✅ `Passkey_Rename.php` - 重命名管理
- ✅ `Plugin.php` - 插件入口
- ✅ `admin/passkey.php` - 管理页面
- ✅ `assets/js/passkey.js` - 前端 WebAuthn

全部通过 PHP 语法检查 ✅

---

## 许可证

Apache License 2.0

Copyright [2024] [Passkey Plugin Authors]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## 致谢

- Typecho 团队
- WebAuthn 规范贡献者
- libsodium 和 OpenSSL 项目
- **中国科技云（China Science and Technology Cloud, CSTCloud）** 提供的大语言模型接口服务支持