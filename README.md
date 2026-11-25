# sec-header-check

[![CI](https://github.com/lucky-star-konata/sec-header-check/actions/workflows/ci.yml/badge.svg)](https://github.com/lucky-star-konata/sec-header-check/actions/workflows/ci.yml)

一条命令给任意 URL 的 **HTTP 安全响应头**做体检并打分。零依赖，只读，不上传任何数据。

当前版本：**v1.0.0**

## 原理（先看这个）

服务器在 HTTP 响应头里告诉浏览器「该启用哪些安全策略」，浏览器收到页面后会照着执行。所以少一个头，就少一层防线：

| 缺失 / 配置不当 | 浏览器会怎样 | 可能被怎样利用 |
| --- | --- | --- |
| `Strict-Transport-Security`（HSTS） | 不强制走 HTTPS | 首次访问可被降级劫持（SSL stripping） |
| `Content-Security-Policy`（CSP） | 不限制脚本和资源来源 | XSS 影响被放大，任意内联脚本可执行 |
| `X-Content-Type-Options` | 允许 MIME 嗅探 | 用户上传的「图片」被当作脚本执行 |
| `X-Frame-Options` / CSP `frame-ancestors` | 允许被任意页面内嵌 | 点击劫持（诱导用户在隐藏 iframe 上点击） |
| `Referrer-Policy` | 跳转时携带完整来源 URL | 敏感参数通过 `Referer` 泄露给第三方 |
| `Permissions-Policy` | 浏览器 API 默认可请求 | 摄像头、麦克风、定位等能力暴露面变大 |
| `Server` / `X-Powered-By` | 暴露组件与版本号 | 攻击者按版本查找已知漏洞 |

工具做的事情：对目标发**一次普通 GET**，拿到响应头后立刻关闭连接，按下表权重逐项判断、扣分、给出修复建议。**不读取正文、不发送攻击载荷、不登录、不修改任何目标状态。**

## 30 秒上手

```bash
python header_check.py https://example.com
```

Python 3.9+，只用标准库，不需要 `pip install`。

## 输出示例（真实运行）

```text
sec-header-check 1.0.0 · https://example.com
HTTP 200  ·  评分 25/100（F）

[FAIL] HSTS 强制 HTTPS（权重 20）: 未设置
       建议: 建议至少 max-age=15552000；确认全站 HTTPS 后再加 includeSubDomains。
[FAIL] CSP 内容安全策略（权重 20）: 未设置
       建议: 建议设置 default-src 'self'，再按需放开 script/style/img 等来源。
[FAIL] X-Content-Type-Options（权重 10）: 未设置
       建议: 设置为 nosniff，阻止浏览器把非脚本文件当脚本执行。
[FAIL] 防点击劫持（XFO / frame-ancestors）（权重 15）: 未设置
       建议: 建议 X-Frame-Options: DENY 或 SAMEORIGIN，也可用 CSP frame-ancestors。
[WARN] Referrer-Policy（权重 10）: 未设置
       建议: 建议 strict-origin-when-cross-origin 或更严格，减少 URL 参数外泄。
[WARN] Permissions-Policy（权重 10）: 未设置
       建议: 按需关闭不需要的能力，例如 camera=(), microphone=(), geolocation=()。
[PASS] 技术栈指纹暴露（权重 15）: cloudflare

汇总: PASS 1 / WARN 2 / FAIL 4
提示: 评分只反映响应头配置，不代表站点没有漏洞。
```

## 检查项与权重

| 检查项 | 判定标准 | 权重 |
| --- | --- | ---: |
| HSTS | `max-age >= 15552000` 为 PASS，偏小为 WARN，缺失为 FAIL | 20 |
| CSP | 缺失为 FAIL；含 `'unsafe-inline'`、`'unsafe-eval'` 或通配符为 WARN | 20 |
| X-Content-Type-Options | 值为 `nosniff` 才 PASS | 10 |
| 防点击劫持 | CSP `frame-ancestors` 或 `X-Frame-Options: DENY/SAMEORIGIN` | 15 |
| Referrer-Policy | 取严格值之一才 PASS，缺失为 WARN | 10 |
| Permissions-Policy | 存在即 PASS，缺失为 WARN | 10 |
| 技术栈指纹 | 无 `X-Powered-By` 且 `Server` 不含版本号才 PASS | 15 |

## 评分规则

- `FAIL` 扣满权重，`WARN` 扣一半，`PASS` 不扣
- `100 - 扣分` 得到总分：A ≥ 90，B ≥ 75，C ≥ 60，D ≥ 40，F < 40
- 加 `--min-score 80`，评分低于 80 时返回退出码 1，可直接接 CI

## 常用参数

```bash
python header_check.py https://example.com              # 文本报告
python header_check.py https://example.com --json       # JSON，便于二次处理
python header_check.py https://example.com --timeout 5  # 超时秒数
python header_check.py https://example.com --min-score 80
python header_check.py --version
```

JSON 结构：

```json
{
  "url": "https://example.com",
  "final_url": "https://example.com/",
  "status": 200,
  "redirects": [],
  "score": 25,
  "grade": "F",
  "checks": [
    {
      "id": "hsts",
      "title": "HSTS 强制 HTTPS",
      "weight": 20,
      "status": "FAIL",
      "current": "未设置",
      "advice": "建议至少 max-age=15552000；确认全站 HTTPS 后再加 includeSubDomains。"
    }
  ]
}
```

## 退出码

| 码 | 含义 |
| --- | --- |
| 0 | 检查完成 |
| 1 | 评分低于 `--min-score` |
| 2 | URL 或请求错误 |

## 已知局限

- 只检查响应头，**不代表站点没有漏洞**；业务逻辑、鉴权、注入类问题不在范围内
- CDN / WAF 可能重写响应头，结果以实际响应为准
- 跟随 30x 跳转检查最终页面，报告中会显示跳转次数
- 使用系统信任链校验证书，证书错误会直接报错退出

## 免责声明

仅用于**自有或已获得授权**的资产做安全配置自查。工具只读取公开响应头，但请勿对未授权目标批量运行。作者不对未授权使用承担责任。

## License

[MIT](LICENSE)
