#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sec-header-check — 检查一个 URL 的 HTTP 安全响应头并打分。

只发送一次普通 GET，读取响应头后立即关闭连接；不读取正文、不发送攻击载荷、不修改目标状态。

用法:
    python header_check.py https://example.com
    python header_check.py https://example.com --json
    python header_check.py https://example.com --min-score 80
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
VERSION_FILE = ROOT / "VERSION"
USER_AGENT = "Mozilla/5.0 (compatible; sec-header-check/1.0)"
MAX_VALUE_LEN = 120

STATUS_ORDER = {"FAIL": 0, "WARN": 1, "PASS": 2}
STATUS_LABEL = {"FAIL": "FAIL", "WARN": "WARN", "PASS": "PASS"}

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"


def get_version() -> str:
    try:
        return VERSION_FILE.read_text(encoding="utf-8-sig").strip() or "0.0.0"
    except OSError:
        return "0.0.0"


def header_value(headers, name: str):
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def clip(value: str) -> str:
    value = " ".join(str(value).split())
    return value if len(value) <= MAX_VALUE_LEN else value[: MAX_VALUE_LEN - 1] + "…"


def result(check_id, title, weight, status, current, advice=""):
    return {
        "id": check_id,
        "title": title,
        "weight": weight,
        "status": status,
        "current": clip(current) if current else "",
        "advice": advice,
    }


def check_hsts(headers):
    value = header_value(headers, "strict-transport-security")
    if not value:
        return result(
            "hsts", "HSTS 强制 HTTPS", 20, FAIL, "未设置",
            "建议至少 max-age=15552000；确认全站 HTTPS 后再加 includeSubDomains。",
        )
    matched = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
    if not matched:
        return result(
            "hsts", "HSTS 强制 HTTPS", 20, FAIL, value,
            "HSTS 缺少有效 max-age，浏览器不会记住强制 HTTPS 策略。",
        )
    if int(matched.group(1)) < 15552000:
        return result(
            "hsts", "HSTS 强制 HTTPS", 20, WARN, value,
            "max-age 小于 180 天，建议提高到 15552000 以上。",
        )
    return result("hsts", "HSTS 强制 HTTPS", 20, PASS, value)


def check_csp(headers):
    value = header_value(headers, "content-security-policy")
    if not value:
        return result(
            "csp", "CSP 内容安全策略", 20, FAIL, "未设置",
            "建议设置 default-src 'self'，再按需放开 script/style/img 等来源。",
        )
    lowered = value.lower()
    weak = [token for token in ("'unsafe-inline'", "'unsafe-eval'") if token in lowered]
    if weak or re.search(r"(?:^|[;\s])\*(?:\s|;|$)", value):
        return result(
            "csp", "CSP 内容安全策略", 20, WARN, value,
            "策略含 " + "、".join(weak or ["通配符 *"]) + "，会明显削弱拦截 XSS 的效果。",
        )
    return result("csp", "CSP 内容安全策略", 20, PASS, value)


def check_nosniff(headers):
    value = header_value(headers, "x-content-type-options")
    if value and value.strip().lower() == "nosniff":
        return result("nosniff", "X-Content-Type-Options", 10, PASS, value)
    return result(
        "nosniff", "X-Content-Type-Options", 10, FAIL, value or "未设置",
        "设置为 nosniff，阻止浏览器把非脚本文件当脚本执行。",
    )


def check_frame(headers):
    csp = header_value(headers, "content-security-policy") or ""
    if re.search(r"frame-ancestors\s+[^;]+", csp, re.I):
        return result(
            "frame", "防点击劫持（XFO / frame-ancestors）", 15,
            PASS, "CSP frame-ancestors",
        )
    value = header_value(headers, "x-frame-options")
    if not value:
        return result(
            "frame", "防点击劫持（XFO / frame-ancestors）", 15, FAIL, "未设置",
            "建议 X-Frame-Options: DENY 或 SAMEORIGIN，也可用 CSP frame-ancestors。",
        )
    if value.strip().lower() in ("deny", "sameorigin"):
        return result("frame", "防点击劫持（XFO / frame-ancestors）", 15, PASS, value)
    return result(
        "frame", "防点击劫持（XFO / frame-ancestors）", 15, WARN, value,
        "ALLOW-FROM 已被现代浏览器废弃，建议改用 CSP frame-ancestors。",
    )


def check_referrer(headers):
    value = header_value(headers, "referrer-policy")
    if not value:
        return result(
            "referrer", "Referrer-Policy", 10, WARN, "未设置",
            "建议 strict-origin-when-cross-origin 或更严格，减少 URL 参数外泄。",
        )
    strict = {
        "no-referrer", "same-origin", "strict-origin",
        "strict-origin-when-cross-origin",
    }
    first = value.split(",")[0].strip().lower()
    if first in strict:
        return result("referrer", "Referrer-Policy", 10, PASS, value)
    return result(
        "referrer", "Referrer-Policy", 10, WARN, value,
        "当前策略仍可能泄露路径或查询参数，建议收紧。",
    )


def check_permissions(headers):
    value = header_value(headers, "permissions-policy")
    if value:
        return result("permissions", "Permissions-Policy", 10, PASS, value)
    return result(
        "permissions", "Permissions-Policy", 10, WARN, "未设置",
        "按需关闭不需要的能力，例如 camera=(), microphone=(), geolocation=()。",
    )


def check_disclosure(headers):
    powered = header_value(headers, "x-powered-by")
    server = header_value(headers, "server") or ""
    if powered:
        return result(
            "disclosure", "技术栈指纹暴露", 15, WARN, f"X-Powered-By: {powered}",
            "移除 X-Powered-By，减少攻击者定位组件的线索。",
        )
    if re.search(r"\d+\.\d+", server):
        return result(
            "disclosure", "技术栈指纹暴露", 15, WARN, f"Server: {server}",
            "隐藏 Server 中的版本号，降低被针对性利用的风险。",
        )
    return result("disclosure", "技术栈指纹暴露", 15, PASS, server or "未暴露")


CHECKS = (
    check_hsts,
    check_csp,
    check_nosniff,
    check_frame,
    check_referrer,
    check_permissions,
    check_disclosure,
)


def grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def score_checks(checks):
    penalty = 0.0
    for item in checks:
        if item["status"] == FAIL:
            penalty += item["weight"]
        elif item["status"] == WARN:
            penalty += item["weight"] / 2
    return max(0, int(round(100 - penalty)))


class _RedirectRecorder(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append({"status": code, "url": newurl})
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("只支持 http:// 或 https:// 开头的完整 URL")
    return url


def fetch_headers(url: str, timeout: int):
    recorder = _RedirectRecorder()
    opener = urllib.request.build_opener(recorder)
    request = urllib.request.Request(url, method="GET", headers={
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Encoding": "identity",
    })
    with opener.open(request, timeout=timeout) as response:
        return {
            "status": getattr(response, "status", None) or response.getcode(),
            "final_url": response.geturl(),
            "headers": response.headers,
            "redirects": recorder.chain,
        }


def print_text(report):
    print(f"sec-header-check {get_version()} · {report['url']}")
    final = report["final_url"]
    if final != report["url"]:
        print(f"最终地址: {final}（跳转 {len(report['redirects'])} 次）")
    print(f"HTTP {report['status']}  ·  评分 {report['score']}/100（{report['grade']}）\n")

    for item in report["checks"]:
        print(f"[{item['status']}] {item['title']}（权重 {item['weight']}）: {item['current']}")
        if item["advice"]:
            print(f"       建议: {item['advice']}")

    counts = {status: 0 for status in STATUS_ORDER}
    for item in report["checks"]:
        counts[item["status"]] += 1
    print(
        f"\n汇总: PASS {counts['PASS']} / WARN {counts['WARN']} / FAIL {counts['FAIL']}"
    )
    print("提示: 评分只反映响应头配置，不代表站点没有漏洞。")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="检查 HTTP 安全响应头并打分")
    parser.add_argument("url", help="目标 URL，如 https://example.com")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时秒数，默认 10")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--min-score", type=int, help="评分低于该值时返回退出码 1，便于 CI 门禁")
    parser.add_argument("--version", action="version", version=f"%(prog)s {get_version()}")
    args = parser.parse_args(argv)

    try:
        url = validate_url(args.url)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    try:
        response = fetch_headers(url, args.timeout)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as exc:
        print(f"[!] 请求失败: {exc}", file=sys.stderr)
        return 2

    checks = [check(response["headers"]) for check in CHECKS]
    checks.sort(key=lambda item: STATUS_ORDER[item["status"]])
    score = score_checks(checks)
    report = {
        "url": url,
        "final_url": response["final_url"],
        "status": response["status"],
        "redirects": response["redirects"],
        "score": score,
        "grade": grade(score),
        "checks": checks,
    }

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_text(report)

    if args.min_score is not None and score < args.min_score:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    raise SystemExit(main())
