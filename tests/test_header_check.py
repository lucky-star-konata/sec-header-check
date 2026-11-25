import http.server
import json
import subprocess
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
SCRIPT = ROOT / "header_check.py"

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class Handler(http.server.BaseHTTPRequestHandler):
    def version_string(self):
        # 默认会带 Python 版本号，这里固定成无版本字符串，避免影响指纹检查
        return "test-server"

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return
        self.send_response(200)
        for key, value in self.server.extra_headers.items():
            self.send_header(key, value)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<html>ok</html>")

    def log_message(self, *args):
        pass


class HeaderCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def url(self, path="/"):
        return f"http://127.0.0.1:{self.port}{path}"

    def run_cli(self, *args):
        return subprocess.run(
            [PY, str(SCRIPT), *args], cwd=ROOT, capture_output=True,
            text=True, encoding="utf-8", errors="replace",
        )

    def test_all_headers_present(self):
        self.server.extra_headers = GOOD_HEADERS
        result = self.run_cli(self.url())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("评分 100/100", result.stdout)
        self.assertIn("FAIL 0", result.stdout)
        self.assertIn("PASS 7", result.stdout)

    def test_missing_headers_lower_score(self):
        self.server.extra_headers = {}
        result = self.run_cli(self.url())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("评分 25/100", result.stdout)
        self.assertIn("FAIL 4", result.stdout)

    def test_frame_ancestors_satisfies_clickjacking(self):
        self.server.extra_headers = {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
        }
        result = self.run_cli(self.url(), "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        frame = next(item for item in payload["checks"] if item["id"] == "frame")
        self.assertEqual(frame["status"], "PASS")

    def test_json_shape(self):
        self.server.extra_headers = GOOD_HEADERS
        result = self.run_cli(self.url(), "--json")
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], 200)
        self.assertEqual(len(payload["checks"]), 7)
        self.assertEqual(payload["grade"], "A")
        self.assertIn("final_url", payload)

    def test_redirect_recorded(self):
        self.server.extra_headers = GOOD_HEADERS
        result = self.run_cli(self.url("/redirect"), "--json")
        payload = json.loads(result.stdout)
        self.assertEqual(len(payload["redirects"]), 1)
        self.assertEqual(payload["final_url"], self.url("/"))

    def test_min_score_gate(self):
        self.server.extra_headers = {}
        result = self.run_cli(self.url(), "--min-score", "80")
        self.assertEqual(result.returncode, 1)

    def test_rejects_non_http_scheme(self):
        result = self.run_cli("ftp://example.com")
        self.assertEqual(result.returncode, 2)
        self.assertIn("http", result.stderr)

    def test_version(self):
        result = self.run_cli("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("1.0.0", result.stdout)


if __name__ == "__main__":
    unittest.main()
