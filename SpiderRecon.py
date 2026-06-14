"""
SpiderRecon v1.0 - Android APK
Bug Bounty Automation Tool
By: Youssef Ashraf (محوّل من Bash to Python/Kivy)
"""

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelItem
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.scrollview import ScrollView
from kivy.uix.popup import Popup
from kivy.uix.progressbar import ProgressBar
from kivy.clock import Clock
from kivy.utils import platform
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.core.clipboard import Clipboard
import threading
import json
import os
import sys
import time
import urllib.request
import urllib.error
import ssl
import socket
import re
import hashlib
from datetime import datetime

# ============================================================
#  CORE LOGIC - SpiderRecon Engine
# ============================================================

class SpiderReconEngine:
    """ده قلب التطبيق — نفس منطق سكريبتك الأصلي لكن بـ Python خالص"""

    def __init__(self, domain, callback=None):
        self.domain = domain.strip().lower()
        self.callback = callback  # function(status, message, data)
        self.results = {
            "subdomains": [],
            "live_hosts": [],
            "ports": {},
            "urls": [],
            "params_urls": [],
            "vulnerabilities": [],
            "secrets": [],
            "js_files": [],
            "status_codes": {},
            "technologies": [],
            "cves": [],
            "report": ""
        }
        self.running = False
        self._stop = False

    def _update(self, phase, message, data=None):
        if self.callback:
            Clock.schedule_once(lambda dt: self.callback(phase, message, data))

    def stop(self):
        self._stop = True

    # -------------------------------------------------------
    #  PHASE 1: Subdomain Enumeration (APIs مجانية)
    # -------------------------------------------------------
    def enum_subdomains(self):
        self._update("subdomains", "🔍 جاري البحث عن الـ subdomains...")
        subs = set()

        # 1. crt.sh
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Linux; Android 14)"
            })
            resp = urllib.request.urlopen(req, timeout=30, context=ctx)
            data = json.loads(resp.read().decode())
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().replace("*.", "").replace("www.", "")
                    if n.endswith(self.domain) and n != self.domain:
                        subs.add(n)
            self._update("subdomains", f"  ✓ crt.sh: {len(subs)} found")
        except Exception as e:
            self._update("subdomains", f"  ⚠ crt.sh: {str(e)[:50]}")

        # 2. HackerTarget (مجاني بدون API key)
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Linux; Android 14)"
            })
            resp = urllib.request.urlopen(req, timeout=30)
            data = resp.read().decode()
            for line in data.strip().split("\n"):
                if "," in line:
                    sub = line.split(",")[0].strip()
                    if sub.endswith(self.domain):
                        subs.add(sub)
            self._update("subdomains", f"  ✓ HackerTarget: more found")
        except:
            pass

        # 3. RapidDNS.io
        try:
            url = f"https://rapiddns.io/subdomains/{self.domain}?full=1"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Linux; Android 14)"
            })
            resp = urllib.request.urlopen(req, timeout=30)
            html = resp.read().decode()
            found = re.findall(r'<td>([\w.-]+\.' + re.escape(self.domain) + r')</td>', html)
            for f in found:
                subs.add(f)
        except:
            pass

        # 4. AlienVault OTX
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Linux; Android 14)"
            })
            resp = urllib.request.urlopen(req, timeout=30)
            data = json.loads(resp.read().decode())
            for entry in data.get("passive_dns", []):
                host = entry.get("hostname", "")
                if host.endswith(self.domain):
                    subs.add(host)
        except:
            pass

        # 5. URLScan.io
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=100"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Linux; Android 14)"
            })
            resp = urllib.request.urlopen(req, timeout=30)
            data = json.loads(resp.read().decode())
            for result in data.get("results", []):
                page = result.get("page", {})
                dom = page.get("domain", "")
                if dom.endswith(self.domain):
                    subs.add(dom)
        except:
            pass

        self.results["subdomains"] = sorted(subs)
        self._update("subdomains", f"✅ إجمالي subdomains: {len(subs)}", list(subs)[:50])

    # -------------------------------------------------------
    #  PHASE 2: Port Scanning (TCP Sockets خفيف)
    # -------------------------------------------------------
    def scan_ports(self, hosts):
        self._update("ports", "🔍 جاري فحص المنافذ...")
        COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                       993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 
                       5900, 5985, 5986, 6379, 8080, 8443, 9090, 27017]
        results = {}
        
        for host in hosts[:5]:  # أول 5 hosts بس عشان السرعة
            hostname = host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            open_ports = []
            for port in COMMON_PORTS:
                if self._stop:
                    return
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    result = s.connect_ex((hostname, port))
                    s.close()
                    if result == 0:
                        open_ports.append(port)
                except:
                    pass
            if open_ports:
                results[hostname] = open_ports
        
        self.results["ports"] = results
        total = sum(len(v) for v in results.values())
        self._update("ports", f"✅ {total} منفذ مفتوح (في {len(results)} host)")

    # -------------------------------------------------------
    #  PHASE 3: HTTP Probing
    # -------------------------------------------------------
    def probe_hosts(self):
        self._update("live", "🔍 جاري فحص المواقع النشطة...")
        live = []
        
        for sub in self.results["subdomains"][:50]:  # أول 50
            if self._stop:
                break
            for proto in ["https", "http"]:
                try:
                    url = f"{proto}://{sub}"
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    req = urllib.request.Request(url, headers={
                        "User-Agent": "Mozilla/5.0 (Linux; Android 14)"
                    })
                    resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                    code = resp.getcode()
                    if code and code < 500:
                        live.append(url)
                        self.results["status_codes"][url] = code
                        # كشف التقنيات من headers
                        server = resp.headers.get("Server", "")
                        if server:
                            self.results["technologies"].append(server)
                        break
                except:
                    continue
        
        self.results["live_hosts"] = live
        self._update("live", f"✅ {len(live)} موقع نشط")

    # -------------------------------------------------------
    #  PHASE 4: URL Collection (Wayback + CommonCrawl APIs)
    # -------------------------------------------------------
    def collect_urls(self):
        self._update("urls", "🔍 جاري جمع الـ URLs...")
        urls = set()
        
        # Wayback Machine
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Linux; Android 14)"
            })
            resp = urllib.request.urlopen(req, timeout=60)
            data = json.loads(resp.read().decode())
            for entry in data[1:]:  # أول entry هو header
                if entry:
                    urls.add(entry[0])
            self._update("urls", f"  ✓ Wayback: {len(urls)}")
        except:
            pass

        # CommonCrawl
        try:
            url = f"https://index.commoncrawl.org/CC-MAIN-2024-18-index?url=*.{self.domain}&output=json&limit=5000"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Linux; Android 14)"
            })
            resp = urllib.request.urlopen(req, timeout=60)
            for line in resp.read().decode().strip().split("\n"):
                try:
                    entry = json.loads(line)
                    u = entry.get("url", "")
                    if u and self.domain in u:
                        urls.add(u)
                except:
                    pass
        except:
            pass

        self.results["urls"] = sorted(urls)
        self._update("urls", f"✅ إجمالي URLs: {len(urls)}")

        # استخراج اللي فيه parameters
        params_urls = [u for u in urls if "?" in u and "=" in u]
        self.results["params_urls"] = sorted(params_urls)
        self._update("params", f"✅ URLs مع parameters: {len(params_urls)}")

    # -------------------------------------------------------
    #  PHASE 5: JS Analysis
    # -------------------------------------------------------
    def analyze_js(self):
        self._update("js", "🔍 جاري تحليل ملفات JS...")
        js_files = set()
        secrets = []
        
        for u in self.results["urls"][:200]:
            if ".js" in u.lower() and u.endswith((".js", ".js?")):
                js_files.add(u)
        
        # فحص أول 30 JS file
        for js_url in list(js_files)[:30]:
            if self._stop:
                break
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(js_url, headers={
                    "User-Agent": "Mozilla/5.0"
                })
                resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                content = resp.read().decode("utf-8", errors="ignore")
                
                # بحث عن endpoints
                endpoints = re.findall(r'(https?://[a-zA-Z0-9._/?=&%#@:;-]+)', content)
                for ep in endpoints[:10]:
                    if self.domain in ep:
                        secrets.append(f"[ENDPOINT] {js_url} → {ep}")
                
                # بحث عن keys/secrets
                patterns = [
                    r'(?:api[_-]?key|apikey|secret|token|password|passwd|access[_-]?key|auth[_-]?token)["\s:=]+["\']?([A-Za-z0-9+/=_-]{10,})["\']?',
                    r'(?:AKIA[0-9A-Z]{16})',  # AWS key
                    r'(?:ghp_[a-zA-Z0-9]{36})',  # GitHub token
                ]
                for pat in patterns:
                    matches = re.findall(pat, content, re.IGNORECASE)
                    for m in matches:
                        secrets.append(f"[SECRET] {js_url} → {m[:50]}")
            except:
                pass
        
        self.results["js_files"] = sorted(js_files)
        self.results["secrets"] = secrets
        self._update("js", f"✅ {len(js_files)} JS files, {len(secrets)} secrets محتملة")

    # -------------------------------------------------------
    #  PHASE 6: Vulnerability Detection
    # -------------------------------------------------------
    def detect_vulnerabilities(self):
        self._update("vuln", "🔍 جاري فحص الثغرات...")
        vulns = []

        for url in self.results["params_urls"][:100]:
            if self._stop:
                break
            
            # 1. SQL Injection test (basic)
            sqli_payloads = ["'", "\"", "1=1", "1'='1", "' OR '1'='1"]
            for payload in sqli_payloads:
                test_url = url.replace("=", f"={payload}", 1) if "=" in url else f"{url}{payload}"
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    req = urllib.request.Request(test_url, headers={
                        "User-Agent": "Mozilla/5.0"
                    })
                    resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                    body = resp.read().decode("utf-8", errors="ignore").lower()
                    # كشف errors
                    if any(err in body for err in ["sql", "mysql", "syntax error", "unclosed quotation", "odbc"]):
                        vulns.append(f"[SQLi] {test_url}")
                        break
                except:
                    pass

            # 2. XSS test (basic reflected)
            xss_payload = "<script>alert(1)</script>"
            if "=" in url:
                test_url = url.split("=")[0] + f"={xss_payload}"
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    req = urllib.request.Request(test_url, headers={
                        "User-Agent": "Mozilla/5.0"
                    })
                    resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                    body = resp.read().decode("utf-8", errors="ignore")
                    if xss_payload in body:
                        vulns.append(f"[XSS] {test_url}")
                except:
                    pass

            # 3. LFI test
            lfi_payloads = ["../../../etc/passwd", "....//....//....//etc/passwd"]
            for payload in lfi_payloads:
                if "=" in url:
                    test_url = url.split("=")[0] + f"={payload}"
                    try:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        req = urllib.request.Request(test_url, headers={
                            "User-Agent": "Mozilla/5.0"
                        })
                        resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                        body = resp.read().decode("utf-8", errors="ignore")
                        if "root:" in body or "bin/bash" in body:
                            vulns.append(f"[LFI] {test_url}")
                            break
                    except:
                        pass

        self.results["vulnerabilities"] = vulns
        self._update("vuln", f"✅ {len(vulns)} ثغرة محتملة")

    # -------------------------------------------------------
    #  PHASE 7: Generate Report
    # -------------------------------------------------------
    def generate_report(self):
        self._update("report", "📄 جاري إنشاء التقرير...")
        
        elapsed = time.time() - self._start_time
        report = []
        report.append("=" * 50)
        report.append("        SPIDERRECON - تقرير الفحص")
        report.append("=" * 50)
        report.append(f"الهدف        : {self.domain}")
        report.append(f"التاريخ      : {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        report.append(f"المدة        : {int(elapsed//60)}د {int(elapsed%60)}ث")
        report.append("")
        
        report.append("── نتائج المسح ─────────────────────────────────")
        report.append(f"  Subdomains        : {len(self.results['subdomains'])}")
        report.append(f"  Live Hosts         : {len(self.results['live_hosts'])}")
        report.append(f"  Open Ports         : {sum(len(v) for v in self.results['ports'].values())}")
        report.append(f"  URLs               : {len(self.results['urls'])}")
        report.append(f"  URLs مع Parameters : {len(self.results['params_urls'])}")
        report.append(f"  JS Files           : {len(self.results['js_files'])}")
        report.append(f"  Secrets            : {len(self.results['secrets'])}")
        report.append(f"  ثغرات             : {len(self.results['vulnerabilities'])}")
        report.append("")
        
        if self.results["vulnerabilities"]:
            report.append("── الثغرات المكتشفة ───────────────────────────")
            for v in self.results["vulnerabilities"][:30]:
                report.append(f"  ⚠ {v}")
            report.append("")
        
        if self.results["live_hosts"]:
            report.append("── المواقع النشطة ─────────────────────────────")
            for h in self.results["live_hosts"][:20]:
                code = self.results["status_codes"].get(h, "")
                report.append(f"  {h} [{code}]")
            report.append("")
        
        report.append("=" * 50)
        report.append("  SpiderRecon v1.0 - Mobile Edition")
        report.append("  تم الفحص بنجاح ✅")
        
        self.results["report"] = "\n".join(report)
        self._update("report", "✅ تم إنشاء التقرير", self.results["report"])

    # -------------------------------------------------------
    #  MAIN RUN
    # -------------------------------------------------------
    def run(self):
        self.running = True
        self._start_time = time.time()
        self._stop = False
        
        self._update("status", "🕷️ بدء SpiderRecon...")
        
        # Phase 1: Subdomains
        self.enum_subdomains()
        if self._stop: return
        
        # Phase 2: Ports (على أخذ عينة من subdomains)
        if self.results["subdomains"]:
            self.scan_ports(self.results["subdomains"][:5])
        if self._stop: return
        
        # Phase 3: Probe
        self.probe_hosts()
        if self._stop: return
        
        # Phase 4: URLs
        self.collect_urls()
        if self._stop: return
        
        # Phase 5: JS
        self.analyze_js()
        if self._stop: return
        
        # Phase 6: Vulns
        self.detect_vulnerabilities()
        if self._stop: return
        
        # Phase 7: Report
        self.generate_report()
        
        self.running = False
        self._update("status", "✅ اكتمل الفحص!")


# ============================================================
#  KIVY UI - واجهة التطبيق
# ============================================================

class SpiderReconUI(BoxLayout):
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.engine = None
        self.orientation = 'vertical'
        
    def start_scan(self):
        domain = self.ids.domain_input.text.strip()
        if not domain:
            self.show_popup("خطأ", "من فضلك أدخل الدومين")
            return
        
        # إعادة تعيين النتائج
        self.ids.status_label.text = "🕷️ جاري التجهيز..."
        self.ids.subs_count.text = "0"
        self.ids.live_count.text = "0"
        self.ids.urls_count.text = "0"
        self.ids.vuln_count.text = "0"
        self.ids.results_text.text = ""
        self.ids.report_text.text = ""
        self.ids.progress_bar.value = 0
        self.ids.start_btn.disabled = True
        self.ids.start_btn.text = "⏳ جاري المسح..."
        
        # بدء المسح في thread منفصل
        self.engine = SpiderReconEngine(domain, self.update_callback)
        threading.Thread(target=self.engine.run, daemon=True).start()
    
    def update_callback(self, phase, message, data=None):
        """تحديث الواجهة من الـ engine"""
        
        if phase == "status":
            self.ids.status_label.text = message
        elif phase == "subdomains":
            if "إجمالي" in message or "✓" in message:
                self.ids.status_label.text = message
            if "إجمالي" in message:
                self.ids.subs_count.text = str(len(self.engine.results["subdomains"]))
        elif phase == "live":
            self.ids.status_label.text = message
            self.ids.live_count.text = str(len(self.engine.results["live_hosts"]))
        elif phase == "urls":
            self.ids.status_label.text = message
            self.ids.urls_count.text = str(len(self.engine.results["urls"]))
        elif phase == "vuln":
            self.ids.status_label.text = message
            self.ids.vuln_count.text = str(len(self.engine.results["vulnerabilities"]))
            # عرض الثغرات
            if self.engine.results["vulnerabilities"]:
                results = "🔴 الثغرات المكتشفة:\n\n"
                for v in self.engine.results["vulnerabilities"][:30]:
                    results += f"⚠️ {v}\n"
                self.ids.results_text.text = results
        elif phase == "report" and data:
            self.ids.report_text.text = data
        elif phase == "status" and "اكتمل" in message:
            self.ids.status_label.text = message
            self.ids.progress_bar.value = 100
            self.ids.start_btn.disabled = False
            self.ids.start_btn.text = "🔄 فحص جديد"
        elif phase == "js":
            self.ids.status_label.text = message
    
    def copy_report(self):
        if self.ids.report_text.text:
            Clipboard.copy(self.ids.report_text.text)
            self.show_popup("تم", "تم نسخ التقرير")
    
    def show_popup(self, title, message):
        popup = Popup(
            title=title,
            content=Label(text=message, size_hint_y=None, height=dp(200), 
                         text_size=(dp(280), None), halign='center'),
            size_hint=(0.8, 0.4),
            auto_dismiss=True
        )
        popup.open()


# ============================================================
#  APP
# ============================================================

class SpiderReconApp(App):
    def build(self):
        self.title = "SpiderRecon"
        return SpiderReconUI()

if __name__ == "__main__":
    SpiderReconApp().run()
