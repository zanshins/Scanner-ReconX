#!/usr/bin/env python3
# =======================
#   ReconX - v 1.0
#   telegram : @zanshin_channel
# =======================

import requests, socket, ssl, os, sys, re, json, time, random
import threading, datetime, concurrent.futures, struct
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse, urlencode
from typing import Optional, List, Dict, Set
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
    VERSION   = "1.0"
    TIMEOUT   = 8
    THREADS   = 40
    DELAY     = 0.0
    RETRY     = 2
    LOG_DIR   = "reconx_logs"

    UA_LIST = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.2478.67 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
        "curl/8.7.1",
    ]

    
    BYPASS_HEADERS = [
        {"X-Forwarded-For":"127.0.0.1","X-Real-IP":"127.0.0.1","X-Custom-IP-Authorization":"127.0.0.1"},
        {"X-Originating-IP":"127.0.0.1","X-Remote-IP":"127.0.0.1","X-Remote-Addr":"127.0.0.1"},
        {"X-Forwarded-Host":"localhost","X-Host":"127.0.0.1","Forwarded":"for=127.0.0.1"},
        {"X-Original-URL":"/","X-Rewrite-URL":"/","X-Override-URL":"/"},
        {"CF-Connecting-IP":"127.0.0.1","True-Client-IP":"127.0.0.1","Fastly-Client-IP":"127.0.0.1"},
        {"Referer":"https://localhost/","Origin":"https://localhost"},
        {"X-WAF-Bypass":"1","X-Security-Token":"bypass","X-Auth-Token":"null"},
        {"Accept-Encoding":"identity","Cache-Control":"no-cache","Pragma":"no-cache"},
    ]


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


# ── Smart Request Engine ───────
class Engine:
    """
    Auto-bypass: on 403/429/503 automatically retries with rotated
    headers, different UA, path variants – transparent to callers.
    """
    def __init__(self, proxy=None, timeout=Config.TIMEOUT, delay=Config.DELAY, threads=Config.THREADS):
        self.proxy   = {"http":proxy,"https":proxy} if proxy else None
        self.timeout = timeout
        self.delay   = delay
        self.threads = threads
        self.sess    = requests.Session()
        self._cnt    = 0
        self._lk     = threading.Lock()

    def _base_headers(self) -> dict:
        return {
            "User-Agent": random.choice(Config.UA_LIST),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

    def get(self, url: str, method="GET", extra_headers=None, stream=False) -> Optional[requests.Response]:
        if self.delay:
            time.sleep(self.delay + random.uniform(0, self.delay*0.5))
        h = self._base_headers()
        if extra_headers:
            h.update(extra_headers)

        for attempt in range(Config.RETRY + 1):
            try:
                r = self.sess.request(
                    method, url, headers=h, timeout=self.timeout,
                    allow_redirects=True, proxies=self.proxy,
                    verify=False, stream=stream
                )
                with self._lk: self._cnt += 1

                
                if r.status_code in (403, 429, 503) and attempt < Config.RETRY:
                    bypass_h = h.copy()
                    bypass_h.update(random.choice(Config.BYPASS_HEADERS))
                    bypass_h["User-Agent"] = random.choice(Config.UA_LIST)
                    time.sleep(0.3)
                    r2 = self.sess.request(
                        method, url, headers=bypass_h, timeout=self.timeout,
                        allow_redirects=True, proxies=self.proxy, verify=False
                    )
                    if r2.status_code == 200:
                        return r2
                return r
            except requests.exceptions.SSLError:
                h["X-Forwarded-Proto"] = "http"
                continue
            except requests.exceptions.TooManyRedirects:
                return None
            except requests.exceptions.RequestException:
                if attempt < Config.RETRY:
                    time.sleep(0.5)
        return None

    @property
    def count(self): return self._cnt


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

{C.E}{C.Y}       scanner tool v1.0{C.E}
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
                "Referrer-Policy","Permissions-Policy","X-XSS-Protection"]
        return {k: k in h for k in keys}

    def _tech(self, resp) -> list:
        txt = resp.text.lower()
        hdr = {k.lower():v.lower() for k,v in resp.headers.items()}
        pats = {
            "WordPress":["wp-content","wp-includes"],
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
             "Wix":["wix.com"],"Squarespace":["squarespace"]}
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
        for p in ["/sitemap.xml","/sitemap_index.xml"]:
            r = self.engine.get(f"{self.url}{p}")
            if r and r.status_code==200:
                return re.findall(r'<loc>(.*?)</loc>', r.text)
        return []


# ═════════════
#  MODULE 2 – ADMIN PANEL FINDER
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
    ],
    "WordPress": [
        "/wp-admin","/wp-login.php","/wp-admin/","/wp-login",
        "/wp-admin/setup-config.php","/wp-admin/admin-ajax.php",
        "/wp-admin/options-general.php","/wp-admin/user-new.php",
        "/wordpress/wp-admin","/wordpress/wp-login.php","/blog/wp-admin",
        "/wp-admin/admin.php","/wp-json/wp/v2/users",
    ],
    "Joomla": [
        "/administrator","/administrator/index.php","/administrator/login.php",
        "/joomla/administrator","/joomla/administrator/index.php",
        "/cms/administrator","/administrator/manifests",
    ],
    "Drupal": [
        "/user/login","/admin/config","/admin/content","/admin/people",
        "/admin/reports","/admin/structure","/drupal/admin",
        "/drupal/user/login",
    ],
    "Magento": [
        "/admin","/adminhtml","/admin123","/magento/admin",
        "/index.php/admin","/store/admin","/shop/admin",
        "/admin/dashboard","/admin/sales",
    ],
    "Laravel/PHP": [
        "/admin/login","/admin/dashboard","/admin-panel",
        "/backend/login","/dashboard/login","/auth/admin",
        "/login.php","/admin.php","/panel.php","/manage.php",
        "/config.php","/configuration.php","/settings.php",
    ],
    "cPanel/Hosting": [
        "/cpanel","/whm","/webmail","/plesk","/ispconfig",
        "/directadmin","/vesta","/serveradmin","/webadmin",
        # cPanel (real login endpoints, http on odd control ports, https on the rest)
        ("http",2082,"/"),  ("http",2082,"/login/"),
        ("https",2083,"/"), ("https",2083,"/login/"),
        ("http",2086,"/"),  ("http",2086,"/login/"),   # WHM
        ("https",2087,"/"), ("https",2087,"/login/"),  # WHM SSL
        ("http",2095,"/"),  ("https",2096,"/"),          # Webmail
        # Plesk
        ("https",8443,"/login_up.php3"), ("https",8443,"/"),
        # DirectAdmin
        ("http",2222,"/"),  ("https",2222,"/"),
        # Webmin / Usermin
        ("https",10000,"/"), ("https",20000,"/"),
        # ISPConfig
        ("https",8080,"/"), ("https",8081,"/"),
        # VestaCP
        ("https",8083,"/"), ("https",8443,"/login/"),
        # cPanel API leftovers
        ("https",2083,"/frontend/paper_lantern/index.html"),
    ],
    "Database": [
        "/phpmyadmin","/pma","/sqladmin","/mysql","/dbadmin",
        "/database","/myadmin","/phpMyAdmin","/phpbb","/pgadmin",
        "/phppgadmin","/adminer","/adminer.php","/db",
        "/mysql/index.php","/pma/index.php","/phpMyAdmin/index.php",
    ],
    "API / GraphQL": [
        "/api/admin","/api/dashboard","/graphql","/graphiql",
        "/admin/api","/backend/api","/api/v1/admin","/api/v2/admin",
        "/swagger","/swagger-ui","/api-docs","/openapi.json",
        "/swagger.json","/console","/api/v1/users","/api/v1/config",
        "/rest/admin","/api/login","/api/auth",
    ],
    "Sensitive Files": [
        "/.env","/.env.local","/.env.backup","/.env.production",
        "/.git/config","/.git/HEAD","/.gitignore","/.gitattributes",
        "/.svn/entries","/.svn/wc.db","/.DS_Store","/Thumbs.db",
        "/wp-config.php","/wp-config.php.bak","/wp-config.php.old",
        "/config.php","/config.php.bak","/config.yml","/config.yaml",
        "/config.json","/configuration.php","/settings.php",
        "/local.xml","/app/etc/local.xml","/.htaccess","/.htpasswd",
        "/web.config","/appsettings.json","/phpinfo.php","/info.php",
        "/test.php","/server-status","/server-info",
        "/backup.sql","/backup.tar.gz","/backup.zip","/dump.sql",
        "/database.sql","/db.sql","/install.php","/setup.php",
        "/composer.json","/composer.lock","/package.json",
        "/Dockerfile","/docker-compose.yml","/.travis.yml",
        "/.well-known/security.txt","/robots.txt","/crossdomain.xml",
        "/clientaccesspolicy.xml","/README.md","/CHANGELOG",
        "/error_log","/debug.log","/access.log","/error.log",
        "/logs/error.log","/logs/access.log","/log/error.log",
    ],
    "Bypass Paths": [
        "/admin/","/admin//","/admin/./","//admin/",
        "/ADMIN","/Admin","/%61dmin","/admin%00",
        "/admin;/","/admin..;/","/.;/admin",
        "/;/admin","/admin%20","/admin%09","/admin%0a",
        "/%2fadmin","/admin%2f","/./admin",
    ],
}

MANAGEMENT_PORT_PROBE = {
    
    2082:  [("http","/"),("http","/login/")],
    2083:  [("https","/"),("https","/login/")],
    2086:  [("http","/"),("http","/login/")],
    2087:  [("https","/"),("https","/login/")],
    2095:  [("http","/")],
    2096:  [("https","/")],
    8443:  [("https","/"),("https","/login_up.php3"),("https","/login/")],
    2222:  [("http","/"),("https","/")],
    10000: [("https","/"),("http","/")],
    20000: [("https","/")],
    8080:  [("http","/"),("http","/admin"),("https","/")],
    8081:  [("http","/"),("https","/")],
    8083:  [("https","/")],
    9090:  [("https","/"),("http","/")],
    8888:  [("http","/"),("https","/")],
    5000:  [("http","/"),("https","/")],
}

class AdminFinder:
    def __init__(self, url, engine: Engine, logger: Logger,
                 threads=None, categories=None, open_ports=None):
        self.url   = url.rstrip('/')
        self.engine= engine
        self.logger= logger
        self.threads = threads or engine.threads
        self.cats  = categories or list(ADMIN_PATHS.keys())
        self.open_ports = open_ports or []   
        self.found : List[dict] = []
        self._lk   = threading.Lock()
        self._done = 0

    def _paths(self) -> list:
        out = []
        for cat in self.cats:
            for p in ADMIN_PATHS.get(cat,[]):
                out.append((cat,p))
        
        for op in self.open_ports:
            port = op.get("port")
            if port in MANAGEMENT_PORT_PROBE:
                for scheme, sub in MANAGEMENT_PORT_PROBE[port]:
                    out.append(("Live Port Panel", (scheme, port, sub)))
        return out

    def _check(self, cat: str, path):
        
        if isinstance(path, tuple):
            scheme, port, sub = path
            parsed = urlparse(self.url)
            full = f"{scheme}://{parsed.hostname}:{port}{sub}"
        elif isinstance(path, str) and path.startswith(':'):
            parsed = urlparse(self.url)
            full = f"{parsed.scheme}://{parsed.hostname}{path}"
        else:
            full = f"{self.url}{path}"

        resp = self.engine.get(full, method="GET")
        with self._lk: self._done += 1
        if not resp: return

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

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = [ex.submit(self._check, cat, p) for cat,p in paths]
            for _ in concurrent.futures.as_completed(futs):
                bar(self._done, total, len(self.found))
        print()

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
    ],
    "LFI/Path Traversal": [
        r'[?&]file=', r'[?&]path=', r'[?&]dir=', r'[?&]folder=',
        r'[?&]include=', r'[?&]page=', r'[?&]doc=', r'[?&]document=',
        r'[?&]template=', r'[?&]view=', r'[?&]load=', r'[?&]read=',
        r'[?&]lang=', r'[?&]locale=', r'[?&]module=', r'[?&]action=',
        r'\.\./', r'%2e%2e%2f',
    ],
    "Open Redirect": [
        r'[?&]url=http', r'[?&]redirect=', r'[?&]return=',
        r'[?&]next=', r'[?&]goto=', r'[?&]redir=', r'[?&]forward=',
        r'[?&]location=', r'[?&]back=', r'[?&]continue=',
        r'[?&]returnurl=', r'[?&]return_to=', r'[?&]dest=',
    ],
    "SSRF": [
        r'[?&]url=', r'[?&]uri=', r'[?&]host=', r'[?&]domain=',
        r'[?&]server=', r'[?&]endpoint=', r'[?&]proxy=',
        r'[?&]fetch=', r'[?&]callback=', r'[?&]target=',
        r'[?&]link=', r'[?&]src=', r'[?&]source=', r'[?&]feed=',
        r'[?&]webhook=', r'[?&]img=', r'[?&]image_url=',
    ],
    "XSS": [
        r'[?&]search=', r'[?&]q=', r'[?&]query=', r'[?&]keyword=',
        r'[?&]term=', r'[?&]s=', r'[?&]name=', r'[?&]comment=',
        r'[?&]message=', r'[?&]text=', r'[?&]input=', r'[?&]msg=',
        r'[?&]title=', r'[?&]desc=', r'[?&]description=',
        r'[?&]email=', r'[?&]feedback=', r'[?&]content=',
    ],
    "IDOR / Auth": [
        r'[?&]token=', r'[?&]key=', r'[?&]api_key=', r'[?&]auth=',
        r'[?&]access_token=', r'[?&]secret=', r'[?&]password=',
        r'[?&]session=', r'[?&]sess=', r'[?&]account_id=',
        r'[?&]user_id=', r'[?&]order_id=', r'[?&]invoice=',
        r'[?&]ref=', r'[?&]reset_token=', r'[?&]hash=',
    ],
    "File Upload / Import": [
        r'/upload', r'/file-upload', r'/import', r'/media/upload',
        r'/attachments?/upload', r'/import-file', r'/uploadfile',
        r'type="file"', r'enctype="multipart',
    ],
    "Admin / Config Exposure": [
        r'/admin', r'/config', r'/setup', r'/install',
        r'/backup', r'/debug', r'\.env', r'\.git',
        r'/console', r'/actuator', r'/manage', r'/_profiler',
    ],
    "Command/Code Injection": [
        r'[?&]cmd=', r'[?&]exec=', r'[?&]command=', r'[?&]run=',
        r'[?&]ping=', r'[?&]host=.*&cmd', r'[?&]code=', r'[?&]eval=',
        r'[?&]debug=', r'[?&]test=',
    ],
    "XXE / Deserialization": [
        r'\.xml(\?|$)', r'[?&]xml=', r'[?&]data=.*base64',
        r'[?&]serialized=', r'[?&]obj=', r'[?&]payload=',
    ],
    "API Version / Debug": [
        r'/api/v\d+', r'/v\d+/', r'[?&]debug=true', r'[?&]test=1',
        r'[?&]verbose=', r'[?&]format=json', r'/internal/',
        r'/private/', r'/staging/', r'/beta/',
    ],
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
        """Classify a URL by file extension into the right media bucket.
        Returns True if it matched something (so caller can skip other handling)."""
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
        """Check if URL has params that may be exploitable"""
        parsed = urlparse(url)
        qs = parsed.query
        if not qs: return

        for vtype, patterns in VULN_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, url, re.I):
                    with self._lk:
                        entry = {"url": url, "pattern": pat, "type": vtype}
                        if entry not in self.vuln_urls[vtype]:
                            self.vuln_urls[vtype].append(entry)
                    break

        
        params = parse_qs(qs)
        if params:
            with self._lk:
                entry = {"url": url, "params": list(params.keys())}
                if entry not in self.params_found:
                    self.params_found.append(entry)

    def _extract(self, url: str, html: str):
        soup = BeautifulSoup(html, 'html.parser')

        
        for tag in soup.find_all('a', href=True):
            href = urljoin(url, tag['href'].strip())
            if not href.startswith('http'): continue
            if self._bucket_media(href):
                continue  
            if self._internal(href):
                with self._lk: self.internal.add(href)
            else:
                with self._lk: self.external.add(href)
            self._classify_url(href)

        
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

        # Forms
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

        # Emails
        found_emails = re.findall(
            r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,7}', html)
        with self._lk: self.emails.update(found_emails)

        # Phones
        found_phones = re.findall(
            r'(?:\+?\d[\d\s\-\(\)]{7,}\d)', html)
        with self._lk: self.phones.update(found_phones[:50])

        # HTML Comments
        for cmt in soup.find_all(string=lambda t: isinstance(t, str) and '<!--' in str(t)):
            pass
        raw_comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        for c in raw_comments:
            c = c.strip()
            if len(c) > 5 and len(c) < 500:
                with self._lk:
                    if c not in self.comments:
                        self.comments.append(c)

        # Sensitive data patterns in source
        sens_pats = [
            r'(?i)(api[_\-]?key|api[_\-]?secret|access[_\-]?token|secret[_\-]?key)\s*[=:]\s*["\']([^"\']{8,})["\']',
            r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']',
            r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["\']([^"\']+)["\']',
            r'(?i)(private[_\-]?key|rsa[_\-]?key)[^"\']*["\']([^"\']{10,})["\']',
            r'(?i)Bearer\s+([a-zA-Z0-9\-_]{20,})',
        ]
        for pat in sens_pats:
            for m in re.finditer(pat, html):
                entry = f"[LEAK] {url} → {m.group(0)[:100]}"
                with self._lk:
                    if entry not in self.sensitive:
                        self.sensitive.append(entry)

        # Hidden URLs in JS vars / meta
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

        sc_col = C.G if resp.status_code==200 else C.Y
        print(f"\r{' '*90}\r  {sc_col}[{resp.status_code}]{C.E} {C.DIM}{url[:80]}{C.E}")
        self.logger.log(f"[CRAWL][{resp.status_code}] {url}")
        self._extract(url, resp.text)

        nxt = []
        with self._lk:
            for link in list(self.internal):
                if link not in self.visited:
                    nxt.append((link, depth+1))
        return nxt

    def run(self) -> dict:
        sep("WEB CRAWLER")
        self.logger.section("WEB CRAWLER")
        print(f"  Target : {C.CY}{self.start}{C.E}")
        print(f"  Depth  : {C.CY}{self.depth}{C.E}  Threads: {C.CY}{self.threads}{C.E}\n")

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

        # Report
        sep("CRAWLER RESULTS")
        print(f"  Pages Crawled  : {C.CY}{len(self.visited)}{C.E}")
        print(f"  Internal Links : {C.CY}{len(self.internal)}{C.E}")
        print(f"  External Links : {C.CY}{len(self.external)}{C.E}")
        print(f"  JS Files       : {C.CY}{len(self.js_files)}{C.E}")
        print(f"  CSS Files      : {C.CY}{len(self.css_files)}{C.E}")
        print(f"  Forms          : {C.G}{len(self.forms)}{C.E}")
        print(f"  Emails         : {C.G}{len(self.emails)}{C.E}")
        print(f"  Comments       : {C.G}{len(self.comments)}{C.E}")

        print(f"\n  {C.Y}Media Discovered:{C.E}")
        print(f"    Images         : {C.CY}{len(self.images)}{C.E}")
        print(f"    GIFs           : {C.CY}{len(self.gifs)}{C.E}")
        print(f"    Videos         : {C.CY}{len(self.videos)}{C.E}")
        print(f"    Audio          : {C.CY}{len(self.audio)}{C.E}")
        print(f"    Documents      : {C.CY}{len(self.documents)}{C.E}  {C.DIM}(pdf/doc/xls/ppt/csv){C.E}")
        print(f"    Archives       : {C.CY}{len(self.archives)}{C.E}  {C.DIM}(zip/rar/7z/tar){C.E}")

        total_vuln = sum(len(v) for v in self.vuln_urls.values())
        print(f"\n  Vuln-Candidate URLs : {C.Y}{total_vuln}{C.E}")
        if self.sensitive:
            print(f"  {C.R}[!] Potential Leaks : {len(self.sensitive)}{C.E}")

        # Vuln URL breakdown
        if total_vuln:
            print(f"\n  {C.Y}Potentially Exploitable URLs:{C.E}")
            for vtype, items in self.vuln_urls.items():
                if items:
                    print(f"\n    {C.M}[{vtype}]{C.E}  ({len(items)} URLs)")
                    for item in items[:10]:
                        print(f"      {C.DIM}{item['url'][:90]}{C.E}")
                    if len(items)>10:
                        print(f"      {C.DIM}... and {len(items)-10} more{C.E}")

        if self.emails:
            print(f"\n  {C.Y}Emails:{C.E}")
            for e in sorted(self.emails)[:20]:
                print(f"    {C.G}✉ {e}{C.E}")

        if self.sensitive:
            print(f"\n  {C.R}Potential Data Leaks:{C.E}")
            for s in self.sensitive[:10]:
                print(f"    {C.R}⚠ {s[:100]}{C.E}")

        if self.forms:
            print(f"\n  {C.Y}Forms ({len(self.forms)}):{C.E}")
            uploads = [f for f in self.forms if f.get('has_file_upload')]
            print(f"    File Upload Forms: {C.G}{len(uploads)}{C.E}")
            for i,fm in enumerate(self.forms[:8],1):
                print(f"    {C.CY}[{i}]{C.E} {fm['method']} → {fm['action'][:60]}  inputs:{len(fm['inputs'])}")

        if self.comments:
            print(f"\n  {C.Y}HTML Comments (top 5):{C.E}")
            for c in self.comments[:5]:
                print(f"    {C.DIM}<!-- {c[:80]} -->{C.E}")

        # Ask about vuln URLs
        if total_vuln and len(self.params_found)>0:
            print(f"\n  {C.Y}[?] Found {len(self.params_found)} URLs with parameters.{C.E}")
            ans = ask("Export bug-hunting URL list to file? [Y/n]","y").lower()
            if ans=='y':
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
        path = os.path.join(Config.LOG_DIR, f"bughunt_urls_{ts}.txt")
        with open(path,'w',encoding='utf-8') as f:
            f.write(f"# Bug Hunting URLs - {self.start}\n# {datetime.datetime.now()}\n\n")
            for vtype, items in self.vuln_urls.items():
                if items:
                    f.write(f"\n## {vtype} ({len(items)})\n")
                    for item in items:
                        f.write(f"{item['url']}\n")
            f.write(f"\n## All Parameter URLs ({len(self.params_found)})\n")
            for p in self.params_found:
                f.write(f"{p['url']}\n")
        cprint(C.G, f"\n[✔] Bug-hunting URLs exported: {path}")


# ════════════
#  MODULE 4 – SENSITIVE FILE SCANNER
# ═════════════
SENSITIVE_PATHS = [
    
    "/.env","/.env.local","/.env.backup","/.env.production","/.env.staging",
    "/.env.development","/.env.test","/.env.example","/.env.sample",
    "/config.php","/config.php.bak","/config.php.old","/config.inc.php",
    "/config.yml","/config.yaml","/config.json","/config.xml",
    "/configuration.php","/settings.php","/settings.py","/settings.rb",
    "/local.xml","/app/etc/local.xml","/web.config","/appsettings.json",
    "/application.properties","/application.yml","/bootstrap.php",
    # Git / SVN
    "/.git/config","/.git/HEAD","/.git/COMMIT_EDITMSG","/.git/index",
    "/.git/packed-refs","/.git/refs/heads/master","/.gitignore",
    "/.svn/entries","/.svn/wc.db","/.svn/format","/.hg/hgrc",
    # CMS Configs
    "/wp-config.php","/wp-config.php.bak","/wp-config.php.old",
    "/wp-config.php~","/wp-config-sample.php",
    "/sites/default/settings.php","/sites/default/default.settings.php",
    # Info / Debug
    "/phpinfo.php","/info.php","/test.php","/debug.php","/status.php",
    "/server-status","/server-info","/_profiler","/telescope",
    "/debug/default/view","/debug/toolbar",
    # Backups
    "/backup.sql","/backup.tar.gz","/backup.zip","/backup.tar",
    "/dump.sql","/database.sql","/db.sql","/data.sql",
    "/backup/database.sql","/backups/backup.sql",
    "/www.tar.gz","/site.tar.gz","/public_html.zip",
    # Logs
    "/error_log","/error.log","/debug.log","/access.log","/app.log",
    "/logs/error.log","/logs/app.log","/log/error.log","/log/debug.log",
    "/storage/logs/laravel.log","/var/log/nginx/error.log",
    # Install
    "/install.php","/install.sql","/setup.php","/upgrade.php",
    "/installer/","/setup/","/install/",
    # Packages
    "/composer.json","/composer.lock","/package.json","/package-lock.json",
    "/yarn.lock","/Gemfile","/Gemfile.lock","/requirements.txt",
    # Docker / CI
    "/Dockerfile","/docker-compose.yml","/docker-compose.yaml",
    "/.travis.yml","/.circleci/config.yml","/.github/workflows",
    "/Jenkinsfile","/.drone.yml",
    # API / Swagger
    "/swagger.json","/swagger.yaml","/openapi.json","/openapi.yaml",
    "/api-docs","/api/swagger.json","/docs/api",
    # Security / Misc
    "/.htaccess","/.htpasswd","/crossdomain.xml","/clientaccesspolicy.xml",
    "/.well-known/security.txt","/.well-known/apple-app-site-association",
    "/security.txt","/humans.txt","/README.md","/CHANGELOG",
    "/CHANGELOG.md","/VERSION","/LICENSE","/Thumbs.db","/.DS_Store",
]

class SensitiveScanner:
    def __init__(self, url, engine: Engine, logger: Logger, threads=None):
        self.url     = url.rstrip('/')
        self.engine  = engine
        self.logger  = logger
        self.threads = threads or engine.threads
        self.found   : List[dict] = []
        self._lk     = threading.Lock()
        self._done   = 0

    def _check(self, path: str):
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
        print(f"  Scanning {C.CY}{len(SENSITIVE_PATHS)}{C.E} paths ...\n")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = [ex.submit(self._check,p) for p in SENSITIVE_PATHS]
            for _ in concurrent.futures.as_completed(futs):
                bar(self._done, len(SENSITIVE_PATHS), len(self.found))
        print()

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
            if port in (80,8080,8000,8081,8082,8083,8088,8443,443):
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
            # Ask about interesting ports
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
#  MODULE 7 – 403/401 BYPASS TESTER
# ════════════════════
class BypassTester:
    def __init__(self, base_url, path, logger: Logger):
        self.base   = base_url.rstrip('/')
        self.path   = path.strip() if path.strip().startswith('/') else '/'+path.strip()
        self.logger = logger
        self.found  : List[dict] = []

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
        """Runs without printing header – used by AdminFinder"""
        t = f"{self.base}{self.path}"
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
        # Path variants
        for variant in [f"{self.path}/", f"{self.path}//", f"/{self.path.lstrip('/')}"]:
            try:
                r = engine.sess.get(f"{self.base}{variant}", timeout=6,
                                    verify=False, allow_redirects=True)
                if r.status_code==200:
                    self.found.append({"url":f"{self.base}{variant}","method":"GET",
                                       "label":"path-variant","status":200})
                    return
            except: pass

    def run(self) -> list:
        sep("403 / 401 BYPASS TESTER")
        self.logger.section("BYPASS TESTER")
        target = f"{self.base}{self.path}"
        print(f"  Target: {C.CY}{target}{C.E}\n")

        # A – Path manipulation
        print(f"  {C.Y}[A] Path Manipulation{C.E}")
        variants = [
            (f"{self.path}/",        "Trailing slash"),
            (f"{self.path}//",       "Double slash"),
            (f"/{self.path.lstrip('/')}", "Strip leading"),
            (f"{self.path}./",       "Dot-slash"),
            (f"{self.path}..;/",     "Dot-dot semicolon"),
            (f"/.;{self.path}",      "Dot prefix"),
            (f"{self.path}%00",      "Null byte"),
            (f"{self.path}%20",      "Space encoded"),
            (f"{self.path}%09",      "Tab encoded"),
            (f"//{self.path.lstrip('/')}","Double slash prefix"),
            (f"{self.path.upper()}","Uppercase"),
            (f"{self.path};/",       "Semicolon"),
            (f"{self.path}?",        "Query char"),
            (f"/api/..{self.path}",  "API traversal"),
            (f"{self.path}%2f",      "Encoded slash"),
            (f"/%2e{self.path}",     "Encoded dot"),
        ]
        for variant, label in variants:
            self._try(label, "GET", f"{self.base}{variant}")

        # B – Header bypass
        print(f"\n  {C.Y}[B] Header Bypass{C.E}")
        header_sets = [
            ({"X-Forwarded-For":"127.0.0.1"},                  "X-Forwarded-For: 127.0.0.1"),
            ({"X-Real-IP":"127.0.0.1"},                        "X-Real-IP: 127.0.0.1"),
            ({"X-Custom-IP-Authorization":"127.0.0.1"},        "X-Custom-IP-Auth"),
            ({"X-Originating-IP":"127.0.0.1"},                 "X-Originating-IP"),
            ({"X-Remote-IP":"127.0.0.1","X-Remote-Addr":"127.0.0.1"}, "X-Remote-*"),
            ({"CF-Connecting-IP":"127.0.0.1"},                 "CF-Connecting-IP"),
            ({"True-Client-IP":"127.0.0.1"},                   "True-Client-IP"),
            ({"X-Forwarded-Host":"localhost"},                  "X-Forwarded-Host: localhost"),
            ({"X-Original-URL": self.path},                    "X-Original-URL"),
            ({"X-Rewrite-URL": self.path},                     "X-Rewrite-URL"),
            ({"Referer": f"{self.base}{self.path}"},           "Referer self"),
            ({"X-Host":"127.0.0.1","Origin":"https://localhost"}, "X-Host+Origin"),
        ]
        for h, label in header_sets:
            self._try(label, "GET", target, headers=h)

        # C – HTTP Methods
        print(f"\n  {C.Y}[C] HTTP Method Bypass{C.E}")
        for method in ["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD",
                       "TRACE","CONNECT","PROPFIND"]:
            self._try(f"Method: {method}", method, target)

        print(f"\n  {C.G}[✔] Bypass Test Done: {len(self.found)} successful{C.E}")
        self.logger.save("bypass_results", self.found)
        return self.found


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

    while True:
        sep("MENU")
        menu_line("1", "Information Gathering")
        menu_line("2", "Admin Panel Finder")
        menu_line("3", "Web Crawler  +  Bug-Hunt URL Extractor")
        menu_line("4", "Sensitive File Scanner")
        menu_line("5", "Port Scanner")
        menu_line("6", "Subdomain Enumerator")
        menu_line("7", "403 / 401 Bypass Tester")
        menu_line("8", "Full Scan  (all modules)")
        menu_line("S", "Settings")
        menu_line("T", "Change Target")
        menu_line("0", "Exit")
        print(f"\n  {C.DIM}Target: {target}  |  Threads: {cfg.threads}  |  Proxy: {cfg.proxy or 'off'}{C.E}")

        ch = ask("Choice:").upper()
        eng = cfg.engine()

        if ch == '1':
            InfoGatherer(target, eng, log).run()
            done_prompt()

        elif ch == '2':
            # Category selection
            cats = list(ADMIN_PATHS.keys())
            print(f"\n  {C.Y}Categories:{C.E}")
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

            AdminFinder(target, eng, log, categories=selected, open_ports=open_ports).run()
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
            SensitiveScanner(target, eng, log).run()
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
            cprint(C.M, "\n  ══ FULL SCAN ══")
            InfoGatherer(target, eng, log).run()

            
            open_ports = PortScanner(target, log).run()

            
            AdminFinder(target, eng, log, open_ports=open_ports).run()

            # Crawler
            try: d = int(ask("Crawl depth [2]:", "2"))
            except: d=2
            wc = WebCrawler(target, eng, log, max_depth=d)
            wc.run()

            # Sensitive
            SensitiveScanner(target, eng, log).run()

            # Subdomains
            SubdomainEnum(target, log).run()

            log.finalize()
            cprint(C.G, "\n  [✔] Full Scan Complete!")
            done_prompt()

        elif ch == 'S':
            cfg.menu()

        elif ch == 'T':
            target = get_url()
            log    = Logger(target)
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
