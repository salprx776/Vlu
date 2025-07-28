import os
import sys
import re
import socket
import requests
import threading
import concurrent.futures
import urllib.parse
from datetime import datetime
import telebot
from telebot import types
import dns.resolver
import json
import ipwhois
from bs4 import BeautifulSoup
import ssl
import whois
import geoip2.database
import hashlib
import base64

# 🔐 CONFIGURATION
BOT_TOKEN = "8083475134:AAGr2cNdYz3DBDtHArKShOYetAsNPzmezmc"
ADMIN_ID = "7887268414"
SCAN_THREADS = 50  # High-speed scanning
TIMEOUT = 3  # Aggressive timeout
MAX_RESOURCE_SIZE = 5242880  # 5MB max download size

# 🔥 ADVANCED VULNERABILITY DETECTION ENGINE
class QuantumScanner:
    def __init__(self):
        self.results = {
            "resources": {
                "scripts": [],
                "images": [],
                "audio": [],
                "video": []
            }
        }
        self.critical_ports = [21, 22, 80, 443, 8080, 3306, 3389, 5900]
        self.sensitive_files = [
            "/.git/HEAD", "/.env", "/wp-config.php", "/.htaccess", 
            "/backup.zip", "/adminer.php", "/phpinfo.php", "/.DS_Store",
            "/config.inc.php", "/.svn/entries", "/WEB-INF/web.xml",
            "/.well-known/security.txt", "/crossdomain.xml", "/clientaccesspolicy.xml",
            "/phpmyadmin/index.php", "/test.php", "/backup.sql"
        ]
        self.exploit_patterns = {
            "SQLi": r"select\s.*from|union\s.*select|insert\s.*into|update\s.*set|delete\s.*from",
            "XSS": r"alert\(.*\)|<\s*script\s*>|onerror\s*=",
            "LFI": r"\.\./|\.\.\\|etc/passwd|boot.ini|win.ini",
            "RCE": r"system\(|exec\(|passthru\(|shell_exec\(",
            "SSRF": r"url=.*http://|request=.*internal|proxy=.*127.0.0.1",
            "JWT": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"
        }
        self.server_tech_patterns = {
            "PHP": r"X-Powered-By: PHP|\.php\?|phpinfo\(\)",
            "NodeJS": r"X-Powered-By: Express|node\.js",
            "ASP.NET": r"X-Powered-By: ASP\.NET|\.aspx\?",
            "WordPress": r"wp-content|wp-includes|wordpress",
            "Joomla": r"joomla",
            "Drupal": r"drupal"
        }

    def deep_scan(self, url):
        """Comprehensive vulnerability assessment with exploit detection"""
        start_time = datetime.now()
        self.results = {
            "target": url,
            "vulnerabilities": [],
            "resources": {
                "scripts": [],
                "images": [],
                "audio": [],
                "video": [],
                "broken_links": []
            },
            "server_info": {}
        }

        try:
            # Extract domain and path
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc
            base_url = f"{parsed.scheme}://{domain}"

            # Phase 1: Network reconnaissance
            self.results.update(self.network_recon(domain))

            # Phase 2: Web vulnerability scanning
            self.web_scan(url, base_url)

            # Phase 3: Hidden content discovery
            self.find_hidden_content(url)

            # Phase 4: Security header analysis
            self.check_security_headers(url)

            # Phase 5: Extract server metadata
            self.extract_server_metadata(url)

            # Phase 6: Resource extraction
            self.extract_resources(url)

            # Scan metadata
            self.results['scan_duration'] = str(datetime.now() - start_time)
            self.results['timestamp'] = str(start_time)

            return self.results

        except Exception as e:
            return {"error": f"Scan failed: {str(e)}"}

    def network_recon(self, domain):
        """Network infrastructure intelligence"""
        results = {}
        try:
            # DNS reconnaissance
            results['dns'] = {}
            for qtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']:
                try:
                    answers = dns.resolver.resolve(domain, qtype, raise_on_no_answer=False)
                    results['dns'][qtype] = [str(r) for r in answers]
                except:
                    pass

            # IP information
            try:
                ip = socket.gethostbyname(domain)
                results['ip'] = ip
                results['ports'] = self.port_scan(ip)
                whois = ipwhois.IPWhois(ip)
                results['whois'] = whois.lookup_rdap()

                # Geolocation
                try:
                    with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
                        response = reader.city(ip)
                        results['geo'] = {
                            "country": response.country.name,
                            "city": response.city.name,
                            "postal": response.postal.code,
                            "location": f"{response.location.latitude},{response.location.longitude}"
                        }
                except:
                    results['geo'] = "Geolocation database missing"

            except:
                results['ip'] = "Resolution failed"

            return results

        except:
            return {"network_error": "Recon failed"}

    def port_scan(self, ip):
        """Ultra-fast port scanning"""
        open_ports = []
        def check_port(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                try:
                    s.connect((ip, port))
                    open_ports.append(port)

                    # Banner grabbing
                    try:
                        banner = s.recv(1024).decode().strip()
                        if banner:
                            self.results.setdefault('banners', {})[port] = banner
                    except:
                        pass

                    return True
                except:
                    return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=SCAN_THREADS) as executor:
            executor.map(check_port, self.critical_ports)

        return open_ports

    def web_scan(self, url, base_url):
        """Deep web vulnerability analysis"""
        session = requests.Session()
        session.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

        try:
            # Fetch target page
            resp = session.get(url, timeout=TIMEOUT, verify=False)
            content = resp.text

            # Store server headers
            self.results['server_info']['headers'] = dict(resp.headers)

            # Check for vulnerabilities in content
            for vuln_type, pattern in self.exploit_patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    self.results['vulnerabilities'].append({
                        "type": vuln_type,
                        "severity": "CRITICAL",
                        "evidence": "Detected exploit pattern in page content"
                    })

            # Analyze forms for vulnerabilities
            soup = BeautifulSoup(content, 'html.parser')
            for form in soup.find_all('form'):
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').upper()

                # Check for password fields without protection
                if form.find('input', {'type': 'password'}):
                    if not form_action.startswith('https://'):
                        self.results['vulnerabilities'].append({
                            "type": "Password Transmission",
                            "severity": "HIGH",
                            "evidence": f"Password field found in non-HTTPS form ({form_method} {form_action})"
                        })

            # Find broken resources
            self.results['resources']['broken_links'] = self.find_broken_resources(session, url, content)

            # Check for hidden comments
            comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text)
            sensitive_comments = [c for c in comments if any(kw in c.lower() for kw in ['password', 'secret', 'key', 'admin'])]
            if sensitive_comments:
                self.results['vulnerabilities'].append({
                    "type": "Sensitive Comments",
                    "severity": "MEDIUM",
                    "evidence": f"Found {len(sensitive_comments)} comments with sensitive keywords"
                })

            # Detect server technology
            self.detect_server_tech(content, resp.headers)

        except Exception as e:
            self.results['scan_errors'] = f"Web scan failed: {str(e)}"

    def detect_server_tech(self, content, headers):
        """Identify server-side technologies"""
        tech_found = []

        # Check headers
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            tech_found.append(powered_by)

        # Check content patterns
        for tech, pattern in self.server_tech_patterns.items():
            if re.search(pattern, content, re.IGNORECASE) or re.search(pattern, powered_by, re.IGNORECASE):
                tech_found.append(tech)

        # Deduplicate and save
        if tech_found:
            self.results['server_info']['technologies'] = list(set(tech_found))

    def extract_server_metadata(self, url):
        """Extract server metadata and configurations"""
        try:
            # WHOIS domain lookup
            domain = urllib.parse.urlparse(url).netloc
            w = whois.whois(domain)
            self.results['server_info']['whois'] = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers
            }

            # SSL/TLS certificate inspection
            hostname = domain.split(':')[0]
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(TIMEOUT)
                s.connect((hostname, 443))
                cert = s.getpeercert()

                self.results['server_info']['ssl'] = {
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "subject": dict(x[0] for x in cert['subject']),
                    "version": cert.get('version'),
                    "serial_number": cert.get('serialNumber'),
                    "expires": cert.get('notAfter')
                }

        except Exception as e:
            self.results['server_info']['metadata_error'] = str(e)

    def extract_resources(self, url):
        """Extract scripts, images, audio, and video resources"""
        try:
            resp = requests.get(url, timeout=TIMEOUT, verify=False)
            soup = BeautifulSoup(resp.text, 'html.parser')

            # Extract scripts
            for script in soup.find_all('script'):
                if script.get('src'):
                    script_url = urllib.parse.urljoin(url, script.get('src'))
                    self.results['resources']['scripts'].append({
                        "url": script_url,
                        "content": self.get_resource_content(script_url)
                    })

            # Extract images
            for img in soup.find_all('img'):
                if img.get('src'):
                    img_url = urllib.parse.urljoin(url, img.get('src'))
                    self.results['resources']['images'].append({
                        "url": img_url,
                        "content": self.get_resource_content(img_url, binary=True)
                    })

            # Extract audio/video
            for media in soup.find_all(['audio', 'video', 'source']):
                src = media.get('src') or media.get('data-src')
                if src:
                    media_url = urllib.parse.urljoin(url, src)
                    self.results['resources']['audio' if media.name == 'audio' else 'video'].append({
                        "url": media_url,
                        "content": self.get_resource_content(media_url, binary=True)
                    })

        except Exception as e:
            self.results['resources']['extraction_error'] = str(e)

    def get_resource_content(self, url, binary=False):
        """Fetch resource content with size limitation"""
        try:
            resp = requests.get(url, timeout=TIMEOUT, stream=True, verify=False)
            content = b''
            for chunk in resp.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > MAX_RESOURCE_SIZE:
                    return "RESOURCE_TOO_LARGE"

            if binary:
                return base64.b64encode(content).decode('utf-8')
            else:
                return content.decode('utf-8', errors='ignore')
        except:
            return None

    def find_hidden_content(self, url):
        """Discover hidden files and directories"""
        parsed = urllib.parse.urlparse(url)
        base_path = os.path.dirname(parsed.path) if parsed.path else '/'

        found = []
        for file in self.sensitive_files:
            try:
                test_url = urllib.parse.urljoin(url, file)
                resp = requests.head(test_url, timeout=TIMEOUT, verify=False)
                if resp.status_code == 200:
                    found.append({
                        "path": test_url,
                        "status": resp.status_code,
                        "content_type": resp.headers.get('Content-Type', '')
                    })

                    # Check for exposed .git directory
                    if '/.git/' in file:
                        self.results['vulnerabilities'].append({
                            "type": "Exposed Git Repository",
                            "severity": "CRITICAL",
                            "evidence": f"Found accessible .git directory at {test_url}"
                        })
            except:
                pass

        self.results['hidden_content'] = found

    def find_broken_resources(self, session, url, content):
        """Find broken links and resources"""
        broken = []
        links = re.findall(r'href=[\'"]?([^\'" >]+)', content)
        links += re.findall(r'src=[\'"]?([^\'" >]+)', content)

        for link in set(links):
            try:
                abs_url = urllib.parse.urljoin(url, link)
                if abs_url.startswith('http'):
                    resp = session.head(abs_url, timeout=TIMEOUT, allow_redirects=True)
                    if resp.status_code >= 400:
                        broken.append({
                            "url": abs_url,
                            "status": resp.status_code
                        })
            except:
                broken.append({"url": link, "status": "Connection failed"})

        return broken

    def check_security_headers(self, url):
        """Analyze security headers"""
        try:
            resp = requests.head(url, timeout=TIMEOUT, verify=False)
            headers = resp.headers
            missing = []

            if 'Content-Security-Policy' not in headers:
                missing.append("Content-Security-Policy")
            if 'X-Frame-Options' not in headers:
                missing.append("X-Frame-Options")
            if 'X-Content-Type-Options' not in headers:
                missing.append("X-Content-Type-Options")
            if 'Strict-Transport-Security' not in headers and url.startswith('https'):
                missing.append("Strict-Transport-Security")

            if missing:
                self.results['vulnerabilities'].append({
                    "type": "Missing Security Headers",
                    "severity": "MEDIUM",
                    "evidence": f"Missing: {', '.join(missing)}"
                })

        except:
            pass

# 🤖 TELEGRAM BOT INTERFACE
class QuantumScannerBot:
    def __init__(self, token):
        self.bot = telebot.TeleBot(token)
        self.scanner = QuantumScanner()

        # 🔒 Admin-only access
        @self.bot.message_handler(func=lambda message: str(message.from_user.id) != ADMIN_ID)
        def reject_non_admin(message):
            self.bot.reply_to(message, "⛔ ACCESS DENIED: Unauthorized user")

        # 🕵️‍♂️ Command handlers
        @self.bot.message_handler(commands=['start', 'help'], func=lambda message: str(message.from_user.id) == ADMIN_ID)
        def send_welcome(message):
            self.bot.reply_to(message,
                "⚡ QUANTUM VULNERABILITY SCANNER ACTIVE\n\n"
                "🔥 Commands:\n"
                "/scan <url> - Deep vulnerability scan\n"
                "/rescan - Re-run last scan\n"
                "/report - Get full vulnerability report\n"
                "/resources - Get extracted resources\n"
                "/serverinfo - Get server intelligence"
            )

        @self.bot.message_handler(regexp=r'^/scan .+', func=lambda message: str(message.from_user.id) == ADMIN_ID)
        def handle_scan(message):
            target = message.text.split(' ', 1)[1].strip()
            if not target.startswith('http'):
                target = 'http://' + target

            self.bot.reply_to(message, f"⚡ INITIATING QUANTUM SCAN: {target}")

            try:
                report = self.scanner.deep_scan(target)
                self.last_report = report

                # Generate summary
                vuln_count = len(report.get('vulnerabilities', []))
                ports = report.get('ports', [])
                hidden = len(report.get('hidden_content', []))
                broken = len(report.get('resources', {}).get('broken_links', []))
                scripts = len(report.get('resources', {}).get('scripts', []))
                images = len(report.get('resources', {}).get('images', []))

                summary = (
                    f"✅ SCAN COMPLETE: {target}\n"
                    f"⏱️ Duration: {report.get('scan_duration', 'N/A')}\n\n"
                    f"🔓 CRITICAL VULNERABILITIES: {vuln_count}\n"
                    f"🔌 OPEN PORTS: {', '.join(map(str, ports)) if ports else 'None'}\n"
                    f"📁 HIDDEN FILES: {hidden}\n"
                    f"🔗 BROKEN LINKS: {broken}\n"
                    f"📜 SCRIPTS FOUND: {scripts}\n"
                    f"🖼️ IMAGES FOUND: {images}"
                )

                self.bot.reply_to(message, summary)

                # Send critical vulnerabilities immediately
                for vuln in report.get('vulnerabilities', []):
                    if vuln['severity'] in ['CRITICAL', 'HIGH']:
                        self.bot.reply_to(message, 
                            f"🚨 {vuln['severity']} VULNERABILITY: {vuln['type']}\n"
                            f"Evidence: {vuln['evidence']}"
                        )

            except Exception as e:
                self.bot.reply_to(message, f"💥 SCAN FAILED: {str(e)}")

        @self.bot.message_handler(commands=['report'], func=lambda message: str(message.from_user.id) == ADMIN_ID)
        def handle_report(message):
            if hasattr(self, 'last_report'):
                report = self.last_report
                response = f"📊 FULL VULNERABILITY REPORT\n"
                response += f"🔗 Target: {report['target']}\n"
                response += f"🕒 Timestamp: {report['timestamp']}\n"
                response += f"⏱️ Duration: {report['scan_duration']}\n\n"

                # Vulnerabilities
                response += "🔓 VULNERABILITIES:\n"
                for vuln in report.get('vulnerabilities', []):
                    response += (
                        f"• {vuln['severity']}: {vuln['type']}\n"
                        f"  Evidence: {vuln['evidence']}\n\n"
                    )

                # Network info
                response += "🌐 NETWORK INTELLIGENCE:\n"
                response += f"• IP: {report.get('ip', 'N/A')}\n"
                response += f"• Open Ports: {', '.join(map(str, report.get('ports', []))) or 'None'}\n\n"

                # Hidden content
                if report.get('hidden_content'):
                    response += "📁 HIDDEN CONTENT FOUND:\n"
                    for item in report['hidden_content']:
                        response += f"• {item['path']} ({item['status']})\n"

                self.bot.reply_to(message, response)
            else:
                self.bot.reply_to(message, "❌ No scan report available")

        @self.bot.message_handler(commands=['serverinfo'], func=lambda message: str(message.from_user.id) == ADMIN_ID)
        def handle_serverinfo(message):
            if hasattr(self, 'last_report') and 'server_info' in self.last_report:
                info = self.last_report['server_info']
                response = "🖥️ SERVER INTELLIGENCE REPORT\n\n"

                # Headers
                response += "📋 HEADERS:\n"
                for k, v in info.get('headers', {}).items():
                    response += f"• {k}: {v}\n"

                # Technologies
                if 'technologies' in info:
                    response += f"\n🔧 TECHNOLOGIES: {', '.join(info['technologies'])}\n"

                # SSL info
                if 'ssl' in info:
                    ssl = info['ssl']
                    response += f"\n🔐 SSL CERTIFICATE:\n"
                    response += f"• Issuer: {ssl.get('issuer', {}).get('organizationName', 'Unknown')}\n"
                    response += f"• Valid Until: {ssl.get('expires', 'Unknown')}\n"

                # WHOIS
                if 'whois' in info:
                    whois = info['whois']
                    response += f"\n📝 WHOIS DATA:\n"
                    response += f"• Registrar: {whois.get('registrar', 'Unknown')}\n"
                    response += f"• Created: {whois.get('creation_date', 'Unknown')}\n"
                    response += f"• Expires: {whois.get('expiration_date', 'Unknown')}\n"

                self.bot.reply_to(message, response)
            else:
                self.bot.reply_to(message, "❌ No server information available")

        @self.bot.message_handler(commands=['resources'], func=lambda message: str(message.from_user.id) == ADMIN_ID)
        def handle_resources(message):
            if hasattr(self, 'last_report') and 'resources' in self.last_report:
                res = self.last_report['resources']
                response = "📦 EXTRACTED RESOURCES REPORT\n\n"

                response += f"📜 SCRIPTS: {len(res['scripts'])}\n"
                for i, script in enumerate(res['scripts'][:3], 1):
                    content_preview = script['content'][:100] + "..." if script['content'] else "EMPTY"
                    response += f"{i}. {script['url']}\n   Preview: {content_preview}\n"

                response += f"\n🖼️ IMAGES: {len(res['images'])}\n"
                for i, img in enumerate(res['images'][:3], 1):
                    response += f"{i}. {img['url']}\n   Size: {len(img['content']) if img['content'] else 0} bytes\n"

                response += f"\n🔊 AUDIO: {len(res['audio'])}\n"
                for i, audio in enumerate(res['audio'][:3], 1):
                    response += f"{i}. {audio['url']}\n"

                response += f"\n🔗 BROKEN LINKS: {len(res['broken_links'])}\n"
                for i, link in enumerate(res['broken_links'][:5], 1):
                    response += f"{i}. {link['url']} (Status: {link['status']})\n"

                self.bot.reply_to(message, response)
            else:
                self.bot.reply_to(message, "❌ No resources available")

    def run(self):
        """Start the bot"""
        print("⚡ QUANTUM VULNERABILITY SCANNER BOT ACTIVATED ⚡")
        self.bot.polling(none_stop=True)

# 💀 MAIN EXECUTION
if __name__ == "__main__":
    if BOT_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN_HERE":
        print("❌ ERROR: Replace BOT_TOKEN with your Telegram bot token!")
        sys.exit(1)
    if ADMIN_ID == "YOUR_TELEGRAM_USER_ID":
        print("❌ ERROR: Replace ADMIN_ID with your Telegram user ID!")
        sys.exit(1)

    print(r"""
    ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗████████╗██╗   ██╗███╗   ███╗
    ██╔══██╗██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██║   ██║████╗ ████║
    ██████╔╝██║   ██║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
    ██╔═══╝ ██║   ██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
    ██║     ╚██████╔╝██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
    ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
    """)

    bot = QuantumScannerBot(BOT_TOKEN)
    bot.run()
# دالة الاستجابة لأمر /start
def start(update, context):
    update.message.reply_text("مرحبًا! أنا شغال 24/7 🔥")

# إعداد البوت
updater = Updater(token=TOKEN, use_context=True)
dp = updater.dispatcher
dp.add_handler(CommandHandler("start", start))

# تشغيل البوت
updater.start_polling()
updater.idle()

