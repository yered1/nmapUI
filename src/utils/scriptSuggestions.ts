import type { ScriptSuggestion } from '../types/nmap';

// Maps port numbers to relevant NSE scripts
const PORT_SCRIPTS: Record<number, ScriptSuggestion[]> = {
  21: [
    { scriptId: 'ftp-anon', description: 'Check for anonymous FTP login', category: 'auth' },
    { scriptId: 'ftp-bounce', description: 'Check for FTP bounce attack', category: 'discovery' },
    { scriptId: 'ftp-brute', description: 'Brute-force FTP credentials', category: 'brute' },
    { scriptId: 'ftp-syst', description: 'Get FTP system type', category: 'discovery' },
    { scriptId: 'ftp-vsftpd-backdoor', description: 'Check for vsftpd 2.3.4 backdoor', category: 'vuln' },
    { scriptId: 'ftp-proftpd-backdoor', description: 'Check for ProFTPD backdoor', category: 'vuln' },
  ],
  22: [
    { scriptId: 'ssh-hostkey', description: 'Show SSH host key fingerprints', category: 'discovery' },
    { scriptId: 'ssh-auth-methods', description: 'List SSH authentication methods', category: 'auth' },
    { scriptId: 'ssh-brute', description: 'Brute-force SSH credentials', category: 'brute' },
    { scriptId: 'ssh2-enum-algos', description: 'Enumerate SSH2 algorithms', category: 'discovery' },
    { scriptId: 'sshv1', description: 'Check for SSHv1 support', category: 'vuln' },
  ],
  23: [
    { scriptId: 'telnet-brute', description: 'Brute-force telnet credentials', category: 'brute' },
    { scriptId: 'telnet-encryption', description: 'Check telnet encryption support', category: 'discovery' },
    { scriptId: 'telnet-ntlm-info', description: 'Get NTLM info from telnet', category: 'discovery' },
  ],
  25: [
    { scriptId: 'smtp-commands', description: 'List SMTP commands supported', category: 'discovery' },
    { scriptId: 'smtp-enum-users', description: 'Enumerate SMTP users via VRFY/EXPN/RCPT', category: 'discovery' },
    { scriptId: 'smtp-brute', description: 'Brute-force SMTP credentials', category: 'brute' },
    { scriptId: 'smtp-open-relay', description: 'Check for open SMTP relay', category: 'vuln' },
    { scriptId: 'smtp-vuln-cve2010-4344', description: 'Check Exim heap overflow', category: 'vuln' },
    { scriptId: 'smtp-ntlm-info', description: 'Get NTLM info from SMTP', category: 'discovery' },
  ],
  53: [
    { scriptId: 'dns-zone-transfer', description: 'Attempt DNS zone transfer (AXFR)', category: 'discovery' },
    { scriptId: 'dns-recursion', description: 'Check for open DNS recursion', category: 'vuln' },
    { scriptId: 'dns-cache-snoop', description: 'Snoop DNS cache for common domains', category: 'discovery' },
    { scriptId: 'dns-nsid', description: 'Get DNS server NSID', category: 'discovery' },
    { scriptId: 'dns-service-discovery', description: 'Discover services via DNS-SD', category: 'discovery' },
  ],
  80: [
    { scriptId: 'http-title', description: 'Get page title', category: 'discovery' },
    { scriptId: 'http-headers', description: 'Show HTTP response headers', category: 'discovery' },
    { scriptId: 'http-methods', description: 'Enumerate allowed HTTP methods', category: 'discovery' },
    { scriptId: 'http-enum', description: 'Enumerate common web paths', category: 'discovery' },
    { scriptId: 'http-robots.txt', description: 'Check robots.txt', category: 'discovery' },
    { scriptId: 'http-shellshock', description: 'Check for Shellshock vulnerability', category: 'vuln' },
    { scriptId: 'http-sql-injection', description: 'Check for SQL injection', category: 'vuln' },
    { scriptId: 'http-xssed', description: 'Check xssed.com for known XSS', category: 'vuln' },
    { scriptId: 'http-server-header', description: 'Show server header info', category: 'discovery' },
    { scriptId: 'http-sitemap-generator', description: 'Generate site map by crawling', category: 'discovery' },
  ],
  110: [
    { scriptId: 'pop3-capabilities', description: 'List POP3 capabilities', category: 'discovery' },
    { scriptId: 'pop3-brute', description: 'Brute-force POP3 credentials', category: 'brute' },
    { scriptId: 'pop3-ntlm-info', description: 'Get NTLM info from POP3', category: 'discovery' },
  ],
  111: [
    { scriptId: 'rpcinfo', description: 'Query RPC portmapper for services', category: 'discovery' },
    { scriptId: 'nfs-ls', description: 'List NFS exports', category: 'discovery' },
    { scriptId: 'nfs-showmount', description: 'Show NFS mounts', category: 'discovery' },
    { scriptId: 'nfs-statfs', description: 'Get NFS filesystem statistics', category: 'discovery' },
  ],
  135: [
    { scriptId: 'msrpc-enum', description: 'Enumerate MSRPC services', category: 'discovery' },
  ],
  139: [
    { scriptId: 'smb-os-discovery', description: 'Discover OS via SMB', category: 'discovery' },
    { scriptId: 'smb-enum-shares', description: 'Enumerate SMB shares', category: 'discovery' },
    { scriptId: 'smb-enum-users', description: 'Enumerate SMB users', category: 'discovery' },
    { scriptId: 'smb-brute', description: 'Brute-force SMB credentials', category: 'brute' },
    { scriptId: 'smb-vuln-ms17-010', description: 'Check for EternalBlue (MS17-010)', category: 'vuln' },
    { scriptId: 'smb-vuln-ms08-067', description: 'Check for Conficker (MS08-067)', category: 'vuln' },
    { scriptId: 'smb-protocols', description: 'Enumerate SMB protocol versions', category: 'discovery' },
    { scriptId: 'smb-security-mode', description: 'Check SMB security mode', category: 'discovery' },
  ],
  143: [
    { scriptId: 'imap-capabilities', description: 'List IMAP capabilities', category: 'discovery' },
    { scriptId: 'imap-brute', description: 'Brute-force IMAP credentials', category: 'brute' },
    { scriptId: 'imap-ntlm-info', description: 'Get NTLM info from IMAP', category: 'discovery' },
  ],
  389: [
    { scriptId: 'ldap-rootdse', description: 'Query LDAP root DSE', category: 'discovery' },
    { scriptId: 'ldap-search', description: 'Search LDAP directory', category: 'discovery' },
    { scriptId: 'ldap-brute', description: 'Brute-force LDAP credentials', category: 'brute' },
    { scriptId: 'ldap-novell-getpass', description: 'Attempt Novell LDAP password retrieval', category: 'vuln' },
  ],
  443: [
    { scriptId: 'ssl-cert', description: 'Show SSL/TLS certificate details', category: 'discovery' },
    { scriptId: 'ssl-enum-ciphers', description: 'Enumerate SSL/TLS cipher suites', category: 'discovery' },
    { scriptId: 'ssl-heartbleed', description: 'Check for Heartbleed vulnerability', category: 'vuln' },
    { scriptId: 'ssl-poodle', description: 'Check for POODLE vulnerability', category: 'vuln' },
    { scriptId: 'ssl-ccs-injection', description: 'Check for CCS injection vulnerability', category: 'vuln' },
    { scriptId: 'http-title', description: 'Get page title', category: 'discovery' },
    { scriptId: 'http-headers', description: 'Show HTTP response headers', category: 'discovery' },
    { scriptId: 'http-methods', description: 'Enumerate allowed HTTP methods', category: 'discovery' },
    { scriptId: 'http-enum', description: 'Enumerate common web paths', category: 'discovery' },
    { scriptId: 'tls-alpn', description: 'Enumerate TLS ALPN protocols', category: 'discovery' },
  ],
  445: [
    { scriptId: 'smb-os-discovery', description: 'Discover OS via SMB', category: 'discovery' },
    { scriptId: 'smb-enum-shares', description: 'Enumerate SMB shares', category: 'discovery' },
    { scriptId: 'smb-enum-users', description: 'Enumerate SMB users', category: 'discovery' },
    { scriptId: 'smb-vuln-ms17-010', description: 'Check for EternalBlue (MS17-010)', category: 'vuln' },
    { scriptId: 'smb-vuln-ms08-067', description: 'Check for Conficker (MS08-067)', category: 'vuln' },
    { scriptId: 'smb-protocols', description: 'Enumerate SMB protocol versions', category: 'discovery' },
    { scriptId: 'smb-security-mode', description: 'Check SMB security mode', category: 'discovery' },
    { scriptId: 'smb2-capabilities', description: 'List SMB2 capabilities', category: 'discovery' },
    { scriptId: 'smb2-security-mode', description: 'Check SMB2 security mode', category: 'discovery' },
  ],
  465: [
    { scriptId: 'ssl-cert', description: 'Show SSL/TLS certificate details', category: 'discovery' },
    { scriptId: 'ssl-enum-ciphers', description: 'Enumerate SSL/TLS cipher suites', category: 'discovery' },
    { scriptId: 'smtp-commands', description: 'List SMTP commands supported', category: 'discovery' },
  ],
  587: [
    { scriptId: 'smtp-commands', description: 'List SMTP commands supported', category: 'discovery' },
    { scriptId: 'smtp-enum-users', description: 'Enumerate SMTP users', category: 'discovery' },
    { scriptId: 'ssl-cert', description: 'Show SSL/TLS certificate details', category: 'discovery' },
  ],
  993: [
    { scriptId: 'ssl-cert', description: 'Show SSL/TLS certificate details', category: 'discovery' },
    { scriptId: 'imap-capabilities', description: 'List IMAP capabilities', category: 'discovery' },
  ],
  995: [
    { scriptId: 'ssl-cert', description: 'Show SSL/TLS certificate details', category: 'discovery' },
    { scriptId: 'pop3-capabilities', description: 'List POP3 capabilities', category: 'discovery' },
  ],
  1433: [
    { scriptId: 'ms-sql-info', description: 'Get SQL Server info', category: 'discovery' },
    { scriptId: 'ms-sql-brute', description: 'Brute-force SQL Server credentials', category: 'brute' },
    { scriptId: 'ms-sql-empty-password', description: 'Check for empty SA password', category: 'vuln' },
    { scriptId: 'ms-sql-config', description: 'Get SQL Server configuration', category: 'discovery' },
    { scriptId: 'ms-sql-ntlm-info', description: 'Get NTLM info from SQL Server', category: 'discovery' },
    { scriptId: 'ms-sql-tables', description: 'Enumerate SQL Server tables', category: 'discovery' },
  ],
  1521: [
    { scriptId: 'oracle-tns-version', description: 'Get Oracle TNS version', category: 'discovery' },
    { scriptId: 'oracle-sid-brute', description: 'Brute-force Oracle SIDs', category: 'brute' },
    { scriptId: 'oracle-brute', description: 'Brute-force Oracle credentials', category: 'brute' },
    { scriptId: 'oracle-enum-users', description: 'Enumerate Oracle users', category: 'discovery' },
  ],
  2049: [
    { scriptId: 'nfs-ls', description: 'List NFS exports', category: 'discovery' },
    { scriptId: 'nfs-showmount', description: 'Show NFS mounts', category: 'discovery' },
    { scriptId: 'nfs-statfs', description: 'Get NFS filesystem statistics', category: 'discovery' },
  ],
  3306: [
    { scriptId: 'mysql-info', description: 'Get MySQL server info', category: 'discovery' },
    { scriptId: 'mysql-brute', description: 'Brute-force MySQL credentials', category: 'brute' },
    { scriptId: 'mysql-empty-password', description: 'Check for empty root password', category: 'vuln' },
    { scriptId: 'mysql-databases', description: 'List MySQL databases', category: 'discovery' },
    { scriptId: 'mysql-users', description: 'List MySQL users', category: 'discovery' },
    { scriptId: 'mysql-enum', description: 'Enumerate MySQL info', category: 'discovery' },
  ],
  3389: [
    { scriptId: 'rdp-ntlm-info', description: 'Get NTLM info from RDP', category: 'discovery' },
    { scriptId: 'rdp-enum-encryption', description: 'Enumerate RDP encryption levels', category: 'discovery' },
    { scriptId: 'rdp-vuln-ms12-020', description: 'Check for MS12-020 RDP vulnerability', category: 'vuln' },
  ],
  5432: [
    { scriptId: 'pgsql-brute', description: 'Brute-force PostgreSQL credentials', category: 'brute' },
  ],
  5900: [
    { scriptId: 'vnc-info', description: 'Get VNC server info', category: 'discovery' },
    { scriptId: 'vnc-brute', description: 'Brute-force VNC credentials', category: 'brute' },
    { scriptId: 'realvnc-auth-bypass', description: 'Check for RealVNC auth bypass', category: 'vuln' },
  ],
  5985: [
    { scriptId: 'http-title', description: 'Get WinRM page title', category: 'discovery' },
  ],
  6379: [
    { scriptId: 'redis-info', description: 'Get Redis server info', category: 'discovery' },
    { scriptId: 'redis-brute', description: 'Brute-force Redis password', category: 'brute' },
  ],
  8080: [
    { scriptId: 'http-title', description: 'Get page title', category: 'discovery' },
    { scriptId: 'http-headers', description: 'Show HTTP response headers', category: 'discovery' },
    { scriptId: 'http-methods', description: 'Enumerate allowed HTTP methods', category: 'discovery' },
    { scriptId: 'http-enum', description: 'Enumerate common web paths', category: 'discovery' },
    { scriptId: 'http-open-proxy', description: 'Check for open HTTP proxy', category: 'vuln' },
  ],
  8443: [
    { scriptId: 'ssl-cert', description: 'Show SSL/TLS certificate details', category: 'discovery' },
    { scriptId: 'ssl-enum-ciphers', description: 'Enumerate SSL/TLS cipher suites', category: 'discovery' },
    { scriptId: 'http-title', description: 'Get page title', category: 'discovery' },
    { scriptId: 'http-headers', description: 'Show HTTP response headers', category: 'discovery' },
  ],
  27017: [
    { scriptId: 'mongodb-info', description: 'Get MongoDB server info', category: 'discovery' },
    { scriptId: 'mongodb-databases', description: 'List MongoDB databases', category: 'discovery' },
    { scriptId: 'mongodb-brute', description: 'Brute-force MongoDB credentials', category: 'brute' },
  ],
};

// Maps service names to relevant scripts (for any port)
const SERVICE_SCRIPTS: Record<string, ScriptSuggestion[]> = {
  http: [
    { scriptId: 'http-title', description: 'Get page title', category: 'discovery' },
    { scriptId: 'http-headers', description: 'Show HTTP response headers', category: 'discovery' },
    { scriptId: 'http-methods', description: 'Enumerate allowed HTTP methods', category: 'discovery' },
    { scriptId: 'http-enum', description: 'Enumerate common web paths', category: 'discovery' },
    { scriptId: 'http-robots.txt', description: 'Check robots.txt', category: 'discovery' },
    { scriptId: 'http-server-header', description: 'Show server header info', category: 'discovery' },
  ],
  https: [
    { scriptId: 'ssl-cert', description: 'Show SSL/TLS certificate details', category: 'discovery' },
    { scriptId: 'ssl-enum-ciphers', description: 'Enumerate SSL/TLS cipher suites', category: 'discovery' },
    { scriptId: 'ssl-heartbleed', description: 'Check for Heartbleed vulnerability', category: 'vuln' },
    { scriptId: 'http-title', description: 'Get page title', category: 'discovery' },
    { scriptId: 'http-headers', description: 'Show HTTP response headers', category: 'discovery' },
  ],
  ssh: [
    { scriptId: 'ssh-hostkey', description: 'Show SSH host key fingerprints', category: 'discovery' },
    { scriptId: 'ssh-auth-methods', description: 'List SSH authentication methods', category: 'auth' },
    { scriptId: 'ssh2-enum-algos', description: 'Enumerate SSH2 algorithms', category: 'discovery' },
  ],
  ftp: [
    { scriptId: 'ftp-anon', description: 'Check for anonymous FTP login', category: 'auth' },
    { scriptId: 'ftp-syst', description: 'Get FTP system type', category: 'discovery' },
  ],
  smtp: [
    { scriptId: 'smtp-commands', description: 'List SMTP commands supported', category: 'discovery' },
    { scriptId: 'smtp-enum-users', description: 'Enumerate SMTP users via VRFY/EXPN/RCPT', category: 'discovery' },
    { scriptId: 'smtp-open-relay', description: 'Check for open SMTP relay', category: 'vuln' },
  ],
  mysql: [
    { scriptId: 'mysql-info', description: 'Get MySQL server info', category: 'discovery' },
    { scriptId: 'mysql-empty-password', description: 'Check for empty root password', category: 'vuln' },
    { scriptId: 'mysql-databases', description: 'List MySQL databases', category: 'discovery' },
  ],
  'ms-sql-s': [
    { scriptId: 'ms-sql-info', description: 'Get SQL Server info', category: 'discovery' },
    { scriptId: 'ms-sql-empty-password', description: 'Check for empty SA password', category: 'vuln' },
    { scriptId: 'ms-sql-config', description: 'Get SQL Server configuration', category: 'discovery' },
  ],
  postgresql: [
    { scriptId: 'pgsql-brute', description: 'Brute-force PostgreSQL credentials', category: 'brute' },
  ],
  vnc: [
    { scriptId: 'vnc-info', description: 'Get VNC server info', category: 'discovery' },
    { scriptId: 'vnc-brute', description: 'Brute-force VNC credentials', category: 'brute' },
    { scriptId: 'realvnc-auth-bypass', description: 'Check for RealVNC auth bypass', category: 'vuln' },
  ],
  rdp: [
    { scriptId: 'rdp-ntlm-info', description: 'Get NTLM info from RDP', category: 'discovery' },
    { scriptId: 'rdp-enum-encryption', description: 'Enumerate RDP encryption levels', category: 'discovery' },
  ],
  'ms-wbt-server': [
    { scriptId: 'rdp-ntlm-info', description: 'Get NTLM info from RDP', category: 'discovery' },
    { scriptId: 'rdp-enum-encryption', description: 'Enumerate RDP encryption levels', category: 'discovery' },
    { scriptId: 'rdp-vuln-ms12-020', description: 'Check for MS12-020 RDP vulnerability', category: 'vuln' },
  ],
  dns: [
    { scriptId: 'dns-zone-transfer', description: 'Attempt DNS zone transfer (AXFR)', category: 'discovery' },
    { scriptId: 'dns-recursion', description: 'Check for open DNS recursion', category: 'vuln' },
    { scriptId: 'dns-cache-snoop', description: 'Snoop DNS cache for common domains', category: 'discovery' },
  ],
  domain: [
    { scriptId: 'dns-zone-transfer', description: 'Attempt DNS zone transfer (AXFR)', category: 'discovery' },
    { scriptId: 'dns-recursion', description: 'Check for open DNS recursion', category: 'vuln' },
  ],
  snmp: [
    { scriptId: 'snmp-info', description: 'Get SNMP system info', category: 'discovery' },
    { scriptId: 'snmp-brute', description: 'Brute-force SNMP community strings', category: 'brute' },
    { scriptId: 'snmp-interfaces', description: 'Enumerate SNMP interfaces', category: 'discovery' },
    { scriptId: 'snmp-processes', description: 'List SNMP running processes', category: 'discovery' },
    { scriptId: 'snmp-netstat', description: 'Get SNMP network stats', category: 'discovery' },
  ],
  smb: [
    { scriptId: 'smb-os-discovery', description: 'Discover OS via SMB', category: 'discovery' },
    { scriptId: 'smb-enum-shares', description: 'Enumerate SMB shares', category: 'discovery' },
    { scriptId: 'smb-enum-users', description: 'Enumerate SMB users', category: 'discovery' },
    { scriptId: 'smb-vuln-ms17-010', description: 'Check for EternalBlue (MS17-010)', category: 'vuln' },
    { scriptId: 'smb-protocols', description: 'Enumerate SMB protocol versions', category: 'discovery' },
  ],
  'microsoft-ds': [
    { scriptId: 'smb-os-discovery', description: 'Discover OS via SMB', category: 'discovery' },
    { scriptId: 'smb-enum-shares', description: 'Enumerate SMB shares', category: 'discovery' },
    { scriptId: 'smb-vuln-ms17-010', description: 'Check for EternalBlue (MS17-010)', category: 'vuln' },
  ],
  telnet: [
    { scriptId: 'telnet-brute', description: 'Brute-force telnet credentials', category: 'brute' },
    { scriptId: 'telnet-encryption', description: 'Check telnet encryption support', category: 'discovery' },
  ],
  ldap: [
    { scriptId: 'ldap-rootdse', description: 'Query LDAP root DSE', category: 'discovery' },
    { scriptId: 'ldap-search', description: 'Search LDAP directory', category: 'discovery' },
  ],
  redis: [
    { scriptId: 'redis-info', description: 'Get Redis server info', category: 'discovery' },
    { scriptId: 'redis-brute', description: 'Brute-force Redis password', category: 'brute' },
  ],
  mongodb: [
    { scriptId: 'mongodb-info', description: 'Get MongoDB server info', category: 'discovery' },
    { scriptId: 'mongodb-databases', description: 'List MongoDB databases', category: 'discovery' },
  ],
};

/**
 * Get script suggestions for a given port number and optional service name.
 * Deduplicates by scriptId, prioritizing port-specific over service-generic.
 */
export function getScriptSuggestions(portId: number, serviceName?: string): ScriptSuggestion[] {
  const seen = new Set<string>();
  const results: ScriptSuggestion[] = [];

  // Port-specific scripts first
  const portScripts = PORT_SCRIPTS[portId] || [];
  for (const s of portScripts) {
    if (!seen.has(s.scriptId)) {
      seen.add(s.scriptId);
      results.push(s);
    }
  }

  // Service-based scripts
  if (serviceName) {
    const svcScripts = SERVICE_SCRIPTS[serviceName.toLowerCase()] || [];
    for (const s of svcScripts) {
      if (!seen.has(s.scriptId)) {
        seen.add(s.scriptId);
        results.push(s);
      }
    }
  }

  // SSL-related ports always get ssl scripts
  const sslPorts = [443, 465, 587, 636, 853, 993, 995, 8443];
  if (sslPorts.includes(portId) && !seen.has('ssl-cert')) {
    results.push({ scriptId: 'ssl-cert', description: 'Show SSL/TLS certificate details', category: 'discovery' });
    if (!seen.has('ssl-enum-ciphers')) {
      results.push({ scriptId: 'ssl-enum-ciphers', description: 'Enumerate SSL/TLS cipher suites', category: 'discovery' });
    }
  }

  return results;
}

/**
 * Generate an nmap command for running suggested scripts against a target.
 */
export function generateNmapCommand(
  ip: string,
  portId: number,
  protocol: string,
  scripts: string[]
): string {
  // Validate IP (IPv4/IPv6 chars only) to prevent argument injection
  if (!/^[\da-fA-F.:]+$/.test(ip)) return '# invalid IP address';
  // Validate script names (alphanumeric, hyphens, dots, underscores)
  for (const s of scripts) {
    if (!/^[a-zA-Z0-9_.-]+$/.test(s)) return '# invalid script name';
  }
  const scriptArg = scripts.join(',');
  const protocolFlag = protocol === 'udp' ? '-sU' : '-sS';
  return `nmap ${protocolFlag} -p ${portId} --script=${scriptArg} ${ip}`;
}
