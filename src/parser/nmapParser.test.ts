import { describe, it, expect } from 'vitest';
import { parseNmapXML, parseNmapGreppable, parseNmapNormal, parseNmapOutput } from './nmapParser';

// Minimal valid nmap XML for testing
const MINIMAL_XML = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV 192.168.1.1" start="1700000000" startstr="Tue Nov 14 2023" version="7.94" xmloutputversion="1.05">
  <scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
  <verbose level="0"/>
  <debugging level="0"/>
  <host starttime="1700000001" endtime="1700000010">
    <status state="up" reason="syn-ack" reason_ttl="64"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="TestVendor"/>
    <hostnames>
      <hostname name="router.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu" method="probed" conf="10">
          <cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="nginx" version="1.18.0" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset" reason_ttl="64"/>
        <service name="https" method="table" conf="3"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.4" accuracy="95" line="1">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="95">
          <cpe>cpe:/o:linux:linux_kernel:5.4</cpe>
        </osclass>
      </osmatch>
    </os>
    <uptime seconds="86400" lastboot="Mon Nov 13 2023"/>
    <distance value="1"/>
    <tcpsequence index="260" difficulty="Good luck!" values="A,B,C"/>
    <times srtt="1234" rttvar="567" to="100000"/>
    <trace port="80" proto="tcp">
      <hop ttl="1" rtt="0.50" ipaddr="192.168.1.1" host="router.local"/>
    </trace>
    <hostscript>
      <script id="smb-os-discovery" output="OS: Linux"/>
    </hostscript>
  </host>
  <host>
    <status state="down" reason="no-response" reason_ttl="0"/>
    <address addr="192.168.1.2" addrtype="ipv4"/>
  </host>
  <runstats>
    <finished time="1700000020" timestr="Tue Nov 14 2023" elapsed="20" summary="2 hosts scanned" exit="success"/>
    <hosts up="1" down="1" total="2"/>
  </runstats>
</nmaprun>`;

// XML with HTML entities (the bug that was fixed)
const XML_WITH_ENTITIES = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap &#45;&#45;privileged -sV 10.0.0.1" start="1700000000" startstr="test" version="7.94" xmloutputversion="1.05">
  <verbose level="0"/>
  <debugging level="0"/>
  <host>
    <status state="up" reason="arp-response" reason_ttl="0"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" method="table" conf="3"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1700000001" elapsed="1" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>`;

// Multi-host XML
const MULTI_HOST_XML = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sS 10.0.0.0/24" start="1700000000" startstr="test" version="7.94" xmloutputversion="1.05">
  <verbose level="0"/>
  <debugging level="0"/>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" method="table" conf="3"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" method="table" conf="3"/></port>
    </ports>
  </host>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <address addr="fe80::1" addrtype="ipv6"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" method="table" conf="3"/></port>
      <port protocol="tcp" portid="443"><state state="filtered"/><service name="https" method="table" conf="3"/></port>
    </ports>
  </host>
  <runstats>
    <finished time="1700000010" elapsed="10" exit="success"/>
    <hosts up="2" down="0" total="2"/>
  </runstats>
</nmaprun>`;

describe('parseNmapXML', () => {
  it('parses a minimal valid XML scan', () => {
    const scan = parseNmapXML(MINIMAL_XML);
    expect(scan.scanner).toBe('nmap');
    expect(scan.args).toBe('nmap -sV 192.168.1.1');
    expect(scan.version).toBe('7.94');
    expect(scan.start).toBe(1700000000);
    expect(scan.totalHosts).toBe(2);
    expect(scan.hostsUp).toBe(1);
    expect(scan.hostsDown).toBe(1);
    expect(scan.scanDuration).toBe(20);
  });

  it('parses scaninfo correctly', () => {
    const scan = parseNmapXML(MINIMAL_XML);
    expect(scan.scaninfo).toHaveLength(1);
    expect(scan.scaninfo[0].type).toBe('syn');
    expect(scan.scaninfo[0].protocol).toBe('tcp');
    expect(scan.scaninfo[0].numservices).toBe(1000);
  });

  it('parses host addresses', () => {
    const scan = parseNmapXML(MINIMAL_XML);
    const host = scan.hosts[0];
    expect(host.ip).toBe('192.168.1.1');
    expect(host.mac).toBe('AA:BB:CC:DD:EE:FF');
    expect(host.addresses).toHaveLength(2);
    expect(host.addresses[1].vendor).toBe('TestVendor');
  });

  it('parses hostnames', () => {
    const scan = parseNmapXML(MINIMAL_XML);
    const host = scan.hosts[0];
    expect(host.hostname).toBe('router.local');
    expect(host.hostnames[0].type).toBe('PTR');
  });

  it('parses ports and services', () => {
    const scan = parseNmapXML(MINIMAL_XML);
    const host = scan.hosts[0];
    expect(host.ports).toHaveLength(3);

    const sshPort = host.ports[0];
    expect(sshPort.portid).toBe(22);
    expect(sshPort.protocol).toBe('tcp');
    expect(sshPort.state.state).toBe('open');
    expect(sshPort.service?.name).toBe('ssh');
    expect(sshPort.service?.product).toBe('OpenSSH');
    expect(sshPort.service?.version).toBe('8.9p1');
    expect(sshPort.service?.extrainfo).toBe('Ubuntu');
    expect(sshPort.service?.cpes).toContain('cpe:/a:openbsd:openssh:8.9p1');

    const httpsPort = host.ports[2];
    expect(httpsPort.state.state).toBe('closed');
  });

  it('counts ports correctly', () => {
    const scan = parseNmapXML(MINIMAL_XML);
    const host = scan.hosts[0];
    expect(host.openPortCount).toBe(2);
    expect(host.closedPortCount).toBe(1);
    expect(host.filteredPortCount).toBe(0);
  });

  it('parses OS info', () => {
    const scan = parseNmapXML(MINIMAL_XML);
    const host = scan.hosts[0];
    expect(host.mainOS).toBe('Linux 5.4');
    expect(host.os.osmatch[0].accuracy).toBe(95);
    expect(host.os.osmatch[0].osclass[0].osfamily).toBe('Linux');
    expect(host.os.osmatch[0].osclass[0].cpes).toContain('cpe:/o:linux:linux_kernel:5.4');
  });

  it('parses uptime and distance', () => {
    const scan = parseNmapXML(MINIMAL_XML);
    const host = scan.hosts[0];
    expect(host.uptime?.seconds).toBe(86400);
    expect(host.uptime?.lastboot).toBe('Mon Nov 13 2023');
    expect(host.distance).toBe(1);
  });

  it('parses TCP sequence info', () => {
    const scan = parseNmapXML(MINIMAL_XML);
    const host = scan.hosts[0];
    expect(host.tcpsequence?.difficulty).toBe('Good luck!');
    expect(host.tcpsequence?.index).toBe(260);
  });

  it('parses times', () => {
    const scan = parseNmapXML(MINIMAL_XML);
    const host = scan.hosts[0];
    expect(host.times?.srtt).toBe(1234);
  });

  it('parses trace', () => {
    const scan = parseNmapXML(MINIMAL_XML);
    const host = scan.hosts[0];
    expect(host.trace?.port).toBe(80);
    expect(host.trace?.hops).toHaveLength(1);
    expect(host.trace?.hops[0].ipaddr).toBe('192.168.1.1');
  });

  it('parses host scripts', () => {
    const scan = parseNmapXML(MINIMAL_XML);
    const host = scan.hosts[0];
    expect(host.hostscripts).toHaveLength(1);
    expect(host.hostscripts[0].id).toBe('smb-os-discovery');
    expect(host.hostscripts[0].output).toBe('OS: Linux');
  });

  it('parses runstats', () => {
    const scan = parseNmapXML(MINIMAL_XML);
    expect(scan.runstats.hosts.up).toBe(1);
    expect(scan.runstats.hosts.down).toBe(1);
    expect(scan.runstats.hosts.total).toBe(2);
    expect(scan.runstats.finished.exit).toBe('success');
  });

  it('handles down hosts with no ports', () => {
    const scan = parseNmapXML(MINIMAL_XML);
    const downHost = scan.hosts[1];
    expect(downHost.status.state).toBe('down');
    expect(downHost.ip).toBe('192.168.1.2');
    expect(downHost.ports).toHaveLength(0);
    expect(downHost.openPortCount).toBe(0);
  });

  it('decodes HTML entities in XML attributes', () => {
    const scan = parseNmapXML(XML_WITH_ENTITIES);
    // &#45; should be decoded to -
    expect(scan.args).toBe('nmap --privileged -sV 10.0.0.1');
    expect(scan.args).not.toContain('&#45;');
  });

  it('computes port summaries across hosts', () => {
    const scan = parseNmapXML(MULTI_HOST_XML);
    expect(scan.uniquePorts.length).toBeGreaterThan(0);
    const sshSummary = scan.uniquePorts.find(p => p.port === 22 && p.state === 'open');
    expect(sshSummary).toBeDefined();
    expect(sshSummary!.count).toBe(2);
    expect(sshSummary!.hosts).toContain('10.0.0.1');
    expect(sshSummary!.hosts).toContain('10.0.0.2');
  });

  it('computes service summaries across hosts', () => {
    const scan = parseNmapXML(MULTI_HOST_XML);
    const sshService = scan.uniqueServices.find(s => s.name === 'ssh');
    expect(sshService).toBeDefined();
    expect(sshService!.count).toBe(2);
  });

  it('parses IPv6 addresses', () => {
    const scan = parseNmapXML(MULTI_HOST_XML);
    const host2 = scan.hosts[1];
    expect(host2.ipv6).toBe('fe80::1');
  });

  it('throws on invalid XML without nmaprun', () => {
    expect(() => parseNmapXML('<root><invalid/></root>')).toThrow('Invalid Nmap XML');
  });

  it('generates unique IDs for each host', () => {
    const scan = parseNmapXML(MULTI_HOST_XML);
    const ids = scan.hosts.map(h => h.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

// ========== Greppable Output Tests ==========

const GREPPABLE_OUTPUT = `# Nmap 7.94 scan initiated Tue Nov 14 2023 as: nmap -sV -oG output.gnmap 192.168.1.0/24
Host: 192.168.1.1 (router.local)\tPorts: 22/open/tcp//ssh//OpenSSH 8.9p1/, 80/open/tcp//http//nginx 1.18.0/, 443/closed/tcp//https///
Host: 192.168.1.5 ()\tPorts: 3306/open/tcp//mysql//MySQL 8.0/
# Nmap done at Tue Nov 14 2023 -- 256 IP addresses scanned`;

const GREPPABLE_NO_STATUS_LINE = `# Nmap 7.94 scan initiated Mon Jan 01 2024 as: nmap -sS -oG - 10.0.0.1
Host: 10.0.0.1 (server.test)\tPorts: 22/open/tcp//ssh//OpenSSH/, 80/open/tcp//http///`;

describe('parseNmapGreppable', () => {
  it('parses hosts from greppable output', () => {
    const scan = parseNmapGreppable(GREPPABLE_OUTPUT);
    expect(scan.hosts).toHaveLength(2);
    expect(scan.args).toBe('nmap -sV -oG output.gnmap 192.168.1.0/24');
  });

  it('parses IP and hostname', () => {
    const scan = parseNmapGreppable(GREPPABLE_OUTPUT);
    expect(scan.hosts[0].ip).toBe('192.168.1.1');
    expect(scan.hosts[0].hostname).toBe('router.local');
  });

  it('parses ports from greppable format', () => {
    const scan = parseNmapGreppable(GREPPABLE_OUTPUT);
    const host = scan.hosts[0];
    expect(host.ports).toHaveLength(3);
    expect(host.ports[0].portid).toBe(22);
    expect(host.ports[0].state.state).toBe('open');
    expect(host.ports[0].service?.name).toBe('ssh');
    expect(host.ports[2].state.state).toBe('closed');
  });

  it('counts open/closed ports correctly', () => {
    const scan = parseNmapGreppable(GREPPABLE_OUTPUT);
    const host = scan.hosts[0];
    expect(host.openPortCount).toBe(2);
    expect(host.closedPortCount).toBe(1);
  });

  it('marks host as up when ports are open (no explicit Status line)', () => {
    const scan = parseNmapGreppable(GREPPABLE_NO_STATUS_LINE);
    expect(scan.hosts).toHaveLength(1);
    expect(scan.hosts[0].status.state).toBe('up');
    expect(scan.hosts[0].openPortCount).toBe(2);
  });

  it('handles hosts with empty hostname', () => {
    const scan = parseNmapGreppable(GREPPABLE_OUTPUT);
    const host2 = scan.hosts[1];
    expect(host2.hostname).toBe('');
  });

  it('computes summary statistics', () => {
    const scan = parseNmapGreppable(GREPPABLE_OUTPUT);
    expect(scan.totalHosts).toBe(2);
    expect(scan.hostsUp).toBe(2);
  });
});

// ========== Normal Output Tests ==========

const NORMAL_OUTPUT = `Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-14 10:00 UTC
Nmap scan report for router.local (192.168.1.1)
Host is up (0.001s latency).
PORT    STATE  SERVICE  VERSION
22/tcp  open   ssh      OpenSSH 8.9p1 Ubuntu 3
80/tcp  open   http     nginx 1.18.0
443/tcp closed https
MAC Address: AA:BB:CC:DD:EE:FF (TestVendor)
OS details: Linux 5.4
Network Distance: 1 hop
Uptime guess: 1.5 days (since Mon Nov 13 2023)

Nmap scan report for 192.168.1.2
Host is down (no-response).

Nmap done: 2 IP addresses (1 host up) scanned in 5.00 seconds`;

const NORMAL_WITH_AGGRESSIVE_OS = `Starting Nmap 7.94 at 2023-11-14 10:00
Nmap scan report for 10.0.0.5
Host is up.
PORT   STATE SERVICE
22/tcp open  ssh
Aggressive OS guesses: Linux 5.15 (96%), Linux 4.15 (90%), FreeBSD 13.0 (85%)`;

describe('parseNmapNormal', () => {
  it('parses hosts from normal output', () => {
    const scan = parseNmapNormal(NORMAL_OUTPUT);
    expect(scan.hosts).toHaveLength(2);
    expect(scan.version).toBe('7.94');
  });

  it('parses host IP and hostname', () => {
    const scan = parseNmapNormal(NORMAL_OUTPUT);
    const host = scan.hosts[0];
    expect(host.ip).toBe('192.168.1.1');
    expect(host.hostname).toBe('router.local');
  });

  it('parses ports from normal output', () => {
    const scan = parseNmapNormal(NORMAL_OUTPUT);
    const host = scan.hosts[0];
    expect(host.ports).toHaveLength(3);
    expect(host.ports[0].portid).toBe(22);
    expect(host.ports[0].state.state).toBe('open');
    expect(host.ports[0].service?.name).toBe('ssh');
    // Normal parser captures rest of line as product (version gets folded in)
    expect(host.ports[0].service?.product).toContain('OpenSSH');
    expect(host.ports[1].service?.product).toContain('nginx');
  });

  it('parses MAC address and vendor', () => {
    const scan = parseNmapNormal(NORMAL_OUTPUT);
    const host = scan.hosts[0];
    expect(host.mac).toBe('AA:BB:CC:DD:EE:FF');
    expect(host.addresses.find(a => a.addrtype === 'mac')?.vendor).toBe('TestVendor');
  });

  it('parses OS details', () => {
    const scan = parseNmapNormal(NORMAL_OUTPUT);
    expect(scan.hosts[0].mainOS).toBe('Linux 5.4');
  });

  it('parses network distance', () => {
    const scan = parseNmapNormal(NORMAL_OUTPUT);
    expect(scan.hosts[0].distance).toBe(1);
  });

  it('parses uptime', () => {
    const scan = parseNmapNormal(NORMAL_OUTPUT);
    const uptime = scan.hosts[0].uptime;
    expect(uptime).not.toBeNull();
    expect(uptime!.seconds).toBe(Math.round(1.5 * 86400));
    expect(uptime!.lastboot).toBe('Mon Nov 13 2023');
  });

  it('parses down hosts', () => {
    const scan = parseNmapNormal(NORMAL_OUTPUT);
    const downHost = scan.hosts[1];
    expect(downHost.status.state).toBe('down');
    expect(downHost.ip).toBe('192.168.1.2');
  });

  it('parses aggressive OS guesses', () => {
    const scan = parseNmapNormal(NORMAL_WITH_AGGRESSIVE_OS);
    expect(scan.hosts[0].mainOS).toBe('Linux 5.15');
  });
});

// ========== Auto-detect Format Tests ==========

describe('parseNmapOutput', () => {
  it('auto-detects XML format', () => {
    const scan = parseNmapOutput(MINIMAL_XML);
    expect(scan.scanner).toBe('nmap');
    expect(scan.hosts.length).toBeGreaterThan(0);
  });

  it('auto-detects greppable format', () => {
    const scan = parseNmapOutput(GREPPABLE_OUTPUT);
    expect(scan.hosts.length).toBeGreaterThan(0);
  });

  it('auto-detects normal format', () => {
    const scan = parseNmapOutput(NORMAL_OUTPUT);
    expect(scan.hosts.length).toBeGreaterThan(0);
  });

  it('throws on unrecognized format', () => {
    expect(() => parseNmapOutput('this is not nmap output')).toThrow('Unrecognized nmap output format');
  });
});
