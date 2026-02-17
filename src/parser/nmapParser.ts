import { XMLParser } from 'fast-xml-parser';
import type {
  NmapScan, NmapHost, ScanInfo, RunStats, Address, Hostname,
  Port, PortState, Service, Script, ScriptElement, OSInfo, OSMatch,
  OSClass, PortUsed, Uptime, TCPSequence, IPIDSequence, TCPTSSequence,
  Times, TraceInfo, TraceHop, HostStatus, Smurf, PortSummary, ServiceSummary,
} from '../types/nmap';

function generateId(): string {
  return `host-${crypto.randomUUID()}`;
}

function ensureArray<T>(val: T | T[] | undefined | null): T[] {
  if (val === undefined || val === null) return [];
  return Array.isArray(val) ? val : [val];
}

function getAttr(obj: any, key: string, defaultVal: any = ''): any {
  if (!obj) return defaultVal;
  // fast-xml-parser puts attributes with @ prefix when attributeNamePrefix is set
  return obj[`@_${key}`] ?? obj[key] ?? defaultVal;
}

function toNum(val: any, defaultVal: number = 0): number {
  const n = Number(val);
  return isNaN(n) ? defaultVal : n;
}

export function parseNmapXML(xmlContent: string): NmapScan {

  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    allowBooleanAttributes: true,
    parseAttributeValue: false,
    processEntities: true,
    htmlEntities: true,
    trimValues: true,
    isArray: (name: string) => {
      const arrayTags = [
        'host', 'port', 'hostname', 'address', 'osmatch', 'osclass',
        'portused', 'table', 'elem', 'script', 'hop', 'scaninfo',
        'cpe', 'smurf',
      ];
      return arrayTags.includes(name);
    },
  });

  const parsed = parser.parse(xmlContent);
  const nmaprun = parsed.nmaprun;

  if (!nmaprun) {
    throw new Error('Invalid Nmap XML: missing <nmaprun> root element');
  }

  const scan: NmapScan = {
    scanner: getAttr(nmaprun, 'scanner', 'nmap'),
    args: getAttr(nmaprun, 'args'),
    start: toNum(getAttr(nmaprun, 'start')),
    startstr: getAttr(nmaprun, 'startstr'),
    version: getAttr(nmaprun, 'version'),
    xmloutputversion: getAttr(nmaprun, 'xmloutputversion'),
    scaninfo: parseScanInfo(nmaprun.scaninfo),
    verbose: toNum(getAttr(nmaprun.verbose, 'level')),
    debugging: toNum(getAttr(nmaprun.debugging, 'level')),
    hosts: parseHosts(nmaprun.host),
    runstats: parseRunStats(nmaprun.runstats),
    totalHosts: 0,
    hostsUp: 0,
    hostsDown: 0,
    hostsFiltered: 0,
    scanDuration: 0,
    uniquePorts: [],
    uniqueServices: [],
  };

  // Compute derived fields
  scan.totalHosts = scan.hosts.length;
  scan.hostsUp = scan.hosts.filter(h => h.status.state === 'up').length;
  scan.hostsDown = scan.hosts.filter(h => h.status.state === 'down').length;
  // hostsFiltered = hosts not classified as up or down (unknown, skipped, etc.)
  scan.hostsFiltered = scan.hosts.filter(h => h.status.state !== 'up' && h.status.state !== 'down').length;
  scan.scanDuration = scan.runstats.finished.elapsed;
  scan.uniquePorts = computePortSummaries(scan.hosts);
  scan.uniqueServices = computeServiceSummaries(scan.hosts);

  return scan;
}

function parseScanInfo(raw: any): ScanInfo[] {
  return ensureArray(raw).map((si: any) => ({
    type: getAttr(si, 'type'),
    protocol: getAttr(si, 'protocol'),
    numservices: toNum(getAttr(si, 'numservices')),
    services: getAttr(si, 'services'),
  }));
}

function parseRunStats(raw: any): RunStats {
  if (!raw) {
    return {
      finished: { time: 0, timestr: '', elapsed: 0, summary: '', exit: '' },
      hosts: { up: 0, down: 0, total: 0 },
    };
  }
  return {
    finished: {
      time: toNum(getAttr(raw.finished, 'time')),
      timestr: getAttr(raw.finished, 'timestr'),
      elapsed: toNum(getAttr(raw.finished, 'elapsed')),
      summary: getAttr(raw.finished, 'summary'),
      exit: getAttr(raw.finished, 'exit'),
    },
    hosts: {
      up: toNum(getAttr(raw.hosts, 'up')),
      down: toNum(getAttr(raw.hosts, 'down')),
      total: toNum(getAttr(raw.hosts, 'total')),
    },
  };
}

function parseHosts(rawHosts: any): NmapHost[] {
  return ensureArray(rawHosts).map(parseHost);
}

function parseHost(raw: any): NmapHost {
  const addresses = parseAddresses(raw.address);
  const hostnames = parseHostnames(raw.hostnames);
  const ports = parsePorts(raw.ports);
  const os = parseOS(raw.os);
  const status = parseHostStatus(raw.status);

  const ip = addresses.find(a => a.addrtype === 'ipv4')?.addr || '';
  const ipv6 = addresses.find(a => a.addrtype === 'ipv6')?.addr || '';
  const mac = addresses.find(a => a.addrtype === 'mac')?.addr || '';
  const hostname = hostnames.length > 0 ? hostnames[0].name : '';
  const mainOS = os.osmatch.length > 0 ? os.osmatch[0].name : '';

  return {
    id: generateId(),
    starttime: toNum(getAttr(raw, 'starttime')),
    endtime: toNum(getAttr(raw, 'endtime')),
    status,
    addresses,
    hostnames,
    ports,
    os,
    uptime: parseUptime(raw.uptime),
    distance: raw.distance ? toNum(getAttr(raw.distance, 'value')) : null,
    tcpsequence: parseTCPSequence(raw.tcpsequence),
    ipidsequence: parseIPIDSequence(raw.ipidsequence),
    tcptssequence: parseTCPTSSequence(raw.tcptssequence),
    times: parseTimes(raw.times),
    trace: parseTrace(raw.trace),
    hostscripts: parseScripts(raw.hostscript),
    smurfs: parseSmurfs(raw.smurf),
    ip,
    ipv6,
    mac,
    hostname,
    mainOS,
    openPortCount: ports.filter(p => p.state.state === 'open').length,
    closedPortCount: ports.filter(p => p.state.state === 'closed').length,
    filteredPortCount: ports.filter(p => p.state.state === 'filtered' || p.state.state === 'open|filtered').length,
  };
}

function parseHostStatus(raw: any): HostStatus {
  if (!raw) return { state: 'unknown', reason: '', reason_ttl: 0 };
  return {
    state: getAttr(raw, 'state', 'unknown') as HostStatus['state'],
    reason: getAttr(raw, 'reason'),
    reason_ttl: toNum(getAttr(raw, 'reason_ttl')),
  };
}

function parseAddresses(raw: any): Address[] {
  return ensureArray(raw).map((a: any) => ({
    addr: getAttr(a, 'addr'),
    addrtype: getAttr(a, 'addrtype', 'ipv4') as Address['addrtype'],
    vendor: getAttr(a, 'vendor') || undefined,
  }));
}

function parseHostnames(raw: any): Hostname[] {
  if (!raw) return [];
  const hostnames = raw.hostname || raw;
  return ensureArray(hostnames).map((h: any) => ({
    name: getAttr(h, 'name'),
    type: getAttr(h, 'type', '') as Hostname['type'],
  })).filter((h: Hostname) => h.name);
}

function parsePorts(raw: any): Port[] {
  if (!raw) return [];
  const portsNode = raw.port || raw;
  return ensureArray(portsNode).map((p: any) => ({
    protocol: getAttr(p, 'protocol', 'tcp'),
    portid: toNum(getAttr(p, 'portid')),
    state: parsePortState(p.state),
    service: parseService(p.service),
    scripts: parseScripts(p.script ? { script: p.script } : null),
    owner: getAttr(p.owner, 'name') || undefined,
  }));
}

function parsePortState(raw: any): PortState {
  if (!raw) return { state: 'unknown', reason: '', reason_ttl: 0 };
  return {
    state: getAttr(raw, 'state', 'unknown'),
    reason: getAttr(raw, 'reason'),
    reason_ttl: toNum(getAttr(raw, 'reason_ttl')),
    reason_ip: getAttr(raw, 'reason_ip') || undefined,
  };
}

function parseService(raw: any): Service | null {
  if (!raw) return null;
  return {
    name: getAttr(raw, 'name'),
    product: getAttr(raw, 'product') || undefined,
    version: getAttr(raw, 'version') || undefined,
    extrainfo: getAttr(raw, 'extrainfo') || undefined,
    ostype: getAttr(raw, 'ostype') || undefined,
    method: getAttr(raw, 'method', 'table'),
    conf: toNum(getAttr(raw, 'conf')),
    tunnel: getAttr(raw, 'tunnel') || undefined,
    proto: getAttr(raw, 'proto') || undefined,
    rpcnum: getAttr(raw, 'rpcnum') || undefined,
    lowver: getAttr(raw, 'lowver') || undefined,
    highver: getAttr(raw, 'highver') || undefined,
    hostname: getAttr(raw, 'hostname') || undefined,
    servicefp: getAttr(raw, 'servicefp') || undefined,
    devicetype: getAttr(raw, 'devicetype') || undefined,
    cpes: ensureArray(raw.cpe).map((c: any) => typeof c === 'string' ? c : String(c)),
  };
}

function parseScripts(raw: any): Script[] {
  if (!raw) return [];
  const scripts = raw.script || raw;
  return ensureArray(scripts).map((s: any) => ({
    id: getAttr(s, 'id'),
    output: getAttr(s, 'output'),
    elements: parseScriptElements(s),
  })).filter((s: Script) => s.id);
}

function parseScriptElements(raw: any): ScriptElement[] {
  const elements: ScriptElement[] = [];
  // Handle <table> elements
  const tables = ensureArray(raw.table);
  for (const table of tables) {
    const key = getAttr(table, 'key', 'table');
    elements.push({
      key,
      value: '',
      children: parseScriptElements(table),
    });
  }
  // Handle <elem> elements
  const elems = ensureArray(raw.elem);
  for (const elem of elems) {
    if (typeof elem === 'string' || typeof elem === 'number') {
      elements.push({ key: '', value: String(elem) });
    } else {
      elements.push({
        key: getAttr(elem, 'key', ''),
        value: elem['#text'] !== undefined ? String(elem['#text']) : '',
      });
    }
  }
  return elements;
}

function parseOS(raw: any): OSInfo {
  if (!raw) return { osmatch: [], osfingerprint: [], portused: [] };
  return {
    osmatch: ensureArray(raw.osmatch).map((om: any) => ({
      name: getAttr(om, 'name'),
      accuracy: toNum(getAttr(om, 'accuracy')),
      line: toNum(getAttr(om, 'line')),
      osclass: ensureArray(om.osclass).map((oc: any) => ({
        type: getAttr(oc, 'type'),
        vendor: getAttr(oc, 'vendor'),
        osfamily: getAttr(oc, 'osfamily'),
        osgen: getAttr(oc, 'osgen'),
        accuracy: toNum(getAttr(oc, 'accuracy')),
        cpes: ensureArray(oc.cpe).map((c: any) => typeof c === 'string' ? c : String(c)),
      } as OSClass)),
    } as OSMatch)),
    osfingerprint: ensureArray(raw.osfingerprint).map((of_: any) =>
      getAttr(of_, 'fingerprint', '')
    ).filter(Boolean),
    portused: ensureArray(raw.portused).map((pu: any) => ({
      state: getAttr(pu, 'state'),
      proto: getAttr(pu, 'proto'),
      portid: toNum(getAttr(pu, 'portid')),
    } as PortUsed)),
  };
}

function parseUptime(raw: any): Uptime | null {
  if (!raw) return null;
  return {
    seconds: toNum(getAttr(raw, 'seconds')),
    lastboot: getAttr(raw, 'lastboot'),
  };
}

function parseTCPSequence(raw: any): TCPSequence | null {
  if (!raw) return null;
  return {
    index: toNum(getAttr(raw, 'index')),
    difficulty: getAttr(raw, 'difficulty'),
    values: getAttr(raw, 'values'),
  };
}

function parseIPIDSequence(raw: any): IPIDSequence | null {
  if (!raw) return null;
  return {
    class: getAttr(raw, 'class'),
    values: getAttr(raw, 'values'),
  };
}

function parseTCPTSSequence(raw: any): TCPTSSequence | null {
  if (!raw) return null;
  return {
    class: getAttr(raw, 'class'),
    values: getAttr(raw, 'values'),
  };
}

function parseTimes(raw: any): Times | null {
  if (!raw) return null;
  return {
    srtt: toNum(getAttr(raw, 'srtt')),
    rttvar: toNum(getAttr(raw, 'rttvar')),
    to: toNum(getAttr(raw, 'to')),
  };
}

function parseTrace(raw: any): TraceInfo | null {
  if (!raw) return null;
  return {
    port: toNum(getAttr(raw, 'port')),
    proto: getAttr(raw, 'proto'),
    hops: ensureArray(raw.hop).map((h: any) => ({
      ttl: toNum(getAttr(h, 'ttl')),
      rtt: toNum(getAttr(h, 'rtt')),
      ipaddr: getAttr(h, 'ipaddr'),
      host: getAttr(h, 'host') || undefined,
    } as TraceHop)),
  };
}

function parseSmurfs(raw: any): Smurf[] {
  return ensureArray(raw).map((s: any) => ({
    responses: getAttr(s, 'responses'),
  }));
}

// Greppable output parser
export function parseNmapGreppable(content: string): NmapScan {
  const lines = content.split('\n');
  const hosts: NmapHost[] = [];
  let args = '';
  let startstr = '';

  for (const line of lines) {
    if (line.startsWith('# Nmap')) {
      const argsMatch = line.match(/# Nmap .+ scan initiated (.+) as: (.+)/);
      if (argsMatch) {
        startstr = argsMatch[1];
        args = argsMatch[2];
      }
      continue;
    }

    if (line.startsWith('#') || line.trim() === '') continue;

    if (line.startsWith('Host:')) {
      const host = parseGreppableLine(line);
      if (host) hosts.push(host);
    }
  }

  const scan: NmapScan = {
    scanner: 'nmap',
    args,
    start: 0,
    startstr,
    version: '',
    xmloutputversion: '',
    scaninfo: [],
    verbose: 0,
    debugging: 0,
    hosts,
    runstats: {
      finished: { time: 0, timestr: '', elapsed: 0, summary: '', exit: 'success' },
      hosts: { up: hosts.filter(h => h.status.state === 'up').length, down: 0, total: hosts.length },
    },
    totalHosts: hosts.length,
    hostsUp: hosts.filter(h => h.status.state === 'up').length,
    hostsDown: 0,
    hostsFiltered: 0,
    scanDuration: 0,
    uniquePorts: [],
    uniqueServices: [],
  };

  scan.uniquePorts = computePortSummaries(scan.hosts);
  scan.uniqueServices = computeServiceSummaries(scan.hosts);

  return scan;
}

function parseGreppableLine(line: string): NmapHost | null {
  // Format: Host: <ip> (<hostname>)\tPorts: <port>/<state>/<protocol>/<owner>/<service>/<rpc>/<version>/\t...
  const hostMatch = line.match(/^Host:\s+(\S+)\s+\(([^)]*)\)/);
  if (!hostMatch) return null;

  const ip = hostMatch[1];
  const hostname = hostMatch[2];

  const addresses: Address[] = [{ addr: ip, addrtype: 'ipv4' }];
  const hostnames: Hostname[] = hostname ? [{ name: hostname, type: '' }] : [];

  const ports: Port[] = [];
  const portsMatch = line.match(/Ports:\s+(.+?)(?:\t|$)/);
  if (portsMatch) {
    const portEntries = portsMatch[1].split(',').map(s => s.trim());
    for (const entry of portEntries) {
      const parts = entry.split('/');
      if (parts.length >= 7) {
        ports.push({
          protocol: parts[2] || 'tcp',
          portid: toNum(parts[0]),
          state: { state: parts[1] || 'unknown', reason: '', reason_ttl: 0 },
          service: {
            name: parts[4] || '',
            product: parts[6] || undefined,
            version: undefined,
            method: 'table',
            conf: 0,
            cpes: [],
          },
          scripts: [],
          owner: parts[3] || undefined,
        });
      }
    }
  }

  const hasOpenPorts = ports.some(p => p.state.state === 'open');
  const statusState = line.includes('Status: Up') || hasOpenPorts ? 'up' as const : 'down' as const;

  return {
    id: generateId(),
    starttime: 0,
    endtime: 0,
    status: { state: statusState, reason: '', reason_ttl: 0 },
    addresses,
    hostnames,
    ports,
    os: { osmatch: [], osfingerprint: [], portused: [] },
    uptime: null,
    distance: null,
    tcpsequence: null,
    ipidsequence: null,
    tcptssequence: null,
    times: null,
    trace: null,
    hostscripts: [],
    smurfs: [],
    ip,
    ipv6: '',
    mac: '',
    hostname: hostname || '',
    mainOS: '',
    openPortCount: ports.filter(p => p.state.state === 'open').length,
    closedPortCount: ports.filter(p => p.state.state === 'closed').length,
    filteredPortCount: ports.filter(p => p.state.state === 'filtered').length,
  };
}

// Aggregation helpers
function computePortSummaries(hosts: NmapHost[]): PortSummary[] {
  const map = new Map<string, PortSummary>();
  for (const host of hosts) {
    for (const port of host.ports) {
      const key = `${port.portid}/${port.protocol}/${port.state.state}`;
      const existing = map.get(key);
      if (existing) {
        existing.count++;
        existing.hosts.push(host.ip || host.ipv6);
      } else {
        map.set(key, {
          port: port.portid,
          protocol: port.protocol,
          state: port.state.state,
          service: port.service?.name || '',
          product: port.service?.product || '',
          count: 1,
          hosts: [host.ip || host.ipv6],
        });
      }
    }
  }
  return Array.from(map.values()).sort((a, b) => a.port - b.port);
}

function computeServiceSummaries(hosts: NmapHost[]): ServiceSummary[] {
  const map = new Map<string, ServiceSummary>();
  for (const host of hosts) {
    for (const port of host.ports) {
      if (!port.service?.name) continue;
      const key = `${port.service.name}/${port.service.product || ''}/${port.service.version || ''}`;
      const existing = map.get(key);
      if (existing) {
        existing.count++;
        if (!existing.ports.includes(port.portid)) existing.ports.push(port.portid);
        const hostAddr = host.ip || host.ipv6;
        if (!existing.hosts.includes(hostAddr)) existing.hosts.push(hostAddr);
      } else {
        map.set(key, {
          name: port.service.name,
          product: port.service.product || '',
          version: port.service.version || '',
          count: 1,
          ports: [port.portid],
          hosts: [host.ip || host.ipv6],
        });
      }
    }
  }
  return Array.from(map.values()).sort((a, b) => a.name.localeCompare(b.name));
}

// Normal output (-oN) parser
export function parseNmapNormal(content: string): NmapScan {
  const lines = content.split('\n');
  const hosts: NmapHost[] = [];
  let args = '';
  let startstr = '';
  let version = '';

  // Parse header
  const headerMatch = content.match(/Starting Nmap ([\d.]+)[^\n]*at (.+)/);
  if (headerMatch) {
    version = headerMatch[1];
    startstr = headerMatch[2];
  }
  const argsMatch = content.match(/Nmap scan report/);
  if (!argsMatch) {
    // Try to extract command from first comment line
    const cmdMatch = lines[0]?.match(/# Nmap (.+)/);
    if (cmdMatch) args = cmdMatch[1];
  }

  let currentHost: {
    ip: string; hostname: string; status: string; reason: string;
    ports: Port[]; os: string; distance: number | null; uptime: Uptime | null;
    mac: string; macVendor: string;
  } | null = null;

  let inPortTable = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Detect "Nmap scan report for ..."
    const reportMatch = line.match(/^Nmap scan report for (?:(\S+) \((\S+)\)|(\S+))$/);
    if (reportMatch) {
      // Save previous host
      if (currentHost) {
        hosts.push(buildNormalHost(currentHost));
      }
      const hostname = reportMatch[1] || '';
      const ip = reportMatch[2] || reportMatch[3] || '';
      currentHost = {
        ip, hostname, status: 'up', reason: '',
        ports: [], os: '', distance: null, uptime: null,
        mac: '', macVendor: '',
      };
      inPortTable = false;
      continue;
    }

    // Host is up/down
    const statusMatch = line.match(/^Host is (up|down)\s*(?:\((.+?)\))?/);
    if (statusMatch && currentHost) {
      currentHost.status = statusMatch[1];
      currentHost.reason = statusMatch[2] || '';
      continue;
    }

    // Port table header
    if (line.match(/^PORT\s+STATE\s+SERVICE/)) {
      inPortTable = true;
      continue;
    }

    // Port line: "22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3"
    if (inPortTable && currentHost) {
      const portMatch = line.match(/^(\d+)\/(tcp|udp|sctp)\s+(open|closed|filtered|open\|filtered|closed\|filtered|unfiltered)\s+(\S+)(?:\s+(.+))?$/);
      if (portMatch) {
        const [, portNum, proto, state, serviceName, rest] = portMatch;
        let product = '';
        let ver = '';
        let extrainfo = '';
        if (rest) {
          // Try to split "product version (extrainfo)"
          const prodMatch = rest.match(/^(.+?)(?:\s+([\d][\d.]*\S*))?(?:\s+\((.+?)\))?$/);
          if (prodMatch) {
            product = prodMatch[1]?.trim() || '';
            ver = prodMatch[2] || '';
            extrainfo = prodMatch[3] || '';
          } else {
            product = rest.trim();
          }
        }
        currentHost.ports.push({
          protocol: proto,
          portid: toNum(portNum),
          state: { state, reason: '', reason_ttl: 0 },
          service: {
            name: serviceName,
            product: product || undefined,
            version: ver || undefined,
            extrainfo: extrainfo || undefined,
            method: 'table',
            conf: 0,
            cpes: [],
          },
          scripts: [],
        });
        continue;
      }
      // Non-port line ends port table
      if (line.trim() !== '' && !line.startsWith('|') && !line.startsWith('| ')) {
        inPortTable = false;
      }
    }

    // MAC Address
    const macMatch = line.match(/^MAC Address:\s+(\S+)\s*(?:\((.+?)\))?/);
    if (macMatch && currentHost) {
      currentHost.mac = macMatch[1];
      currentHost.macVendor = macMatch[2] || '';
      continue;
    }

    // OS detection
    if (line.startsWith('OS details:') && currentHost) {
      currentHost.os = line.replace('OS details:', '').trim();
      continue;
    }
    const aggressiveOS = line.match(/^Aggressive OS guesses:\s+(.+)/);
    if (aggressiveOS && currentHost && !currentHost.os) {
      currentHost.os = aggressiveOS[1].split(',')[0].replace(/\s*\(\d+%\)/, '').trim();
      continue;
    }

    // Network distance
    const distMatch = line.match(/^Network Distance:\s+(\d+)\s+hop/);
    if (distMatch && currentHost) {
      currentHost.distance = toNum(distMatch[1]);
      continue;
    }

    // Uptime
    const uptimeMatch = line.match(/^Uptime guess:\s+([\d.]+)\s+days\s+\(since (.+)\)/);
    if (uptimeMatch && currentHost) {
      currentHost.uptime = {
        seconds: Math.round(parseFloat(uptimeMatch[1]) * 86400),
        lastboot: uptimeMatch[2],
      };
      continue;
    }
  }

  // Save last host
  if (currentHost) {
    hosts.push(buildNormalHost(currentHost));
  }

  const scan: NmapScan = {
    scanner: 'nmap',
    args,
    start: 0,
    startstr,
    version,
    xmloutputversion: '',
    scaninfo: [],
    verbose: 0,
    debugging: 0,
    hosts,
    runstats: {
      finished: { time: 0, timestr: '', elapsed: 0, summary: '', exit: 'success' },
      hosts: { up: hosts.filter(h => h.status.state === 'up').length, down: hosts.filter(h => h.status.state === 'down').length, total: hosts.length },
    },
    totalHosts: hosts.length,
    hostsUp: hosts.filter(h => h.status.state === 'up').length,
    hostsDown: hosts.filter(h => h.status.state === 'down').length,
    hostsFiltered: 0,
    scanDuration: 0,
    uniquePorts: [],
    uniqueServices: [],
  };

  scan.uniquePorts = computePortSummaries(scan.hosts);
  scan.uniqueServices = computeServiceSummaries(scan.hosts);
  return scan;
}

function buildNormalHost(h: {
  ip: string; hostname: string; status: string; reason: string;
  ports: Port[]; os: string; distance: number | null; uptime: Uptime | null;
  mac: string; macVendor: string;
}): NmapHost {
  const addresses: Address[] = [{ addr: h.ip, addrtype: 'ipv4' }];
  if (h.mac) addresses.push({ addr: h.mac, addrtype: 'mac', vendor: h.macVendor || undefined });

  return {
    id: generateId(),
    starttime: 0,
    endtime: 0,
    status: { state: h.status as 'up' | 'down' | 'unknown' | 'skipped', reason: h.reason, reason_ttl: 0 },
    addresses,
    hostnames: h.hostname ? [{ name: h.hostname, type: '' }] : [],
    ports: h.ports,
    os: {
      osmatch: h.os ? [{ name: h.os, accuracy: 0, line: 0, osclass: [] }] : [],
      osfingerprint: [],
      portused: [],
    },
    uptime: h.uptime,
    distance: h.distance,
    tcpsequence: null,
    ipidsequence: null,
    tcptssequence: null,
    times: null,
    trace: null,
    hostscripts: [],
    smurfs: [],
    ip: h.ip,
    ipv6: '',
    mac: h.mac,
    hostname: h.hostname,
    mainOS: h.os,
    openPortCount: h.ports.filter(p => p.state.state === 'open').length,
    closedPortCount: h.ports.filter(p => p.state.state === 'closed').length,
    filteredPortCount: h.ports.filter(p => p.state.state === 'filtered' || p.state.state === 'open|filtered').length,
  };
}

// Auto-detect format and parse
export function parseNmapOutput(content: string): NmapScan {
  const trimmed = content.trim();
  if (trimmed.startsWith('<?xml') || trimmed.startsWith('<nmaprun')) {
    return parseNmapXML(trimmed);
  }
  if (trimmed.startsWith('# Nmap') || trimmed.startsWith('Host:')) {
    return parseNmapGreppable(trimmed);
  }
  // Detect normal output format
  if (trimmed.includes('Nmap scan report for') || trimmed.startsWith('Starting Nmap')) {
    return parseNmapNormal(trimmed);
  }
  // Try XML parse anyway
  try {
    return parseNmapXML(trimmed);
  } catch {
    throw new Error(
      'Unrecognized nmap output format. Supported formats: XML (-oX), Greppable (-oG), Normal (-oN)'
    );
  }
}
