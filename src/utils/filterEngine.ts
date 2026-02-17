import type { NmapHost, FilterGroup, FilterRule, SortConfig } from '../types/nmap';

// Get a nested field value from a host object using dot notation
function getFieldValue(host: NmapHost, field: string): any {
  if (field === 'ip') return host.ip;
  if (field === 'ipv6') return host.ipv6;
  if (field === 'mac') return host.mac;
  if (field === 'hostname') return host.hostname;
  if (field === 'status') return host.status.state;
  if (field === 'reason') return host.status.reason;
  if (field === 'mainOS') return host.mainOS;
  if (field === 'openPortCount') return host.openPortCount;
  if (field === 'closedPortCount') return host.closedPortCount;
  if (field === 'filteredPortCount') return host.filteredPortCount;
  if (field === 'totalPorts') return host.ports.length;
  if (field === 'macVendor') return host.addresses.find(a => a.addrtype === 'mac')?.vendor || '';
  if (field === 'osAccuracy') return host.os.osmatch[0]?.accuracy || 0;
  if (field === 'osfamily') return host.os.osmatch[0]?.osclass[0]?.osfamily || '';
  if (field === 'osvendor') return host.os.osmatch[0]?.osclass[0]?.vendor || '';
  if (field === 'uptimeSeconds') return host.uptime?.seconds || 0;
  if (field === 'lastboot') return host.uptime?.lastboot || '';
  if (field === 'distance') return host.distance || 0;
  if (field === 'tcpDifficulty') return host.tcpsequence?.difficulty || '';
  if (field === 'hostscriptCount') return host.hostscripts.length;
  if (field === 'ports') return host.ports.map(p => `${p.portid}/${p.protocol}`).join(', ');
  if (field === 'services') return host.ports.map(p => p.service?.name).filter(Boolean).join(', ');
  if (field === 'products') return host.ports.map(p => p.service?.product).filter(Boolean).join(', ');
  if (field === 'allAddresses') return host.addresses.map(a => a.addr).join(', ');
  if (field === 'allHostnames') return host.hostnames.map(h => h.name).join(', ');
  if (field === 'cpes') {
    const cpes: string[] = [];
    for (const p of host.ports) {
      if (p.service?.cpes) cpes.push(...p.service.cpes);
    }
    for (const om of host.os.osmatch) {
      for (const oc of om.osclass) {
        cpes.push(...oc.cpes);
      }
    }
    return [...new Set(cpes)].join(', ');
  }

  // Fallback: try dot notation traversal
  const parts = field.split('.');
  let val: any = host;
  for (const part of parts) {
    if (val === null || val === undefined) return '';
    val = val[part];
  }
  return val ?? '';
}

function matchesRule(host: NmapHost, rule: FilterRule): boolean {
  if (!rule.enabled) return true;

  const fieldVal = getFieldValue(host, rule.field);
  const strVal = String(fieldVal).toLowerCase();
  const ruleVal = rule.value.toLowerCase();

  switch (rule.operator) {
    case 'equals':
      return strVal === ruleVal;
    case 'not_equals':
      return strVal !== ruleVal;
    case 'contains':
      return strVal.includes(ruleVal);
    case 'not_contains':
      return !strVal.includes(ruleVal);
    case 'starts_with':
      return strVal.startsWith(ruleVal);
    case 'ends_with':
      return strVal.endsWith(ruleVal);
    case 'greater_than':
      return Number(fieldVal) > Number(rule.value);
    case 'less_than':
      return Number(fieldVal) < Number(rule.value);
    case 'in_range': {
      const [min, max] = rule.value.split('-').map(Number);
      const num = Number(fieldVal);
      return num >= min && num <= max;
    }
    case 'regex':
      try {
        const pattern = rule.value;
        // Reject patterns prone to catastrophic backtracking:
        // 1. Any group containing a quantifier or alternation, followed by a quantifier
        //    Covers: (a+)+, (a*)*b, (a|a)+, (a|ab)*, etc.
        if (/\([^)]*[+*|][^)]*\)[+*?{]/.test(pattern)) {
          return false;
        }
        // 2. Adjacent unbounded quantifiers: \d+\d+x, \w+\w+, .+.+, etc.
        if (/[+*}\?]\s*\\?[dDwWsS.]\s*[+*{]/.test(pattern)) {
          return false;
        }
        const re = new RegExp(pattern, 'i');
        const testStr = String(fieldVal).slice(0, 1000);
        return re.test(testStr);
      } catch {
        return false;
      }
    case 'is_empty':
      return strVal === '' || strVal === '0';
    case 'is_not_empty':
      return strVal !== '' && strVal !== '0';
    default:
      return true;
  }
}

export function applyFilters(hosts: NmapHost[], filterGroup: FilterGroup): NmapHost[] {
  if (filterGroup.rules.length === 0) return hosts;

  const enabledRules = filterGroup.rules.filter(r => r.enabled);
  if (enabledRules.length === 0) return hosts;

  return hosts.filter(host => {
    if (filterGroup.logic === 'AND') {
      return enabledRules.every(rule => matchesRule(host, rule));
    } else {
      return enabledRules.some(rule => matchesRule(host, rule));
    }
  });
}

export function applySearch(hosts: NmapHost[], query: string): NmapHost[] {
  if (!query.trim()) return hosts;
  const q = query.toLowerCase().trim();

  return hosts.filter(host => {
    // Search across all major fields
    if (host.ip.toLowerCase().includes(q)) return true;
    if (host.ipv6.toLowerCase().includes(q)) return true;
    if (host.mac.toLowerCase().includes(q)) return true;
    if (host.hostname.toLowerCase().includes(q)) return true;
    if (host.mainOS.toLowerCase().includes(q)) return true;
    if (host.status.state.toLowerCase().includes(q)) return true;

    // Search in hostnames
    for (const hn of host.hostnames) {
      if (hn.name.toLowerCase().includes(q)) return true;
    }

    // Search in addresses
    for (const addr of host.addresses) {
      if (addr.addr.toLowerCase().includes(q)) return true;
      if (addr.vendor?.toLowerCase().includes(q)) return true;
    }

    // Search in ports/services
    for (const port of host.ports) {
      if (String(port.portid).includes(q)) return true;
      if (port.service?.name?.toLowerCase().includes(q)) return true;
      if (port.service?.product?.toLowerCase().includes(q)) return true;
      if (port.service?.version?.toLowerCase().includes(q)) return true;
      if (port.service?.extrainfo?.toLowerCase().includes(q)) return true;
    }

    // Search in scripts
    for (const script of host.hostscripts) {
      if (script.id.toLowerCase().includes(q)) return true;
      if (script.output.toLowerCase().includes(q)) return true;
    }
    for (const port of host.ports) {
      for (const script of port.scripts) {
        if (script.id.toLowerCase().includes(q)) return true;
        if (script.output.toLowerCase().includes(q)) return true;
      }
    }

    return false;
  });
}

export function applySorting(hosts: NmapHost[], sorts: SortConfig[]): NmapHost[] {
  if (sorts.length === 0) return hosts;

  return [...hosts].sort((a, b) => {
    for (const sort of sorts) {
      const aVal = getFieldValue(a, sort.field);
      const bVal = getFieldValue(b, sort.field);
      const dir = sort.direction === 'asc' ? 1 : -1;

      // Numeric comparison
      const aNum = Number(aVal);
      const bNum = Number(bVal);
      if (!isNaN(aNum) && !isNaN(bNum)) {
        if (aNum !== bNum) return (aNum - bNum) * dir;
        continue;
      }

      // IP address comparison
      if (sort.field === 'ip' || sort.field === 'ipv6') {
        const cmp = compareIPs(String(aVal), String(bVal));
        if (cmp !== 0) return cmp * dir;
        continue;
      }

      // String comparison
      const cmp = String(aVal).localeCompare(String(bVal));
      if (cmp !== 0) return cmp * dir;
    }
    return 0;
  });
}

function compareIPs(a: string, b: string): number {
  const aParts = a.split('.').map(Number);
  const bParts = b.split('.').map(Number);
  for (let i = 0; i < 4; i++) {
    const diff = (aParts[i] || 0) - (bParts[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

// Available filter fields
export const FILTER_FIELDS = [
  { value: 'ip', label: 'IP Address', type: 'string' },
  { value: 'ipv6', label: 'IPv6 Address', type: 'string' },
  { value: 'mac', label: 'MAC Address', type: 'string' },
  { value: 'macVendor', label: 'MAC Vendor', type: 'string' },
  { value: 'hostname', label: 'Hostname', type: 'string' },
  { value: 'allHostnames', label: 'All Hostnames', type: 'string' },
  { value: 'status', label: 'Status', type: 'string' },
  { value: 'reason', label: 'Status Reason', type: 'string' },
  { value: 'mainOS', label: 'OS', type: 'string' },
  { value: 'osfamily', label: 'OS Family', type: 'string' },
  { value: 'osvendor', label: 'OS Vendor', type: 'string' },
  { value: 'osAccuracy', label: 'OS Accuracy', type: 'number' },
  { value: 'openPortCount', label: 'Open Ports', type: 'number' },
  { value: 'closedPortCount', label: 'Closed Ports', type: 'number' },
  { value: 'filteredPortCount', label: 'Filtered Ports', type: 'number' },
  { value: 'totalPorts', label: 'Total Ports', type: 'number' },
  { value: 'ports', label: 'Port Numbers', type: 'string' },
  { value: 'services', label: 'Services', type: 'string' },
  { value: 'products', label: 'Products', type: 'string' },
  { value: 'cpes', label: 'CPEs', type: 'string' },
  { value: 'uptimeSeconds', label: 'Uptime (seconds)', type: 'number' },
  { value: 'lastboot', label: 'Last Boot', type: 'string' },
  { value: 'distance', label: 'Network Distance', type: 'number' },
  { value: 'tcpDifficulty', label: 'TCP Seq Difficulty', type: 'string' },
  { value: 'hostscriptCount', label: 'Host Scripts Count', type: 'number' },
];

export const FILTER_OPERATORS = [
  { value: 'equals', label: 'Equals', types: ['string', 'number'] },
  { value: 'not_equals', label: 'Not Equals', types: ['string', 'number'] },
  { value: 'contains', label: 'Contains', types: ['string'] },
  { value: 'not_contains', label: 'Does Not Contain', types: ['string'] },
  { value: 'starts_with', label: 'Starts With', types: ['string'] },
  { value: 'ends_with', label: 'Ends With', types: ['string'] },
  { value: 'greater_than', label: 'Greater Than', types: ['number'] },
  { value: 'less_than', label: 'Less Than', types: ['number'] },
  { value: 'in_range', label: 'In Range', types: ['number'] },
  { value: 'regex', label: 'Matches Regex', types: ['string'] },
  { value: 'is_empty', label: 'Is Empty', types: ['string', 'number'] },
  { value: 'is_not_empty', label: 'Is Not Empty', types: ['string', 'number'] },
];
