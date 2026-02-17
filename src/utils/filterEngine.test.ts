import { describe, it, expect } from 'vitest';
import { applyFilters, applySearch, applySorting } from './filterEngine';
import type { NmapHost, FilterGroup, FilterRule, SortConfig } from '../types/nmap';

// Helper to create a minimal host for testing
function makeHost(overrides: Partial<NmapHost> = {}): NmapHost {
  return {
    id: 'host-1',
    starttime: 0,
    endtime: 0,
    status: { state: 'up', reason: 'syn-ack', reason_ttl: 64 },
    addresses: [{ addr: '192.168.1.1', addrtype: 'ipv4' }],
    hostnames: [{ name: 'test.local', type: 'PTR' }],
    ports: [
      {
        protocol: 'tcp', portid: 22,
        state: { state: 'open', reason: 'syn-ack', reason_ttl: 64 },
        service: { name: 'ssh', product: 'OpenSSH', version: '8.9', method: 'probed', conf: 10, cpes: [] },
        scripts: [],
      },
      {
        protocol: 'tcp', portid: 80,
        state: { state: 'open', reason: 'syn-ack', reason_ttl: 64 },
        service: { name: 'http', product: 'nginx', version: '1.18', method: 'probed', conf: 10, cpes: [] },
        scripts: [{ id: 'http-title', output: 'Welcome Page', elements: [] }],
      },
    ],
    os: { osmatch: [{ name: 'Linux 5.4', accuracy: 95, line: 1, osclass: [{ type: 'general purpose', vendor: 'Linux', osfamily: 'Linux', osgen: '5.X', accuracy: 95, cpes: [] }] }], osfingerprint: [], portused: [] },
    uptime: { seconds: 86400, lastboot: '2023-11-13' },
    distance: 2,
    tcpsequence: { index: 260, difficulty: 'Good luck!', values: '' },
    ipidsequence: null,
    tcptssequence: null,
    times: null,
    trace: null,
    hostscripts: [{ id: 'smb-os', output: 'Windows detected', elements: [] }],
    smurfs: [],
    ip: '192.168.1.1',
    ipv6: '',
    mac: 'AA:BB:CC:DD:EE:FF',
    hostname: 'test.local',
    mainOS: 'Linux 5.4',
    openPortCount: 2,
    closedPortCount: 0,
    filteredPortCount: 0,
    ...overrides,
  };
}

function makeRule(overrides: Partial<FilterRule> = {}): FilterRule {
  return {
    id: 'rule-1',
    field: 'ip',
    operator: 'equals',
    value: '192.168.1.1',
    enabled: true,
    ...overrides,
  };
}

function makeGroup(rules: FilterRule[], logic: 'AND' | 'OR' = 'AND'): FilterGroup {
  return { id: 'group-1', logic, rules };
}

const hosts = [
  makeHost({ id: 'h1', ip: '192.168.1.1', hostname: 'web.local', openPortCount: 3, mainOS: 'Linux 5.4', addresses: [{ addr: '192.168.1.1', addrtype: 'ipv4' }] }),
  makeHost({ id: 'h2', ip: '192.168.1.2', hostname: 'db.local', openPortCount: 1, mainOS: 'Windows 10', addresses: [{ addr: '192.168.1.2', addrtype: 'ipv4' }] }),
  makeHost({ id: 'h3', ip: '10.0.0.1', hostname: '', openPortCount: 0, mainOS: '', status: { state: 'down', reason: 'no-response', reason_ttl: 0 }, addresses: [{ addr: '10.0.0.1', addrtype: 'ipv4' }], ports: [] }),
];

describe('applyFilters', () => {
  it('returns all hosts when no rules', () => {
    const result = applyFilters(hosts, makeGroup([]));
    expect(result).toHaveLength(3);
  });

  it('filters by equals', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ field: 'ip', operator: 'equals', value: '192.168.1.1' }),
    ]));
    expect(result).toHaveLength(1);
    expect(result[0].ip).toBe('192.168.1.1');
  });

  it('filters by not_equals', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ field: 'ip', operator: 'not_equals', value: '10.0.0.1' }),
    ]));
    expect(result).toHaveLength(2);
  });

  it('filters by contains', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ field: 'ip', operator: 'contains', value: '192.168' }),
    ]));
    expect(result).toHaveLength(2);
  });

  it('filters by not_contains', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ field: 'hostname', operator: 'not_contains', value: 'web' }),
    ]));
    expect(result).toHaveLength(2);
  });

  it('filters by starts_with', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ field: 'ip', operator: 'starts_with', value: '10.' }),
    ]));
    expect(result).toHaveLength(1);
    expect(result[0].ip).toBe('10.0.0.1');
  });

  it('filters by ends_with', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ field: 'hostname', operator: 'ends_with', value: '.local' }),
    ]));
    expect(result).toHaveLength(2);
  });

  it('filters by greater_than', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ field: 'openPortCount', operator: 'greater_than', value: '1' }),
    ]));
    expect(result).toHaveLength(1);
    expect(result[0].openPortCount).toBe(3);
  });

  it('filters by less_than', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ field: 'openPortCount', operator: 'less_than', value: '2' }),
    ]));
    expect(result).toHaveLength(2);
  });

  it('filters by in_range', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ field: 'openPortCount', operator: 'in_range', value: '1-3' }),
    ]));
    expect(result).toHaveLength(2);
  });

  it('filters by regex', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ field: 'ip', operator: 'regex', value: '^192\\.168' }),
    ]));
    expect(result).toHaveLength(2);
  });

  it('rejects ReDoS regex patterns with nested quantifiers', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ field: 'ip', operator: 'regex', value: '(a+)+b' }),
    ]));
    expect(result).toHaveLength(0);
  });

  it('rejects ReDoS regex patterns with alternation in quantified group', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ field: 'ip', operator: 'regex', value: '(a|a)+b' }),
    ]));
    expect(result).toHaveLength(0);
  });

  it('rejects ReDoS regex patterns with overlapping alternation', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ field: 'ip', operator: 'regex', value: '(a|ab)*c' }),
    ]));
    expect(result).toHaveLength(0);
  });

  it('rejects adjacent unbounded quantifiers', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ field: 'ip', operator: 'regex', value: '\\d+\\d+\\d+x' }),
    ]));
    expect(result).toHaveLength(0);
  });

  it('handles invalid regex gracefully', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ field: 'ip', operator: 'regex', value: '[invalid' }),
    ]));
    expect(result).toHaveLength(0);
  });

  it('filters by is_empty', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ field: 'mainOS', operator: 'is_empty', value: '' }),
    ]));
    expect(result).toHaveLength(1);
    expect(result[0].ip).toBe('10.0.0.1');
  });

  it('filters by is_not_empty', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ field: 'mainOS', operator: 'is_not_empty', value: '' }),
    ]));
    expect(result).toHaveLength(2);
  });

  it('applies AND logic', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ id: 'r1', field: 'status', operator: 'equals', value: 'up' }),
      makeRule({ id: 'r2', field: 'ip', operator: 'starts_with', value: '192' }),
    ], 'AND'));
    expect(result).toHaveLength(2);
  });

  it('applies OR logic', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ id: 'r1', field: 'ip', operator: 'equals', value: '192.168.1.1' }),
      makeRule({ id: 'r2', field: 'ip', operator: 'equals', value: '10.0.0.1' }),
    ], 'OR'));
    expect(result).toHaveLength(2);
  });

  it('ignores disabled rules', () => {
    const result = applyFilters(hosts, makeGroup([
      makeRule({ field: 'ip', operator: 'equals', value: 'NONEXISTENT', enabled: false }),
    ]));
    expect(result).toHaveLength(3);
  });
});

describe('applySearch', () => {
  it('returns all hosts for empty query', () => {
    expect(applySearch(hosts, '')).toHaveLength(3);
    expect(applySearch(hosts, '   ')).toHaveLength(3);
  });

  it('searches by IP', () => {
    expect(applySearch(hosts, '192.168.1.1')).toHaveLength(1);
  });

  it('searches by hostname', () => {
    expect(applySearch(hosts, 'web.local')).toHaveLength(1);
  });

  it('searches by OS', () => {
    expect(applySearch(hosts, 'linux')).toHaveLength(1);
  });

  it('searches by service name', () => {
    const result = applySearch(hosts, 'ssh');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });

  it('searches by product name', () => {
    const result = applySearch(hosts, 'nginx');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });

  it('searches by port number', () => {
    const result = applySearch(hosts, '22');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });

  it('searches by script id', () => {
    const result = applySearch(hosts, 'http-title');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });

  it('searches by script output', () => {
    const result = applySearch(hosts, 'Welcome Page');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });

  it('searches by host script output', () => {
    const result = applySearch(hosts, 'Windows detected');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });

  it('search is case-insensitive', () => {
    expect(applySearch(hosts, 'LINUX')).toHaveLength(1);
  });
});

describe('applySorting', () => {
  it('returns original order with no sorts', () => {
    const result = applySorting(hosts, []);
    expect(result.map(h => h.id)).toEqual(['h1', 'h2', 'h3']);
  });

  it('sorts by IP ascending', () => {
    const result = applySorting(hosts, [{ field: 'ip', direction: 'asc' }]);
    expect(result[0].ip).toBe('10.0.0.1');
    expect(result[1].ip).toBe('192.168.1.1');
    expect(result[2].ip).toBe('192.168.1.2');
  });

  it('sorts by IP descending', () => {
    const result = applySorting(hosts, [{ field: 'ip', direction: 'desc' }]);
    expect(result[0].ip).toBe('192.168.1.2');
    expect(result[2].ip).toBe('10.0.0.1');
  });

  it('sorts by numeric field', () => {
    const result = applySorting(hosts, [{ field: 'openPortCount', direction: 'desc' }]);
    expect(result[0].openPortCount).toBe(3);
    expect(result[1].openPortCount).toBe(1);
    expect(result[2].openPortCount).toBe(0);
  });

  it('sorts by string field', () => {
    const result = applySorting(hosts, [{ field: 'mainOS', direction: 'asc' }]);
    // Empty string sorts first
    expect(result[0].mainOS).toBe('');
  });

  it('does not mutate original array', () => {
    const original = [...hosts];
    applySorting(hosts, [{ field: 'ip', direction: 'desc' }]);
    expect(hosts.map(h => h.id)).toEqual(original.map(h => h.id));
  });
});
