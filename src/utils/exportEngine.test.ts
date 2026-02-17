import { describe, it, expect } from 'vitest';
import { exportData, getExportFilename, getExportMimeType } from './exportEngine';
import type { NmapScan, NmapHost, ExportOptions } from '../types/nmap';

function makeScan(overrides: Partial<NmapScan> = {}): NmapScan {
  return {
    scanner: 'nmap',
    args: 'nmap -sV 192.168.1.0/24',
    start: 1700000000,
    startstr: 'Tue Nov 14 2023',
    version: '7.94',
    xmloutputversion: '1.05',
    scaninfo: [{ type: 'syn', protocol: 'tcp', numservices: 1000, services: '1-1000' }],
    verbose: 0,
    debugging: 0,
    hosts: [],
    runstats: {
      finished: { time: 1700000020, timestr: '', elapsed: 20, summary: '', exit: 'success' },
      hosts: { up: 1, down: 0, total: 1 },
    },
    totalHosts: 1,
    hostsUp: 1,
    hostsDown: 0,
    hostsFiltered: 0,
    scanDuration: 20,
    uniquePorts: [],
    uniqueServices: [],
    ...overrides,
  };
}

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
        service: { name: 'ssh', product: 'OpenSSH', version: '8.9p1', method: 'probed', conf: 10, cpes: [] },
        scripts: [],
      },
    ],
    os: { osmatch: [{ name: 'Linux 5.4', accuracy: 95, line: 1, osclass: [{ type: 'general purpose', vendor: 'Linux', osfamily: 'Linux', osgen: '5.X', accuracy: 95, cpes: [] }] }], osfingerprint: [], portused: [] },
    uptime: null,
    distance: null,
    tcpsequence: null,
    ipidsequence: null,
    tcptssequence: null,
    times: null,
    trace: null,
    hostscripts: [],
    smurfs: [],
    ip: '192.168.1.1',
    ipv6: '',
    mac: '',
    hostname: 'test.local',
    mainOS: 'Linux 5.4',
    openPortCount: 1,
    closedPortCount: 0,
    filteredPortCount: 0,
    ...overrides,
  };
}

const defaultOptions: ExportOptions = {
  format: 'csv',
  includeHostDetails: true,
  includePorts: true,
  includeScripts: false,
  includeOS: true,
  includeTrace: false,
};

describe('exportData - CSV', () => {
  it('produces valid CSV with headers', () => {
    const csv = exportData(makeScan(), [makeHost()], { ...defaultOptions, format: 'csv' });
    const lines = csv.split('\n');
    expect(lines[0]).toContain('IP');
    expect(lines[0]).toContain('Port');
    expect(lines[0]).toContain('Service');
    expect(lines.length).toBeGreaterThan(1);
  });

  it('escapes commas in CSV cells', () => {
    const host = makeHost({
      hostname: 'host,with,commas',
    });
    const csv = exportData(makeScan(), [host], { ...defaultOptions, format: 'csv' });
    expect(csv).toContain('"host,with,commas"');
  });

  it('escapes double quotes in CSV cells', () => {
    const host = makeHost({
      ports: [{
        protocol: 'tcp', portid: 80,
        state: { state: 'open', reason: '', reason_ttl: 0 },
        service: { name: 'http', product: 'Apache "Web Server"', method: 'probed', conf: 10, cpes: [] },
        scripts: [],
      }],
    });
    const csv = exportData(makeScan(), [host], { ...defaultOptions, format: 'csv' });
    expect(csv).toContain('""Web Server""');
  });

  it('escapes newlines in CSV cells', () => {
    const host = makeHost({
      ports: [{
        protocol: 'tcp', portid: 80,
        state: { state: 'open', reason: '', reason_ttl: 0 },
        service: { name: 'http', product: 'Server\nwith\nnewlines', method: 'probed', conf: 10, cpes: [] },
        scripts: [],
      }],
    });
    const csv = exportData(makeScan(), [host], { ...defaultOptions, format: 'csv' });
    // Newlines should be quoted
    expect(csv).toContain('"Server\nwith\nnewlines"');
  });

  it('escapes carriage returns in CSV cells', () => {
    const host = makeHost({
      ports: [{
        protocol: 'tcp', portid: 80,
        state: { state: 'open', reason: '', reason_ttl: 0 },
        service: { name: 'http', product: 'Server\r\nCRLF', method: 'probed', conf: 10, cpes: [] },
        scripts: [],
      }],
    });
    const csv = exportData(makeScan(), [host], { ...defaultOptions, format: 'csv' });
    expect(csv).toContain('"Server\r\nCRLF"');
  });

  it('includes OS columns when includeOS is true', () => {
    const csv = exportData(makeScan(), [makeHost()], { ...defaultOptions, format: 'csv', includeOS: true });
    const header = csv.split('\n')[0];
    expect(header).toContain('OS');
    expect(header).toContain('OS Accuracy');
  });

  it('excludes OS columns when includeOS is false', () => {
    const csv = exportData(makeScan(), [makeHost()], { ...defaultOptions, format: 'csv', includeOS: false });
    const header = csv.split('\n')[0];
    expect(header).not.toContain('OS Accuracy');
  });
});

describe('exportData - JSON', () => {
  it('produces valid JSON', () => {
    const json = exportData(makeScan(), [makeHost()], { ...defaultOptions, format: 'json' });
    const parsed = JSON.parse(json);
    expect(parsed.scanInfo).toBeDefined();
    expect(parsed.hosts).toHaveLength(1);
  });

  it('includes notes when requested', () => {
    const options: ExportOptions = {
      ...defaultOptions,
      format: 'json',
      includeNotes: true,
      notes: [{
        id: 'n1', title: 'Test Note', content: 'Note content',
        targets: [{ hostId: 'h1', ip: '192.168.1.1', portId: 22, protocol: 'tcp' }],
        screenshots: [{ id: 's1', dataUrl: 'data:image/png;base64,abc', fileName: 'test.png', createdAt: 1000 }],
        createdAt: 1000, updatedAt: 2000,
      }],
    };
    const json = exportData(makeScan(), [makeHost()], options);
    const parsed = JSON.parse(json);
    expect(parsed.notes).toHaveLength(1);
    expect(parsed.notes[0].title).toBe('Test Note');
  });
});

describe('exportData - Markdown', () => {
  it('produces valid Markdown', () => {
    const md = exportData(makeScan(), [makeHost()], { ...defaultOptions, format: 'markdown' });
    expect(md).toContain('# Nmap Scan Report');
    expect(md).toContain('## Hosts');
    expect(md).toContain('192.168.1.1');
  });

  it('escapes pipe characters in table cells', () => {
    const host = makeHost({
      ports: [{
        protocol: 'tcp', portid: 80,
        state: { state: 'open|filtered', reason: '', reason_ttl: 0 },
        service: { name: 'http', method: 'table', conf: 3, cpes: [] },
        scripts: [],
      }],
    });
    const md = exportData(makeScan(), [host], { ...defaultOptions, format: 'markdown' });
    // Pipe in "open|filtered" should be escaped for markdown tables
    expect(md).toContain('open\\|filtered');
  });
});

describe('exportData - HTML', () => {
  it('produces valid HTML', () => {
    const html = exportData(makeScan(), [makeHost()], { ...defaultOptions, format: 'html' });
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('Nmap Scan Report');
    expect(html).toContain('192.168.1.1');
  });

  it('escapes HTML entities', () => {
    const scan = makeScan({ args: 'nmap <script>alert(1)</script>' });
    const html = exportData(scan, [makeHost()], { ...defaultOptions, format: 'html' });
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;');
  });

  it('escapes single quotes in HTML output', () => {
    const scan = makeScan({ args: "nmap --script='http-enum'" });
    const html = exportData(scan, [makeHost()], { ...defaultOptions, format: 'html' });
    expect(html).toContain('&#x27;');
    expect(html).not.toMatch(/nmap --script='http-enum'/);
  });

  it('only allows data:image/ sources for screenshots', () => {
    const options: ExportOptions = {
      ...defaultOptions,
      format: 'html',
      includeNotes: true,
      notes: [{
        id: 'n1', title: 'Test', content: 'test',
        targets: [], createdAt: 1000, updatedAt: 2000,
        screenshots: [
          { id: 's1', dataUrl: 'data:image/png;base64,abc', fileName: 'good.png', createdAt: 1000 },
          { id: 's2', dataUrl: 'https://evil.com/steal', fileName: 'bad.png', createdAt: 1000 },
        ],
      }],
    };
    const html = exportData(makeScan(), [makeHost()], options);
    // The safe data URL should be present, the evil URL should not
    expect(html).toContain('data:image/png;base64,abc');
    expect(html).not.toContain('https://evil.com/steal');
  });
});

describe('exportData - XML', () => {
  it('produces valid XML', () => {
    const xml = exportData(makeScan(), [makeHost()], { ...defaultOptions, format: 'xml' });
    expect(xml).toContain('<?xml version');
    expect(xml).toContain('nmapui-export');
    expect(xml).toContain('192.168.1.1');
  });

  it('escapes XML special characters including single quotes', () => {
    const host = makeHost({ hostname: "test<>&\"'host" });
    const xml = exportData(makeScan(), [host], { ...defaultOptions, format: 'xml' });
    expect(xml).toContain('&amp;');
    expect(xml).toContain('&lt;');
    expect(xml).toContain('&gt;');
    expect(xml).toContain('&quot;');
    expect(xml).toContain('&#x27;');
  });
});

describe('getExportFilename', () => {
  it('returns .csv extension for csv format', () => {
    expect(getExportFilename('csv')).toMatch(/\.csv$/);
  });

  it('returns .md extension for markdown format', () => {
    expect(getExportFilename('markdown')).toMatch(/\.md$/);
  });

  it('returns .json extension for json format', () => {
    expect(getExportFilename('json')).toMatch(/\.json$/);
  });

  it('includes timestamp in filename', () => {
    const filename = getExportFilename('csv');
    expect(filename).toMatch(/nmap-results-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.csv/);
  });
});

describe('getExportMimeType', () => {
  it('returns correct MIME types', () => {
    expect(getExportMimeType('csv')).toBe('text/csv');
    expect(getExportMimeType('json')).toBe('application/json');
    expect(getExportMimeType('html')).toBe('text/html');
    expect(getExportMimeType('xml')).toBe('application/xml');
    expect(getExportMimeType('markdown')).toBe('text/markdown');
  });
});
