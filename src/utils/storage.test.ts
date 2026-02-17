import { describe, it, expect } from 'vitest';
import { exportProjectFile, importProjectFile, generateProjectId } from './storage';

describe('exportProjectFile', () => {
  it('produces valid JSON with magic header', () => {
    const result = exportProjectFile('scan data', 'scan.xml', []);
    const parsed = JSON.parse(result);
    expect(parsed.magic).toBe('NMAPUI_PROJECT');
    expect(parsed.version).toBe(1);
    expect(parsed.scanData).toBe('scan data');
    expect(parsed.scanFileName).toBe('scan.xml');
    expect(parsed.notes).toEqual([]);
    expect(parsed.mergedScans).toEqual([]);
    expect(typeof parsed.exportedAt).toBe('number');
  });

  it('includes notes in export', () => {
    const notes = [{
      id: 'n1', title: 'Test', content: 'Content',
      targets: [], screenshots: [],
      createdAt: 1000, updatedAt: 2000,
    }];
    const result = exportProjectFile('data', 'file.xml', notes);
    const parsed = JSON.parse(result);
    expect(parsed.notes).toHaveLength(1);
    expect(parsed.notes[0].title).toBe('Test');
  });

  it('includes merged scans', () => {
    const merged = [{ fileName: 'second.xml', content: '<xml/>' }];
    const result = exportProjectFile('data', 'file.xml', [], merged);
    const parsed = JSON.parse(result);
    expect(parsed.mergedScans).toHaveLength(1);
  });
});

describe('importProjectFile', () => {
  it('parses a valid project file', () => {
    const exported = exportProjectFile('scan data', 'scan.xml', []);
    const imported = importProjectFile(exported);
    expect(imported.magic).toBe('NMAPUI_PROJECT');
    expect(imported.scanData).toBe('scan data');
    expect(imported.scanFileName).toBe('scan.xml');
  });

  it('throws on invalid JSON', () => {
    expect(() => importProjectFile('not json')).toThrow('not valid JSON');
  });

  it('throws on missing magic header', () => {
    expect(() => importProjectFile(JSON.stringify({ data: 'hello' }))).toThrow('missing NmapUI signature');
  });

  it('throws on missing scan data', () => {
    expect(() => importProjectFile(JSON.stringify({
      magic: 'NMAPUI_PROJECT',
      version: 1,
      scanFileName: 'test.xml',
    }))).toThrow('missing scan data');
  });

  it('throws on non-string scan data', () => {
    expect(() => importProjectFile(JSON.stringify({
      magic: 'NMAPUI_PROJECT',
      version: 1,
      scanData: 12345,
      scanFileName: 'test.xml',
    }))).toThrow('missing scan data');
  });

  it('filters invalid notes to empty array', () => {
    const data = {
      magic: 'NMAPUI_PROJECT',
      version: 1,
      scanData: 'data',
      scanFileName: 'test.xml',
      notes: [
        { id: 'valid', title: 'T', content: 'C', targets: [], screenshots: [], createdAt: 1, updatedAt: 2 },
        { id: 123, title: 'bad' }, // missing fields
        null,
        'string',
      ],
      exportedAt: Date.now(),
      mergedScans: [],
    };
    const imported = importProjectFile(JSON.stringify(data));
    expect(imported.notes).toHaveLength(1);
    expect(imported.notes[0].id).toBe('valid');
  });

  it('defaults notes to empty array if missing', () => {
    const data = {
      magic: 'NMAPUI_PROJECT',
      version: 1,
      scanData: 'data',
      scanFileName: 'test.xml',
      exportedAt: Date.now(),
    };
    const imported = importProjectFile(JSON.stringify(data));
    expect(imported.notes).toEqual([]);
  });

  it('defaults scanFileName when not a string', () => {
    const data = {
      magic: 'NMAPUI_PROJECT',
      version: 1,
      scanData: 'data',
      scanFileName: 12345,
      exportedAt: Date.now(),
      notes: [],
      mergedScans: [],
    };
    const imported = importProjectFile(JSON.stringify(data));
    expect(imported.scanFileName).toBe('unknown.xml');
  });

  it('defaults exportedAt when not a number', () => {
    const data = {
      magic: 'NMAPUI_PROJECT',
      version: 1,
      scanData: 'data',
      scanFileName: 'test.xml',
      exportedAt: 'not-a-number',
      notes: [],
      mergedScans: [],
    };
    const imported = importProjectFile(JSON.stringify(data));
    expect(typeof imported.exportedAt).toBe('number');
  });

  it('defaults mergedScans to empty array if missing', () => {
    const data = {
      magic: 'NMAPUI_PROJECT',
      version: 1,
      scanData: 'data',
      scanFileName: 'test.xml',
      exportedAt: Date.now(),
      notes: [],
    };
    const imported = importProjectFile(JSON.stringify(data));
    expect(imported.mergedScans).toEqual([]);
  });
});

describe('generateProjectId', () => {
  it('creates deterministic IDs from filename and start time', () => {
    const id1 = generateProjectId('scan.xml', 1700000000);
    const id2 = generateProjectId('scan.xml', 1700000000);
    expect(id1).toBe(id2);
  });

  it('creates different IDs for different inputs', () => {
    const id1 = generateProjectId('scan1.xml', 1700000000);
    const id2 = generateProjectId('scan2.xml', 1700000000);
    expect(id1).not.toBe(id2);
  });

  it('includes proj- prefix', () => {
    const id = generateProjectId('test.xml', 100);
    expect(id).toMatch(/^proj-/);
  });
});
