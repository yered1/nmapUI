// Complete Nmap data model covering all fields from nmap XML DTD

export interface NmapScan {
  scanner: string;
  args: string;
  start: number;
  startstr: string;
  version: string;
  xmloutputversion: string;
  scaninfo: ScanInfo[];
  verbose: number;
  debugging: number;
  hosts: NmapHost[];
  runstats: RunStats;
  // Derived fields
  totalHosts: number;
  hostsUp: number;
  hostsDown: number;
  hostsFiltered: number;
  scanDuration: number;
  uniquePorts: PortSummary[];
  uniqueServices: ServiceSummary[];
}

export interface ScanInfo {
  type: string;
  protocol: string;
  numservices: number;
  services: string;
}

export interface RunStats {
  finished: {
    time: number;
    timestr: string;
    elapsed: number;
    summary: string;
    exit: string;
  };
  hosts: {
    up: number;
    down: number;
    total: number;
  };
}

export interface NmapHost {
  id: string; // generated unique id
  starttime: number;
  endtime: number;
  status: HostStatus;
  addresses: Address[];
  hostnames: Hostname[];
  ports: Port[];
  os: OSInfo;
  uptime: Uptime | null;
  distance: number | null;
  tcpsequence: TCPSequence | null;
  ipidsequence: IPIDSequence | null;
  tcptssequence: TCPTSSequence | null;
  times: Times | null;
  trace: TraceInfo | null;
  hostscripts: Script[];
  smurfs: Smurf[];
  // Derived convenience fields
  ip: string;
  ipv6: string;
  mac: string;
  hostname: string;
  mainOS: string;
  openPortCount: number;
  closedPortCount: number;
  filteredPortCount: number;
}

export interface HostStatus {
  state: 'up' | 'down' | 'unknown' | 'skipped';
  reason: string;
  reason_ttl: number;
}

export interface Address {
  addr: string;
  addrtype: 'ipv4' | 'ipv6' | 'mac';
  vendor?: string;
}

export interface Hostname {
  name: string;
  type: 'user' | 'PTR' | '';
}

export interface Port {
  protocol: string;
  portid: number;
  state: PortState;
  service: Service | null;
  scripts: Script[];
  owner?: string;
}

export interface PortState {
  state: string; // open, closed, filtered, unfiltered, open|filtered, closed|filtered
  reason: string;
  reason_ttl: number;
  reason_ip?: string;
}

export interface Service {
  name: string;
  product?: string;
  version?: string;
  extrainfo?: string;
  ostype?: string;
  method: string;
  conf: number;
  tunnel?: string;
  proto?: string;
  rpcnum?: string;
  lowver?: string;
  highver?: string;
  hostname?: string;
  servicefp?: string;
  devicetype?: string;
  cpes: string[];
}

export interface Script {
  id: string;
  output: string;
  elements: ScriptElement[];
}

export interface ScriptElement {
  key: string;
  value: string;
  children?: ScriptElement[];
}

export interface OSInfo {
  osmatch: OSMatch[];
  osfingerprint: string[];
  portused: PortUsed[];
}

export interface OSMatch {
  name: string;
  accuracy: number;
  line: number;
  osclass: OSClass[];
}

export interface OSClass {
  type: string;
  vendor: string;
  osfamily: string;
  osgen: string;
  accuracy: number;
  cpes: string[];
}

export interface PortUsed {
  state: string;
  proto: string;
  portid: number;
}

export interface Uptime {
  seconds: number;
  lastboot: string;
}

export interface TCPSequence {
  index: number;
  difficulty: string;
  values: string;
}

export interface IPIDSequence {
  class: string;
  values: string;
}

export interface TCPTSSequence {
  class: string;
  values: string;
}

export interface Times {
  srtt: number;
  rttvar: number;
  to: number;
}

export interface TraceInfo {
  port: number;
  proto: string;
  hops: TraceHop[];
}

export interface TraceHop {
  ttl: number;
  rtt: number;
  ipaddr: string;
  host?: string;
}

export interface Smurf {
  responses: string;
}

// Aggregation types
export interface PortSummary {
  port: number;
  protocol: string;
  state: string;
  service: string;
  product: string;
  count: number;
  hosts: string[];
}

export interface ServiceSummary {
  name: string;
  product: string;
  version: string;
  count: number;
  ports: number[];
  hosts: string[];
}

// Filter types
export type FilterOperator = 'equals' | 'not_equals' | 'contains' | 'not_contains' |
  'starts_with' | 'ends_with' | 'greater_than' | 'less_than' | 'in_range' |
  'regex' | 'is_empty' | 'is_not_empty';

export interface FilterRule {
  id: string;
  field: string;
  operator: FilterOperator;
  value: string;
  enabled: boolean;
}

export interface FilterGroup {
  id: string;
  logic: 'AND' | 'OR';
  rules: FilterRule[];
}

export type SortDirection = 'asc' | 'desc';

export interface SortConfig {
  field: string;
  direction: SortDirection;
}

// Column definition for table views
export interface ColumnDef {
  id: string;
  label: string;
  field: string;
  sortable: boolean;
  filterable: boolean;
  width?: number;
  minWidth?: number;
  visible: boolean;
  render?: (value: any, host: NmapHost) => string;
}

// Export types
export type ExportFormat = 'csv' | 'json' | 'html' | 'xml' | 'markdown' | 'project';

export interface ExportOptions {
  format: ExportFormat;
  includeHostDetails: boolean;
  includePorts: boolean;
  includeScripts: boolean;
  includeOS: boolean;
  includeTrace: boolean;
  includeNotes?: boolean;
  notes?: Note[];
  selectedHostIds?: string[];
}

// View types
export type ViewMode = 'dashboard' | 'hosts' | 'ports' | 'services' | 'notes' | 'vulnerabilities';

// Tab types for host detail
export type HostDetailTab = 'ports' | 'os' | 'scripts' | 'trace' | 'timing' | 'notes' | 'suggestions' | 'raw';

// ========== Notes & Screenshots ==========

export interface NoteTarget {
  hostId: string;
  ip: string;
  portId?: number;
  protocol?: string;
}

export interface Screenshot {
  id: string;
  dataUrl: string;
  fileName: string;
  createdAt: number;
}

export interface Note {
  id: string;
  title: string;
  content: string;
  screenshots: Screenshot[];
  targets: NoteTarget[];
  createdAt: number;
  updatedAt: number;
}

// ========== Nmap Script Suggestions ==========

export interface ScriptSuggestion {
  scriptId: string;
  description: string;
  category: string;
  args?: string;
}

// ========== Saved Project ==========

export interface SavedProject {
  id: string;
  name: string;
  scanData: string; // raw scan file content
  scanFileName: string;
  notes: Note[];
  mergedScans: { fileName: string; content: string }[];
  savedAt: number;
}
