import { useState, useCallback, useMemo, useEffect, useRef } from 'react';
import type { NmapScan, NmapHost, FilterGroup, SortConfig, ViewMode, Note, NoteTarget } from '../types/nmap';
import { applyFilters, applySearch, applySorting } from '../utils/filterEngine';
import { saveNotes, loadNotes, generateProjectId, createDebouncedSave } from '../utils/storage';

export interface AppState {
  scan: NmapScan | null;
  fileName: string;
  rawScanData: string; // raw file content for project export
  viewMode: ViewMode;
  searchQuery: string;
  filterGroup: FilterGroup;
  sorts: SortConfig[];
  selectedHostId: string | null;
  selectedHostIds: Set<string>;
  showExportDialog: boolean;
  showFilterPanel: boolean;
  error: string | null;
  loading: boolean;
  notes: Note[];
  editingNoteId: string | null;
  showNoteEditor: boolean;
  noteEditorDefaults: { hostId?: string; ip?: string; portId?: number; protocol?: string } | null;
  previousViewMode: ViewMode | null;
}

const initialFilterGroup: FilterGroup = {
  id: 'root',
  logic: 'AND',
  rules: [],
};

const initialState: AppState = {
  scan: null,
  fileName: '',
  rawScanData: '',
  viewMode: 'dashboard',
  searchQuery: '',
  filterGroup: initialFilterGroup,
  sorts: [],
  selectedHostId: null,
  selectedHostIds: new Set(),
  showExportDialog: false,
  showFilterPanel: false,
  error: null,
  loading: false,
  notes: [],
  editingNoteId: null,
  showNoteEditor: false,
  noteEditorDefaults: null,
  previousViewMode: null,
};

export function useAppStore() {
  const [state, setState] = useState<AppState>(initialState);
  const debouncedSave = useRef(createDebouncedSave(800));
  // Track whether notes have been loaded/modified at least once for auto-save
  const notesInitialized = useRef(false);
  // Track whether we should skip the auto-load from IndexedDB (for project imports)
  const skipAutoLoad = useRef(false);

  // Auto-save notes when they change
  const projectId = useMemo(() => {
    if (!state.scan || !state.fileName) return null;
    return generateProjectId(state.fileName, state.scan.start);
  }, [state.scan, state.fileName]);

  useEffect(() => {
    if (!projectId) return;
    // Only save if notes have been initialized (avoids saving the initial empty array)
    if (!notesInitialized.current) return;
    debouncedSave.current(() => saveNotes(projectId, state.notes));
  }, [state.notes, projectId]);

  // Load notes when scan is loaded
  const loadSavedNotes = useCallback(async (fileName: string, scanStart: number) => {
    // Skip if the caller already provided notes (e.g., project file import)
    if (skipAutoLoad.current) {
      skipAutoLoad.current = false;
      return;
    }
    try {
      const pid = generateProjectId(fileName, scanStart);
      const notes = await loadNotes(pid);
      if (notes.length > 0) {
        setState(prev => ({ ...prev, notes }));
        notesInitialized.current = true;
      }
    } catch (err) {
      console.error('Failed to load saved notes:', err);
    }
  }, []);

  const setScan = useCallback((scan: NmapScan, fileName: string, rawData?: string) => {
    notesInitialized.current = false;
    setState(prev => ({
      ...prev,
      scan,
      fileName,
      rawScanData: rawData || '',
      viewMode: 'dashboard',
      error: null,
      loading: false,
      selectedHostId: null,
      selectedHostIds: new Set(),
      searchQuery: '',
      filterGroup: initialFilterGroup,
      sorts: [],
      notes: [],
      editingNoteId: null,
      showNoteEditor: false,
      noteEditorDefaults: null,
      previousViewMode: null,
    }));
    // Load any previously saved notes for this scan
    loadSavedNotes(fileName, scan.start);
  }, [loadSavedNotes]);

  const setNotes = useCallback((notes: Note[]) => {
    notesInitialized.current = true;
    setState(prev => ({ ...prev, notes }));
  }, []);

  /**
   * setScan variant that also loads notes from provided data instead of IndexedDB.
   * Used for project file imports to avoid the race condition.
   */
  const setScanWithNotes = useCallback((scan: NmapScan, fileName: string, rawData: string, notes: Note[]) => {
    skipAutoLoad.current = true;
    notesInitialized.current = notes.length > 0;
    setState(prev => ({
      ...prev,
      scan,
      fileName,
      rawScanData: rawData,
      viewMode: 'dashboard',
      error: null,
      loading: false,
      selectedHostId: null,
      selectedHostIds: new Set(),
      searchQuery: '',
      filterGroup: initialFilterGroup,
      sorts: [],
      notes,
      editingNoteId: null,
      showNoteEditor: false,
      noteEditorDefaults: null,
      previousViewMode: null,
    }));
  }, []);

  const setViewMode = useCallback((viewMode: ViewMode) => {
    setState(prev => ({ ...prev, viewMode, selectedHostId: null }));
  }, []);

  const setSearchQuery = useCallback((searchQuery: string) => {
    setState(prev => ({ ...prev, searchQuery }));
  }, []);

  const setFilterGroup = useCallback((filterGroup: FilterGroup) => {
    setState(prev => ({ ...prev, filterGroup }));
  }, []);

  const setSorts = useCallback((sorts: SortConfig[]) => {
    setState(prev => ({ ...prev, sorts }));
  }, []);

  const toggleSort = useCallback((field: string) => {
    setState(prev => {
      const existing = prev.sorts.find(s => s.field === field);
      if (!existing) {
        return { ...prev, sorts: [{ field, direction: 'asc' }] };
      }
      if (existing.direction === 'asc') {
        return { ...prev, sorts: [{ field, direction: 'desc' }] };
      }
      return { ...prev, sorts: prev.sorts.filter(s => s.field !== field) };
    });
  }, []);

  const setSelectedHostId = useCallback((id: string | null) => {
    setState(prev => ({ ...prev, selectedHostId: id }));
  }, []);

  const toggleHostSelection = useCallback((id: string) => {
    setState(prev => {
      const newSet = new Set(prev.selectedHostIds);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
      return { ...prev, selectedHostIds: newSet };
    });
  }, []);

  const selectAllHosts = useCallback((hosts: NmapHost[]) => {
    setState(prev => ({
      ...prev,
      selectedHostIds: new Set(hosts.map(h => h.id)),
    }));
  }, []);

  const clearSelection = useCallback(() => {
    setState(prev => ({ ...prev, selectedHostIds: new Set() }));
  }, []);

  const setShowExportDialog = useCallback((show: boolean) => {
    setState(prev => ({ ...prev, showExportDialog: show }));
  }, []);

  const setShowFilterPanel = useCallback((show: boolean) => {
    setState(prev => ({ ...prev, showFilterPanel: show }));
  }, []);

  const setError = useCallback((error: string | null) => {
    setState(prev => ({ ...prev, error, loading: false }));
  }, []);

  const setLoading = useCallback((loading: boolean) => {
    setState(prev => ({ ...prev, loading }));
  }, []);

  const reset = useCallback(() => {
    notesInitialized.current = false;
    setState(initialState);
  }, []);

  // ========== Notes Management ==========

  const addNote = useCallback((note: Note) => {
    notesInitialized.current = true;
    setState(prev => ({
      ...prev,
      notes: [...prev.notes, note],
      viewMode: prev.previousViewMode || 'notes',
      showNoteEditor: false,
      editingNoteId: null,
      noteEditorDefaults: null,
      previousViewMode: null,
    }));
  }, []);

  const updateNote = useCallback((note: Note) => {
    notesInitialized.current = true;
    setState(prev => ({
      ...prev,
      notes: prev.notes.map(n => n.id === note.id ? note : n),
      viewMode: prev.previousViewMode || 'notes',
      showNoteEditor: false,
      editingNoteId: null,
      noteEditorDefaults: null,
      previousViewMode: null,
    }));
  }, []);

  const deleteNote = useCallback((noteId: string) => {
    notesInitialized.current = true;
    setState(prev => ({
      ...prev,
      notes: prev.notes.filter(n => n.id !== noteId),
    }));
  }, []);

  const openNoteEditor = useCallback((defaults?: { hostId?: string; ip?: string; portId?: number; protocol?: string }) => {
    setState(prev => ({
      ...prev,
      previousViewMode: prev.viewMode !== 'notes' ? prev.viewMode : prev.previousViewMode,
      viewMode: 'notes',
      showNoteEditor: true,
      editingNoteId: null,
      noteEditorDefaults: defaults || null,
    }));
  }, []);

  const editNote = useCallback((noteId: string) => {
    setState(prev => ({
      ...prev,
      previousViewMode: prev.viewMode !== 'notes' ? prev.viewMode : prev.previousViewMode,
      viewMode: 'notes',
      showNoteEditor: true,
      editingNoteId: noteId,
      noteEditorDefaults: null,
    }));
  }, []);

  const closeNoteEditor = useCallback(() => {
    setState(prev => ({
      ...prev,
      viewMode: prev.previousViewMode || 'notes',
      showNoteEditor: false,
      editingNoteId: null,
      noteEditorDefaults: null,
      previousViewMode: null,
    }));
  }, []);

  // ========== Merge Scan ==========

  const mergeScan = useCallback((newScan: NmapScan) => {
    setState(prev => {
      if (!prev.scan) return prev;
      // Deep clone hosts array to avoid mutating previous state
      const mergedHosts = prev.scan.hosts.map(h => ({
        ...h,
        ports: h.ports.map(p => ({ ...p, scripts: [...p.scripts] })),
        hostscripts: [...h.hostscripts],
      }));
      const merged = { ...prev.scan, hosts: mergedHosts };

      for (const newHost of newScan.hosts) {
        const hostIp = newHost.ip || newHost.ipv6;
        const existingIdx = merged.hosts.findIndex(h => (h.ip || h.ipv6) === hostIp);

        if (existingIdx >= 0) {
          // Merge ports and scripts into existing host
          const existing = merged.hosts[existingIdx];
          const existingPortKeys = new Set(existing.ports.map(p => `${p.portid}/${p.protocol}`));

          for (const port of newHost.ports) {
            const portKey = `${port.portid}/${port.protocol}`;
            if (existingPortKeys.has(portKey)) {
              // Merge scripts into existing port
              const existingPort = existing.ports.find(p => `${p.portid}/${p.protocol}` === portKey);
              if (existingPort) {
                const existingScriptIds = new Set(existingPort.scripts.map(s => s.id));
                for (const script of port.scripts) {
                  if (!existingScriptIds.has(script.id)) {
                    existingPort.scripts.push(script);
                  } else {
                    // Update existing script output with newer data
                    const idx = existingPort.scripts.findIndex(s => s.id === script.id);
                    if (idx >= 0) existingPort.scripts[idx] = script;
                  }
                }
                // Update service info if the new data has more detail
                if (port.service && (!existingPort.service || (port.service.conf > existingPort.service.conf))) {
                  existingPort.service = port.service;
                }
                // Update state if different
                if (port.state.state !== existingPort.state.state) {
                  existingPort.state = port.state;
                }
              }
            } else {
              existing.ports.push(port);
            }
          }

          // Merge host scripts
          const existingHostScriptIds = new Set(existing.hostscripts.map(s => s.id));
          for (const script of newHost.hostscripts) {
            if (!existingHostScriptIds.has(script.id)) {
              existing.hostscripts.push(script);
            }
          }

          // Update port counts
          existing.openPortCount = existing.ports.filter(p => p.state.state === 'open').length;
          existing.closedPortCount = existing.ports.filter(p => p.state.state === 'closed').length;
          existing.filteredPortCount = existing.ports.filter(p => p.state.state === 'filtered' || p.state.state === 'open|filtered').length;
        } else {
          // New host, add it
          merged.hosts.push(newHost);
        }
      }

      // Update scan-level stats
      merged.totalHosts = merged.hosts.length;
      merged.hostsUp = merged.hosts.filter(h => h.status.state === 'up').length;
      merged.hostsDown = merged.hosts.filter(h => h.status.state === 'down').length;

      return { ...prev, scan: merged };
    });
  }, []);

  // ========== Computed values ==========

  const filteredHosts = useMemo(() => {
    if (!state.scan) return [];
    let hosts = state.scan.hosts;
    hosts = applyFilters(hosts, state.filterGroup);
    hosts = applySearch(hosts, state.searchQuery);
    hosts = applySorting(hosts, state.sorts);
    return hosts;
  }, [state.scan, state.filterGroup, state.searchQuery, state.sorts]);

  const selectedHost = useMemo(() => {
    if (!state.selectedHostId || !state.scan) return null;
    return state.scan.hosts.find(h => h.id === state.selectedHostId) || null;
  }, [state.selectedHostId, state.scan]);

  // Note lookup helpers
  const getNotesForHost = useCallback((hostId: string): Note[] => {
    return state.notes.filter(n => n.targets.some(t => t.hostId === hostId));
  }, [state.notes]);

  const getNotesForPort = useCallback((hostId: string, portId: number, protocol: string): Note[] => {
    return state.notes.filter(n =>
      n.targets.some(t => t.hostId === hostId && t.portId === portId && t.protocol === protocol)
    );
  }, [state.notes]);

  const hostsWithNotes = useMemo((): Set<string> => {
    const set = new Set<string>();
    for (const note of state.notes) {
      for (const target of note.targets) {
        set.add(target.hostId);
      }
    }
    return set;
  }, [state.notes]);

  const portsWithNotes = useMemo((): Set<string> => {
    const set = new Set<string>();
    for (const note of state.notes) {
      for (const target of note.targets) {
        if (target.portId !== undefined && target.protocol) {
          set.add(`${target.hostId}:${target.portId}/${target.protocol}`);
        }
      }
    }
    return set;
  }, [state.notes]);

  return {
    state,
    filteredHosts,
    selectedHost,
    setScan,
    setScanWithNotes,
    setViewMode,
    setSearchQuery,
    setFilterGroup,
    setSorts,
    toggleSort,
    setSelectedHostId,
    toggleHostSelection,
    selectAllHosts,
    clearSelection,
    setShowExportDialog,
    setShowFilterPanel,
    setError,
    setLoading,
    reset,
    // Notes
    addNote,
    updateNote,
    deleteNote,
    setNotes,
    openNoteEditor,
    editNote,
    closeNoteEditor,
    getNotesForHost,
    getNotesForPort,
    hostsWithNotes,
    portsWithNotes,
    // Scan merge
    mergeScan,
  };
}

export type AppStore = ReturnType<typeof useAppStore>;
