import type { Note, SavedProject } from '../types/nmap';

const DB_NAME = 'nmapui';
const DB_VERSION = 1;

const STORE_PROJECTS = 'projects';
const STORE_NOTES = 'notes';

// Cache the database connection to avoid opening a new one per operation
let cachedDb: IDBDatabase | null = null;

function openDB(): Promise<IDBDatabase> {
  if (cachedDb) return Promise.resolve(cachedDb);
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_PROJECTS)) {
        db.createObjectStore(STORE_PROJECTS, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(STORE_NOTES)) {
        const noteStore = db.createObjectStore(STORE_NOTES, { keyPath: 'id' });
        noteStore.createIndex('projectId', 'projectId', { unique: false });
      }
    };

    request.onsuccess = () => {
      cachedDb = request.result;
      cachedDb.onclose = () => { cachedDb = null; };
      cachedDb.onerror = () => { cachedDb = null; };
      resolve(cachedDb);
    };
    request.onerror = () => reject(request.error);
  });
}

function txOp<T>(
  storeName: string,
  mode: IDBTransactionMode,
  op: (store: IDBObjectStore) => IDBRequest<T>
): Promise<T> {
  return openDB().then(db => {
    return new Promise<T>((resolve, reject) => {
      const tx = db.transaction(storeName, mode);
      const store = tx.objectStore(storeName);
      const req = op(store);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  });
}

// ========== Notes (keyed by project ID prefix) ==========

interface StoredNote extends Note {
  projectId: string;
}

export async function saveNotes(projectId: string, notes: Note[]): Promise<void> {
  const db = await openDB();
  const tx = db.transaction(STORE_NOTES, 'readwrite');
  const store = tx.objectStore(STORE_NOTES);

  // Delete all existing notes for this project
  const index = store.index('projectId');
  const getReq = index.getAllKeys(projectId);

  await new Promise<void>((resolve, reject) => {
    getReq.onsuccess = () => {
      const keys = getReq.result;
      for (const key of keys) {
        store.delete(key);
      }
      // Add all current notes
      for (const note of notes) {
        store.put({ ...note, projectId });
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    };
    getReq.onerror = () => reject(getReq.error);
  });
}

export async function loadNotes(projectId: string): Promise<Note[]> {
  const db = await openDB();
  return new Promise<Note[]>((resolve, reject) => {
    const tx = db.transaction(STORE_NOTES, 'readonly');
    const store = tx.objectStore(STORE_NOTES);
    const index = store.index('projectId');
    const req = index.getAll(projectId);
    req.onsuccess = () => {
      const results = req.result as StoredNote[];
      // Strip projectId before returning
      resolve(results.map(({ projectId: _, ...note }) => note));
    };
    req.onerror = () => reject(req.error);
  });
}

// ========== Projects ==========

export async function saveProject(project: SavedProject): Promise<void> {
  await txOp(STORE_PROJECTS, 'readwrite', store => store.put(project));
}

export async function loadProject(id: string): Promise<SavedProject | undefined> {
  return txOp(STORE_PROJECTS, 'readonly', store => store.get(id));
}

export async function listProjects(): Promise<SavedProject[]> {
  return txOp(STORE_PROJECTS, 'readonly', store => store.getAll());
}

export async function deleteProject(id: string): Promise<void> {
  const db = await openDB();
  const tx = db.transaction([STORE_PROJECTS, STORE_NOTES], 'readwrite');

  // Delete project
  tx.objectStore(STORE_PROJECTS).delete(id);

  // Delete associated notes
  const noteStore = tx.objectStore(STORE_NOTES);
  const index = noteStore.index('projectId');
  const getReq = index.getAllKeys(id);

  await new Promise<void>((resolve, reject) => {
    getReq.onsuccess = () => {
      for (const key of getReq.result) {
        noteStore.delete(key);
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    };
    getReq.onerror = () => reject(getReq.error);
  });
}

// ========== Portable Project File (.nmapui) ==========

const PROJECT_FILE_VERSION = 1;
const PROJECT_FILE_MAGIC = 'NMAPUI_PROJECT';

export interface NmapUIProjectFile {
  magic: typeof PROJECT_FILE_MAGIC;
  version: number;
  exportedAt: number;
  scanFileName: string;
  scanData: string;
  notes: Note[];
  mergedScans: { fileName: string; content: string }[];
}

/**
 * Export the current project as a portable JSON file (.nmapui)
 * that can be shared between users/machines.
 */
export function exportProjectFile(
  scanData: string,
  scanFileName: string,
  notes: Note[],
  mergedScans: { fileName: string; content: string }[] = []
): string {
  const project: NmapUIProjectFile = {
    magic: PROJECT_FILE_MAGIC,
    version: PROJECT_FILE_VERSION,
    exportedAt: Date.now(),
    scanFileName,
    scanData,
    notes,
    mergedScans,
  };
  return JSON.stringify(project);
}

/**
 * Import a .nmapui project file. Returns the parsed project data
 * or throws an error if the file is invalid.
 */
export function importProjectFile(content: string): NmapUIProjectFile {
  let data: any;
  try {
    data = JSON.parse(content);
  } catch {
    throw new Error('Invalid project file: not valid JSON');
  }

  if (!data || data.magic !== PROJECT_FILE_MAGIC) {
    throw new Error('Invalid project file: missing NmapUI signature');
  }

  if (!data.scanData || typeof data.scanData !== 'string') {
    throw new Error('Invalid project file: missing scan data');
  }

  // Validate notes array - filter to structurally valid notes only
  if (!Array.isArray(data.notes)) {
    data.notes = [];
  } else {
    data.notes = data.notes.filter((n: any) =>
      n &&
      typeof n.id === 'string' &&
      typeof n.title === 'string' &&
      typeof n.content === 'string' &&
      Array.isArray(n.targets) &&
      Array.isArray(n.screenshots) &&
      typeof n.createdAt === 'number' &&
      typeof n.updatedAt === 'number'
    );
  }

  if (!Array.isArray(data.mergedScans)) {
    data.mergedScans = [];
  }

  // Validate remaining fields with safe defaults
  if (typeof data.scanFileName !== 'string') data.scanFileName = 'unknown.xml';
  if (typeof data.exportedAt !== 'number') data.exportedAt = Date.now();

  return data as NmapUIProjectFile;
}

/**
 * Download a file to the user's machine.
 */
export function downloadFile(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ========== Auto-save helpers ==========

/**
 * Generate a stable project ID from scan data for consistent keying.
 */
export function generateProjectId(fileName: string, scanStart: number): string {
  return `proj-${fileName}-${scanStart}`;
}

/**
 * Debounced save: returns a function that debounces calls.
 */
export function createDebouncedSave(delayMs: number = 1000) {
  let timer: ReturnType<typeof setTimeout> | null = null;
  return (fn: () => Promise<void>) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      fn().catch(err => console.error('Auto-save failed:', err));
    }, delayMs);
  };
}
