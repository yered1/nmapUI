import React, { useCallback, useEffect, useState } from 'react';
import { useAppStore } from './store/appStore';
import { parseNmapOutput } from './parser/nmapParser';
import { importProjectFile } from './utils/storage';
import { isEncryptedEnvelope, type EncryptedEnvelope } from './utils/crypto';
import { ErrorBoundary } from './components/ErrorBoundary';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { ImportView } from './components/ImportView';
import { DashboardView } from './components/DashboardView';
import { HostsView } from './components/HostsView';
import { PortsView } from './components/PortsView';
import { ServicesView } from './components/ServicesView';
import { NotesView } from './components/NotesView';
import { ExportDialog } from './components/ExportDialog';
import { DiffView } from './components/DiffView';

import { MergeDialog } from './components/MergeDialog';
import { DecryptDialog } from './components/DecryptDialog';

function AppInner() {
  const store = useAppStore();
  const { state, filteredHosts } = store;
  const [showDiff, setShowDiff] = useState(false);
  const [showMerge, setShowMerge] = useState(false);
  const [decryptPending, setDecryptPending] = useState<{ envelope: EncryptedEnvelope; rawContent: string; fileName: string } | null>(null);
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    if (typeof localStorage !== 'undefined') {
      return (localStorage.getItem('nmapui-theme') as 'dark' | 'light') || 'dark';
    }
    return 'dark';
  });

  // Apply theme
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('nmapui-theme', theme);
  }, [theme]);

  const loadProjectContent = useCallback((content: string, fileName: string) => {
    store.setLoading(true);

    // Check if it's a .nmapui project file
    if (fileName.endsWith('.nmapui') || content.trimStart().startsWith('{"magic":"NMAPUI_PROJECT"')) {
      try {
        const project = importProjectFile(content);
        const scan = parseNmapOutput(project.scanData);

        // Use setScanWithNotes to atomically set scan + notes, avoiding
        // the race condition with async IndexedDB note loading
        store.setScanWithNotes(scan, project.scanFileName, project.scanData, project.notes);

        // Apply merged scans
        for (const merged of project.mergedScans) {
          try {
            const mergedScan = parseNmapOutput(merged.content);
            store.mergeScan(mergedScan);
          } catch {
            // Skip invalid merged scans
          }
        }
      } catch (err: any) {
        console.error('NmapUI project import error:', err);
        store.setError(err.message || 'Failed to import project file');
      }
      return;
    }

    try {
      const scan = parseNmapOutput(content);
      store.setScan(scan, fileName, content);
    } catch (err: any) {
      console.error('NmapUI parse error:', err);
      store.setError(err.message || 'Failed to parse file');
    }
  }, [store]);

  const handleFileLoad = useCallback((content: string, fileName: string) => {
    // Check if the file is encrypted
    const envelope = isEncryptedEnvelope(content);
    if (envelope) {
      setDecryptPending({ envelope, rawContent: content, fileName });
      return;
    }

    loadProjectContent(content, fileName);
  }, [loadProjectContent]);

  const handleDecrypted = useCallback((plaintext: string, fileName: string) => {
    setDecryptPending(null);
    loadProjectContent(plaintext, fileName);
  }, [loadProjectContent]);

  // Wire up Electron IPC if running in Electron
  useEffect(() => {
    if (!window.electronAPI) return;
    const cleanupFile = window.electronAPI.onFileOpened((data) => {
      handleFileLoad(data.content, data.fileName);
    });
    const cleanupExport = window.electronAPI.onTriggerExport(() => {
      store.setShowExportDialog(true);
    });
    return () => {
      cleanupFile?.();
      cleanupExport?.();
    };
  }, [handleFileLoad, store]);

  // Global keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Escape: close modals, deselect host, clear selection
      if (e.key === 'Escape') {
        if (decryptPending) {
          setDecryptPending(null);
          return;
        }
        if (state.showNoteEditor) {
          store.closeNoteEditor();
          return;
        }
        if (state.showExportDialog) {
          store.setShowExportDialog(false);
          return;
        }
        if (showMerge) {
          setShowMerge(false);
          return;
        }
        if (showDiff) {
          setShowDiff(false);
          return;
        }
        if (store.selectedHost) {
          store.setSelectedHostId(null);
          return;
        }
        if (state.selectedHostIds.size > 0) {
          store.clearSelection();
          return;
        }
        if (state.showFilterPanel) {
          store.setShowFilterPanel(false);
          return;
        }
      }

      // Ctrl/Cmd + O: open file
      if ((e.ctrlKey || e.metaKey) && e.key === 'o') {
        e.preventDefault();
        if (window.electronAPI) {
          window.electronAPI.openFileDialog().then(result => {
            if (result) handleFileLoad(result.content, result.fileName);
          });
        }
      }

      // Ctrl/Cmd + E: export
      if ((e.ctrlKey || e.metaKey) && e.key === 'e') {
        e.preventDefault();
        if (state.scan) store.setShowExportDialog(true);
      }

      // Ctrl/Cmd + F: focus search (if on hosts view)
      if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
        const searchInput = document.querySelector('.search-box .input') as HTMLInputElement;
        if (searchInput) {
          e.preventDefault();
          searchInput.focus();
        }
      }

      // Ctrl/Cmd + D: toggle diff view
      if ((e.ctrlKey || e.metaKey) && e.key === 'd') {
        e.preventDefault();
        if (state.scan) setShowDiff(prev => !prev);
      }

      // Ctrl/Cmd + N: new note
      if ((e.ctrlKey || e.metaKey) && e.key === 'n') {
        e.preventDefault();
        if (state.scan) store.openNoteEditor();
      }

      // Ctrl/Cmd + M: merge scan
      if ((e.ctrlKey || e.metaKey) && e.key === 'm') {
        e.preventDefault();
        if (state.scan) setShowMerge(true);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [state, store, handleFileLoad, showDiff, showMerge, decryptPending]);

  const toggleTheme = useCallback(() => {
    setTheme(prev => prev === 'dark' ? 'light' : 'dark');
  }, []);

  const renderContent = () => {
    if (!state.scan) {
      return <ImportView onFileLoad={handleFileLoad} error={state.error} />;
    }

    switch (state.viewMode) {
      case 'dashboard':
        return <DashboardView scan={state.scan} hosts={filteredHosts} store={store} />;
      case 'hosts':
        return <HostsView scan={state.scan} hosts={filteredHosts} store={store} onImportResults={() => setShowMerge(true)} />;
      case 'ports':
        return <PortsView scan={state.scan} hosts={filteredHosts} store={store} />;
      case 'services':
        return <ServicesView scan={state.scan} hosts={filteredHosts} store={store} />;
      case 'notes':
        return <NotesView scan={state.scan} store={store} />;
      default:
        return <DashboardView scan={state.scan} hosts={filteredHosts} store={store} />;
    }
  };

  return (
    <div className="app-layout">
      <Header
        fileName={state.fileName}
        hasScan={!!state.scan}
        onImport={() => store.reset()}
        onExport={() => store.setShowExportDialog(true)}
        onDiff={() => setShowDiff(true)}
        onMerge={() => setShowMerge(true)}
        onNewNote={() => store.openNoteEditor()}
        onToggleTheme={toggleTheme}
        theme={theme}
      />
      <div className="app-body">
        {state.scan && (
          <Sidebar
            viewMode={state.viewMode}
            onViewChange={store.setViewMode}
            scan={state.scan}
            filteredCount={filteredHosts.length}
            noteCount={state.notes.length}
          />
        )}
        <main className="app-content" role="main" aria-label="Main content">
          {state.loading && <div className="loading-spinner" role="status" aria-label="Loading">Loading...</div>}
          {renderContent()}
        </main>
      </div>
      {state.showExportDialog && state.scan && (
        <ExportDialog
          scan={state.scan}
          hosts={filteredHosts}
          selectedIds={state.selectedHostIds}
          notes={state.notes}
          rawScanData={state.rawScanData}
          fileName={state.fileName}
          onClose={() => store.setShowExportDialog(false)}
        />
      )}
      {showDiff && state.scan && (
        <DiffView
          baseScan={state.scan}
          onClose={() => setShowDiff(false)}
        />
      )}
      {showMerge && state.scan && (
        <MergeDialog
          store={store}
          onClose={() => setShowMerge(false)}
        />
      )}
      {decryptPending && (
        <DecryptDialog
          envelope={decryptPending.envelope}
          rawContent={decryptPending.rawContent}
          fileName={decryptPending.fileName}
          onDecrypted={handleDecrypted}
          onClose={() => setDecryptPending(null)}
        />
      )}
    </div>
  );
}

export function App() {
  return (
    <ErrorBoundary>
      <AppInner />
    </ErrorBoundary>
  );
}
