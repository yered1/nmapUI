import React, { useState, useMemo, useCallback } from 'react';
import type { NmapScan } from '../types/nmap';
import type { AppStore } from '../store/appStore';
import { NoteEditor } from './NoteEditor';
import { sanitizeNoteHtml } from '../utils/sanitize';

interface NotesViewProps {
  scan: NmapScan;
  store: AppStore;
}

export function NotesView({ scan, store }: NotesViewProps) {
  const { state } = store;
  const [search, setSearch] = useState('');
  const [filterTarget, setFilterTarget] = useState<string>('all');
  const [expandedNote, setExpandedNote] = useState<string | null>(null);
  const [screenshotPreview, setScreenshotPreview] = useState<string | null>(null);

  // All hooks must be called unconditionally (React rules of hooks)
  const targetIps = useMemo(() => {
    const ips = new Set<string>();
    for (const note of state.notes) {
      for (const target of note.targets) {
        ips.add(target.ip);
      }
    }
    return Array.from(ips).sort();
  }, [state.notes]);

  const filteredNotes = useMemo(() => {
    let notes = state.notes;
    if (filterTarget !== 'all') {
      notes = notes.filter(n => n.targets.some(t => t.ip === filterTarget));
    }
    if (search) {
      const q = search.toLowerCase();
      notes = notes.filter(n =>
        n.title.toLowerCase().includes(q) ||
        n.content.toLowerCase().includes(q) ||
        n.targets.some(t =>
          t.ip.toLowerCase().includes(q) ||
          (t.portId !== undefined && String(t.portId).includes(q))
        )
      );
    }
    return notes.sort((a, b) => b.updatedAt - a.updatedAt);
  }, [state.notes, search, filterTarget]);

  const handleDeleteNote = useCallback((e: React.MouseEvent, noteId: string) => {
    e.stopPropagation();
    if (confirm('Delete this note? This cannot be undone.')) {
      store.deleteNote(noteId);
    }
  }, [store]);

  const formatDate = (ts: number) => new Date(ts).toLocaleString();

  // If the note editor is open, render it inline (replacing the notes list)
  if (state.showNoteEditor) {
    return (
      <NoteEditor
        scan={scan}
        store={store}
        onClose={store.closeNoteEditor}
      />
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Toolbar */}
      <div className="toolbar">
        <div className="search-box" style={{ maxWidth: 300 }}>
          <span className="icon">{'\u2315'}</span>
          <input
            className="input"
            type="text"
            placeholder="Search notes..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ paddingLeft: 28 }}
          />
        </div>
        <select
          className="select"
          value={filterTarget}
          onChange={e => setFilterTarget(e.target.value)}
        >
          <option value="all">All Targets</option>
          {targetIps.map(ip => <option key={ip} value={ip}>{ip}</option>)}
        </select>
        <div className="header-spacer" />
        <span className="result-count">
          {filteredNotes.length} note{filteredNotes.length !== 1 ? 's' : ''}
        </span>
        <button
          className="btn btn-sm btn-primary"
          onClick={() => store.openNoteEditor()}
        >
          + New Note
        </button>
      </div>

      {/* Notes List */}
      <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
        {filteredNotes.length === 0 ? (
          <div className="empty-state">
            <div className="icon">{'\u270E'}</div>
            <div>{state.notes.length === 0 ? 'No notes yet' : 'No notes match your filters'}</div>
            <button
              className="btn btn-sm btn-primary"
              style={{ marginTop: 12 }}
              onClick={() => store.openNoteEditor()}
            >
              Create your first note
            </button>
          </div>
        ) : (
          <div className="notes-list">
            {filteredNotes.map(note => {
              const isExpanded = expandedNote === note.id;
              return (
                <div key={note.id} className="note-card">
                  <div
                    className="note-card-header"
                    onClick={() => setExpandedNote(isExpanded ? null : note.id)}
                  >
                    <span className="note-expand-icon">{isExpanded ? '\u25BC' : '\u25B6'}</span>
                    <div className="note-card-title-area">
                      <span className="note-card-title">{note.title}</span>
                      <div className="note-card-meta">
                        <span>{formatDate(note.updatedAt)}</span>
                        {(() => {
                          const inlineImgCount = (note.content.match(/<img\s/g) || []).length;
                          const totalImages = note.screenshots.length + inlineImgCount;
                          return totalImages > 0 ? (
                            <span className="note-meta-badge">
                              {'\u{1F4F7}'} {totalImages}
                            </span>
                          ) : null;
                        })()}
                        {note.targets.length > 0 && (
                          <span className="note-meta-badge note-meta-ips">
                            {(() => {
                              const uniqueIps = [...new Set(note.targets.map(t => t.ip))];
                              return uniqueIps.map(ip => (
                                <span key={ip} className="note-meta-ip">{ip}</span>
                              ));
                            })()}
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="note-card-actions" onClick={e => e.stopPropagation()}>
                      <button
                        className="btn btn-sm btn-ghost"
                        onClick={() => store.editNote(note.id)}
                        title="Edit note"
                      >
                        Edit
                      </button>
                      <button
                        className="btn btn-sm btn-ghost btn-danger"
                        onClick={e => handleDeleteNote(e, note.id)}
                        title="Delete note"
                      >
                        Delete
                      </button>
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="note-card-body">
                      {/* Targets */}
                      {note.targets.length > 0 && (
                        <div className="note-targets-section">
                          <div className="note-section-label">Targets</div>
                          <div className="target-chips">
                            {note.targets.map((t, i) => (
                              <span
                                key={i}
                                className="target-chip target-chip-clickable"
                                onClick={() => {
                                  const host = scan.hosts.find(h => h.id === t.hostId);
                                  if (host) {
                                    store.setSelectedHostId(host.id);
                                    store.setViewMode('hosts');
                                  }
                                }}
                              >
                                {t.ip}
                                {t.portId !== undefined ? `:${t.portId}/${t.protocol}` : ''}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Content (rendered as HTML from rich text editor) */}
                      {note.content && (
                        <div className="note-content-section">
                          <div className="note-section-label">Notes</div>
                          {note.content.trim().startsWith('<') ? (
                            <div
                              className="note-content-html"
                              dangerouslySetInnerHTML={{ __html: sanitizeNoteHtml(note.content) }}
                            />
                          ) : (
                            <div className="note-content-text">{note.content}</div>
                          )}
                        </div>
                      )}

                      {/* Legacy screenshots (old notes with separate screenshot arrays) */}
                      {note.screenshots.length > 0 && (
                        <div className="note-screenshots-section">
                          <div className="note-section-label">Screenshots</div>
                          <div className="screenshot-grid">
                            {note.screenshots.filter(ss => ss.dataUrl.startsWith('data:image/')).map(ss => (
                              <div
                                key={ss.id}
                                className="screenshot-thumb"
                                onClick={() => setScreenshotPreview(ss.dataUrl)}
                              >
                                <img src={ss.dataUrl} alt={ss.fileName} />
                                <div className="screenshot-name">{ss.fileName}</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Screenshot preview overlay */}
      {screenshotPreview && screenshotPreview.startsWith('data:image/') && (
        <div className="screenshot-preview-overlay" onClick={() => setScreenshotPreview(null)}>
          <img src={screenshotPreview} alt="Screenshot preview" />
          <button className="btn btn-sm screenshot-preview-close" onClick={() => setScreenshotPreview(null)}>
            Close
          </button>
        </div>
      )}
    </div>
  );
}
