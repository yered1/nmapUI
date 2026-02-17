import React, { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { useEditor, EditorContent } from '@tiptap/react';
import StarterKit from '@tiptap/starter-kit';
import Underline from '@tiptap/extension-underline';
import { TextStyle } from '@tiptap/extension-text-style';
import Color from '@tiptap/extension-color';
import Highlight from '@tiptap/extension-highlight';
import Image from '@tiptap/extension-image';
import Placeholder from '@tiptap/extension-placeholder';
import type { NmapScan, NmapHost, Note, NoteTarget, Screenshot } from '../types/nmap';
import type { AppStore } from '../store/appStore';

interface NoteEditorProps {
  scan: NmapScan;
  store: AppStore;
  onClose: () => void;
}

function generateId(): string {
  return crypto.randomUUID();
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function escapeAttr(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Convert old plain-text content to HTML, preserving line breaks
function plainTextToHtml(text: string): string {
  if (!text) return '';
  // If it already looks like HTML, return as-is
  if (text.trim().startsWith('<')) return text;
  return text.split('\n').map(line => `<p>${escapeHtml(line) || '<br>'}</p>`).join('');
}

// Migrate old-style screenshots into HTML as inline images at the end
function migrateScreenshots(html: string, screenshots: Screenshot[]): string {
  if (screenshots.length === 0) return html;
  const imgs = screenshots.map(ss => {
    // Only allow data: image URIs
    const safeSrc = ss.dataUrl.startsWith('data:image/') ? escapeAttr(ss.dataUrl) : '';
    return `<img src="${safeSrc}" alt="${escapeAttr(ss.fileName)}" />`;
  }).join('');
  return html + imgs;
}

const TEXT_COLORS = [
  { name: 'Default', color: '' },
  { name: 'Red', color: '#ef4444' },
  { name: 'Orange', color: '#f97316' },
  { name: 'Yellow', color: '#eab308' },
  { name: 'Green', color: '#22c55e' },
  { name: 'Blue', color: '#3b82f6' },
  { name: 'Purple', color: '#a855f7' },
  { name: 'Pink', color: '#ec4899' },
  { name: 'Gray', color: '#6b7280' },
];

const HIGHLIGHT_COLORS = [
  { name: 'None', color: '' },
  { name: 'Yellow', color: '#fef08a' },
  { name: 'Green', color: '#bbf7d0' },
  { name: 'Blue', color: '#bfdbfe' },
  { name: 'Purple', color: '#e9d5ff' },
  { name: 'Pink', color: '#fce7f3' },
  { name: 'Orange', color: '#fed7aa' },
  { name: 'Red', color: '#fecaca' },
];

const FONT_SIZES = [
  { label: 'Small', class: 'text-sm', tag: null, level: 0 },
  { label: 'Body', class: 'text-body', tag: 'paragraph', level: 0 },
  { label: 'Large', class: 'text-lg', tag: 'heading', level: 3 },
  { label: 'Title', class: 'text-xl', tag: 'heading', level: 2 },
  { label: 'Heading', class: 'text-2xl', tag: 'heading', level: 1 },
];

export function NoteEditor({ scan, store, onClose }: NoteEditorProps) {
  const { state } = store;
  const existingNote = state.editingNoteId
    ? state.notes.find(n => n.id === state.editingNoteId) || null
    : null;

  const [title, setTitle] = useState(existingNote?.title || '');
  const [targets, setTargets] = useState<NoteTarget[]>(() => {
    if (existingNote) return existingNote.targets;
    if (state.noteEditorDefaults) {
      const d = state.noteEditorDefaults;
      if (d.hostId && d.ip) {
        return [{
          hostId: d.hostId,
          ip: d.ip,
          portId: d.portId,
          protocol: d.protocol,
        }];
      }
    }
    return [];
  });
  const [targetSearch, setTargetSearch] = useState('');
  const [showTargetPicker, setShowTargetPicker] = useState(false);
  const [expandedTargetHost, setExpandedTargetHost] = useState<string | null>(null);

  // Dropdown states
  const [showTextColor, setShowTextColor] = useState(false);
  const [showHighlight, setShowHighlight] = useState(false);
  const [showFontSize, setShowFontSize] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Use a ref for image insertion so that handlePaste/handleDrop closures
  // in editorProps always call the latest version (avoids stale closure)
  const insertImageRef = useRef<(file: File) => void>(() => {});

  // Build initial HTML content from existing note
  const initialContent = useMemo(() => {
    if (!existingNote) return '';
    let html = plainTextToHtml(existingNote.content);
    // Migrate old separate screenshots to inline images
    if (existingNote.screenshots.length > 0) {
      html = migrateScreenshots(html, existingNote.screenshots);
    }
    return html;
  }, [existingNote]);

  const editor = useEditor({
    // immediatelyRender: false is required for React 18 StrictMode compatibility.
    // Without it, StrictMode's double mount/unmount cycle breaks the contenteditable
    // state, causing keyboard typing to stop working while paste still functions.
    immediatelyRender: false,
    extensions: [
      StarterKit.configure({
        heading: { levels: [1, 2, 3] },
      }),
      Underline,
      TextStyle,
      Color,
      Highlight.configure({ multicolor: true }),
      Image.configure({
        inline: true,
        allowBase64: true,
        HTMLAttributes: {
          class: 'note-inline-image',
        },
      }),
      Placeholder.configure({
        placeholder: 'Write your notes here... Paste images with Ctrl+V',
      }),
    ],
    content: initialContent,
    editorProps: {
      attributes: {
        class: 'note-tiptap-editor',
      },
      handlePaste(view, event) {
        const items = event.clipboardData?.items;
        if (!items) return false;
        for (const item of Array.from(items)) {
          if (item.type.startsWith('image/')) {
            event.preventDefault();
            const file = item.getAsFile();
            if (file) insertImageRef.current(file);
            return true;
          }
        }
        return false;
      },
      handleDrop(view, event) {
        const files = event.dataTransfer?.files;
        if (!files || files.length === 0) return false;
        for (const file of Array.from(files)) {
          if (file.type.startsWith('image/')) {
            event.preventDefault();
            insertImageRef.current(file);
            return true;
          }
        }
        return false;
      },
    },
  });

  // Keep the ref updated with the latest editor instance
  const insertImageFromFile = useCallback((file: File) => {
    if (!editor) return;
    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = reader.result as string;
      editor.chain().focus().setImage({ src: dataUrl, alt: file.name }).run();
    };
    reader.readAsDataURL(file);
  }, [editor]);
  insertImageRef.current = insertImageFromFile;

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files) return;
    for (const file of Array.from(files)) {
      if (file.type.startsWith('image/')) {
        insertImageFromFile(file);
      }
    }
    e.target.value = '';
  }, [insertImageFromFile]);

  const addHostTarget = useCallback((host: NmapHost) => {
    const existing = targets.find(t => t.hostId === host.id && !t.portId);
    if (!existing) {
      setTargets(prev => [...prev, {
        hostId: host.id,
        ip: host.ip || host.ipv6,
      }]);
    }
  }, [targets]);

  const addPortTarget = useCallback((host: NmapHost, portId: number, protocol: string) => {
    const existing = targets.find(t => t.hostId === host.id && t.portId === portId && t.protocol === protocol);
    if (!existing) {
      setTargets(prev => [...prev, {
        hostId: host.id,
        ip: host.ip || host.ipv6,
        portId,
        protocol,
      }]);
    }
  }, [targets]);

  const removeTarget = useCallback((index: number) => {
    setTargets(prev => prev.filter((_, i) => i !== index));
  }, []);

  const handleSave = useCallback(() => {
    if (!editor) return;
    const html = editor.getHTML();
    const isEmpty = editor.isEmpty && !title.trim();
    if (isEmpty) return;

    const now = Date.now();
    const note: Note = {
      id: existingNote?.id || generateId(),
      title: title.trim() || 'Untitled Note',
      content: html,
      screenshots: [], // Screenshots are now inline in HTML
      targets,
      createdAt: existingNote?.createdAt || now,
      updatedAt: now,
    };

    if (existingNote) {
      store.updateNote(note);
    } else {
      store.addNote(note);
    }
    onClose();
  }, [editor, title, targets, existingNote, store, onClose]);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClick = () => {
      setShowTextColor(false);
      setShowHighlight(false);
      setShowFontSize(false);
    };
    document.addEventListener('click', handleClick);
    return () => document.removeEventListener('click', handleClick);
  }, []);

  // Filter hosts for target picker
  const filteredHosts = targetSearch
    ? scan.hosts.filter(h => {
        const q = targetSearch.toLowerCase();
        return (h.ip && h.ip.toLowerCase().includes(q)) ||
               (h.ipv6 && h.ipv6.toLowerCase().includes(q)) ||
               (h.hostname && h.hostname.toLowerCase().includes(q)) ||
               h.ports.some(p => String(p.portid).includes(q) ||
                 (p.service?.name || '').toLowerCase().includes(q));
      })
    : scan.hosts;

  // Current active states for toolbar
  const currentFontSize = (() => {
    if (!editor) return 'Body';
    if (editor.isActive('heading', { level: 1 })) return 'Heading';
    if (editor.isActive('heading', { level: 2 })) return 'Title';
    if (editor.isActive('heading', { level: 3 })) return 'Large';
    return 'Body';
  })();

  return (
    <div className="note-editor-inline">
      {/* Sticky header: back, title, actions */}
      <div className="note-editor-header">
        <button className="btn btn-sm btn-ghost" onClick={onClose}>
          {'\u2190'} Back to Notes
        </button>
        <div className="note-editor-header-spacer" />
        <button className="btn btn-sm" onClick={onClose}>Cancel</button>
        <button
          className="btn btn-sm btn-primary"
          onClick={handleSave}
          disabled={!title.trim() && (editor?.isEmpty ?? true)}
        >
          {existingNote ? 'Save Changes' : 'Create Note'}
        </button>
      </div>

      {/* Sticky: title input + formatting toolbar */}
      <div className="note-editor-sticky">
        <input
          className="note-title-input"
          type="text"
          placeholder="Title"
          value={title}
          onChange={e => setTitle(e.target.value)}
          autoFocus
        />

        {/* Formatting toolbar */}
        {editor && (
          <div className="note-toolbar">
            {/* Font size dropdown */}
            <div className="note-toolbar-dropdown" onClick={e => e.stopPropagation()}>
              <button
                className="note-toolbar-btn note-toolbar-select"
                onClick={() => { setShowFontSize(!showFontSize); setShowTextColor(false); setShowHighlight(false); }}
                title="Text style"
              >
                {currentFontSize}
                <span className="note-toolbar-caret">{'\u25BE'}</span>
              </button>
              {showFontSize && (
                <div className="note-toolbar-menu">
                  {FONT_SIZES.map(size => (
                    <button
                      key={size.label}
                      className={`note-toolbar-menu-item ${size.class} ${currentFontSize === size.label ? 'active' : ''}`}
                      onClick={() => {
                        if (size.tag === 'heading') {
                          editor.chain().focus().toggleHeading({ level: size.level as 1 | 2 | 3 }).run();
                        } else {
                          editor.chain().focus().setParagraph().run();
                        }
                        setShowFontSize(false);
                      }}
                    >
                      {size.label}
                    </button>
                  ))}
                </div>
              )}
            </div>

            <div className="note-toolbar-divider" />

            {/* Bold */}
            <button
              className={`note-toolbar-btn ${editor.isActive('bold') ? 'active' : ''}`}
              onClick={() => editor.chain().focus().toggleBold().run()}
              title="Bold (Ctrl+B)"
            >
              <strong>B</strong>
            </button>

            {/* Italic */}
            <button
              className={`note-toolbar-btn ${editor.isActive('italic') ? 'active' : ''}`}
              onClick={() => editor.chain().focus().toggleItalic().run()}
              title="Italic (Ctrl+I)"
            >
              <em>I</em>
            </button>

            {/* Underline */}
            <button
              className={`note-toolbar-btn ${editor.isActive('underline') ? 'active' : ''}`}
              onClick={() => editor.chain().focus().toggleUnderline().run()}
              title="Underline (Ctrl+U)"
            >
              <span style={{ textDecoration: 'underline' }}>U</span>
            </button>

            {/* Strikethrough */}
            <button
              className={`note-toolbar-btn ${editor.isActive('strike') ? 'active' : ''}`}
              onClick={() => editor.chain().focus().toggleStrike().run()}
              title="Strikethrough"
            >
              <span style={{ textDecoration: 'line-through' }}>S</span>
            </button>

            <div className="note-toolbar-divider" />

            {/* Text color */}
            <div className="note-toolbar-dropdown" onClick={e => e.stopPropagation()}>
              <button
                className={`note-toolbar-btn ${editor.isActive('textStyle') ? 'active' : ''}`}
                onClick={() => { setShowTextColor(!showTextColor); setShowHighlight(false); setShowFontSize(false); }}
                title="Text color"
              >
                <span className="note-toolbar-color-icon">
                  A
                  <span
                    className="note-toolbar-color-bar"
                    style={{ background: editor.getAttributes('textStyle').color || 'var(--text-primary)' }}
                  />
                </span>
              </button>
              {showTextColor && (
                <div className="note-toolbar-menu note-color-grid">
                  {TEXT_COLORS.map(c => (
                    <button
                      key={c.name}
                      className="note-color-swatch"
                      style={{ background: c.color || 'var(--text-primary)' }}
                      title={c.name}
                      onClick={() => {
                        if (c.color) {
                          editor.chain().focus().setColor(c.color).run();
                        } else {
                          editor.chain().focus().unsetColor().run();
                        }
                        setShowTextColor(false);
                      }}
                    />
                  ))}
                </div>
              )}
            </div>

            {/* Highlight color */}
            <div className="note-toolbar-dropdown" onClick={e => e.stopPropagation()}>
              <button
                className={`note-toolbar-btn ${editor.isActive('highlight') ? 'active' : ''}`}
                onClick={() => { setShowHighlight(!showHighlight); setShowTextColor(false); setShowFontSize(false); }}
                title="Highlight color"
              >
                <span className="note-toolbar-highlight-icon">
                  <span
                    className="note-toolbar-highlight-bar"
                    style={{ background: editor.getAttributes('highlight').color || '#fef08a' }}
                  />
                </span>
              </button>
              {showHighlight && (
                <div className="note-toolbar-menu note-color-grid">
                  {HIGHLIGHT_COLORS.map(c => (
                    <button
                      key={c.name}
                      className="note-color-swatch"
                      style={{ background: c.color || 'var(--bg-tertiary)', border: !c.color ? '2px dashed var(--border-light)' : undefined }}
                      title={c.name}
                      onClick={() => {
                        if (c.color) {
                          editor.chain().focus().toggleHighlight({ color: c.color }).run();
                        } else {
                          editor.chain().focus().unsetHighlight().run();
                        }
                        setShowHighlight(false);
                      }}
                    />
                  ))}
                </div>
              )}
            </div>

            <div className="note-toolbar-divider" />

            {/* Bullet list */}
            <button
              className={`note-toolbar-btn ${editor.isActive('bulletList') ? 'active' : ''}`}
              onClick={() => editor.chain().focus().toggleBulletList().run()}
              title="Bullet list"
            >
              {'\u2022'}
            </button>

            {/* Ordered list */}
            <button
              className={`note-toolbar-btn ${editor.isActive('orderedList') ? 'active' : ''}`}
              onClick={() => editor.chain().focus().toggleOrderedList().run()}
              title="Numbered list"
            >
              1.
            </button>

            {/* Blockquote */}
            <button
              className={`note-toolbar-btn ${editor.isActive('blockquote') ? 'active' : ''}`}
              onClick={() => editor.chain().focus().toggleBlockquote().run()}
              title="Quote"
            >
              {'\u201C'}
            </button>

            {/* Code block */}
            <button
              className={`note-toolbar-btn ${editor.isActive('codeBlock') ? 'active' : ''}`}
              onClick={() => editor.chain().focus().toggleCodeBlock().run()}
              title="Code block"
            >
              {'</>'}
            </button>

            <div className="note-toolbar-divider" />

            {/* Insert image */}
            <button
              className="note-toolbar-btn"
              onClick={() => fileInputRef.current?.click()}
              title="Insert image"
            >
              {'\u{1F4F7}'}
            </button>
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*"
              multiple
              style={{ display: 'none' }}
              onChange={handleFileInput}
            />

            {/* Horizontal rule */}
            <button
              className="note-toolbar-btn"
              onClick={() => editor.chain().focus().setHorizontalRule().run()}
              title="Horizontal divider"
            >
              &#x2500;
            </button>
          </div>
        )}
      </div>

      {/* Scrollable content area */}
      <div className="note-editor-scroll">
        {/* Editor content */}
        <div className="note-editor-wrapper">
          <EditorContent editor={editor} />
        </div>

        {/* Targets */}
        <div className="note-editor-targets">
          <div className="form-label-row">
            <label className="form-label">Applies to (IPs / Ports)</label>
            <button
              className="btn btn-sm"
              onClick={() => setShowTargetPicker(!showTargetPicker)}
            >
              {showTargetPicker ? 'Hide Picker' : '+ Add Target'}
            </button>
          </div>

          {/* Selected targets */}
          {targets.length > 0 && (
            <div className="target-chips">
              {targets.map((t, i) => (
                <span key={i} className="target-chip">
                  <span className="target-chip-text">
                    {t.ip}
                    {t.portId !== undefined ? `:${t.portId}/${t.protocol}` : ' (host)'}
                  </span>
                  <button
                    className="target-chip-remove"
                    onClick={() => removeTarget(i)}
                    aria-label="Remove target"
                  >
                    {'\u2715'}
                  </button>
                </span>
              ))}
            </div>
          )}

          {/* Target picker */}
          {showTargetPicker && (
            <div className="target-picker">
              <input
                className="input"
                type="text"
                placeholder="Search hosts/ports..."
                value={targetSearch}
                onChange={e => setTargetSearch(e.target.value)}
                style={{ marginBottom: 8 }}
              />
              <div className="target-picker-list">
                {filteredHosts.map(host => {
                  const isExpanded = expandedTargetHost === host.id;
                  const hostIp = host.ip || host.ipv6 || 'N/A';
                  const isHostTargeted = targets.some(t => t.hostId === host.id && !t.portId);

                  return (
                    <div key={host.id} className="target-picker-host">
                      <div className="target-picker-host-row">
                        <button
                          className="btn btn-sm btn-ghost btn-icon"
                          onClick={() => setExpandedTargetHost(isExpanded ? null : host.id)}
                          style={{ padding: '2px 4px', fontSize: 10 }}
                        >
                          {isExpanded ? '\u25BC' : '\u25B6'}
                        </button>
                        <span className="mono" style={{ flex: 1 }}>
                          {hostIp}
                          {host.hostname ? ` (${host.hostname})` : ''}
                        </span>
                        <button
                          className={`btn btn-sm ${isHostTargeted ? 'btn-primary' : ''}`}
                          onClick={() => addHostTarget(host)}
                          disabled={isHostTargeted}
                          style={{ padding: '1px 6px', fontSize: 10 }}
                        >
                          {isHostTargeted ? 'Added' : '+ Host'}
                        </button>
                      </div>
                      {isExpanded && host.ports.length > 0 && (
                        <div className="target-picker-ports">
                          {host.ports.filter(p => p.state.state === 'open' || p.state.state === 'open|filtered').map(port => {
                            const isPortTargeted = targets.some(
                              t => t.hostId === host.id && t.portId === port.portid && t.protocol === port.protocol
                            );
                            return (
                              <div key={`${port.portid}/${port.protocol}`} className="target-picker-port-row">
                                <span className="mono" style={{ fontSize: 11 }}>
                                  {port.portid}/{port.protocol}
                                </span>
                                <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                                  {port.service?.name || ''}
                                </span>
                                <button
                                  className={`btn btn-sm ${isPortTargeted ? 'btn-primary' : ''}`}
                                  onClick={() => addPortTarget(host, port.portid, port.protocol)}
                                  disabled={isPortTargeted}
                                  style={{ padding: '1px 6px', fontSize: 10, marginLeft: 'auto' }}
                                >
                                  {isPortTargeted ? 'Added' : '+ Port'}
                                </button>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  );
                })}
                {filteredHosts.length === 0 && (
                  <div style={{ padding: 12, textAlign: 'center', color: 'var(--text-muted)', fontSize: 11 }}>
                    No hosts match search
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
