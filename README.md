# NmapUI

Cross-platform desktop application for parsing, viewing, and exporting Nmap scan results. Built with Electron, React, and TypeScript.

**Author:** Yered Cespedes — [https://x.com/i_trmt](https://x.com/i_trmt) | [LinkedIn](https://www.linkedin.com/in/yered-cespedes-52902761/)

## Features

### Import & Parsing
- **Drag & drop** file import or file picker dialog
- **Paste** XML content directly into the app
- **Auto-detect** format: XML (`-oX`), Greppable (`-oG`), and Normal (`-oN`) output
- **Command-line** file association — open `.xml` files directly with NmapUI
- **Scan merging** — import additional scan results to combine with existing data
- **File size validation** — 100 MB limit with clear error messaging
- Parses **all Nmap XML fields** including:
  - Host status, addresses (IPv4, IPv6, MAC), hostnames
  - Ports: state, service, product, version, CPEs, tunnel, confidence
  - OS detection: matches, classes, accuracy, fingerprints
  - Scripts: host scripts and per-port script output with structured elements
  - Traceroute: hops, RTT, hosts
  - TCP/IP sequence prediction and timing data
  - Uptime, distance, smurfs, and run statistics

### Views
- **Dashboard** — scan overview with statistics, charts for top ports, services, OS distribution, and port state breakdown
- **Hosts** — full sortable, filterable table with multi-select, column sorting, and inline search
- **Host Detail** — tabbed view with Ports, OS Detection, Scripts, Notes, Script Suggestions, Trace & Timing, and Raw Data tabs
- **Ports** — aggregated port view across all hosts with state/protocol filtering, expandable host lists, and clickable IPs that navigate to the host detail
- **Services** — aggregated service/product view with CPE tracking, expandable instance details, and clickable IPs
- **Notes** — rich text notes manager with search, target filtering, and inline editing

### Notes & Screenshots
- **Inline rich text editor** (opens directly in the notes panel, no modal) with formatting:
  - Bold, italic, underline, strikethrough
  - Text color picker (9 colors)
  - Highlight/background color picker (7 colors)
  - Headings (3 levels), body text
  - Bullet lists, numbered lists, blockquotes, code blocks
  - Horizontal dividers
  - **Sticky formatting toolbar** — stays visible while scrolling note content
- **Inline screenshots** — paste images from clipboard (Ctrl+V), drag & drop, or file picker; images appear inline within the note text
- **Target association** — link notes to specific hosts and/or ports
- **NSE script suggestions** per port/service with copy-to-clipboard and validated command generation
- **Auto-save** to local IndexedDB with debounced persistence
- **View restoration** — editing a note from Hosts view returns to Hosts after save/close

### Portable Project Files
- **`.nmapui` project format** — single-file container with scan data, merged scans, and all notes
- **Quantum-safe encryption** for portable files:
  - **Symmetric**: AES-256-GCM with PBKDF2 (600K iterations) — quantum-safe (Grover-resistant at 256-bit)
  - **Asymmetric**: ML-KEM-768 (FIPS 203, NIST post-quantum standard) key encapsulation + AES-256-GCM bulk encryption
  - PEM-like key export/import for ML-KEM-768 public and secret keys
  - Built-in key pair generation

### Filtering & Search
- **Global search** across IP, hostname, service, product, OS, scripts, and more
- **Advanced filter builder** with 25+ filterable fields:
  - IP Address, IPv6, MAC, MAC Vendor, Hostname
  - Status, Reason, OS, OS Family, OS Vendor, OS Accuracy
  - Open/Closed/Filtered port counts, total ports
  - Port numbers, services, products, CPEs
  - Uptime, last boot, network distance, TCP difficulty
  - Host script count
- **12 filter operators**: equals, not equals, contains, not contains, starts/ends with, greater/less than, range, regex, is empty, is not empty
- **AND/OR logic** toggle for combining multiple filter rules
- **Per-column sorting** with multi-level sort and IP-aware comparison

### Export
- **6 export formats**: CSV, JSON, HTML Report, XML, Markdown, Portable Project (`.nmapui`)
- **Notes included** in JSON, HTML, and Markdown exports
- **Configurable scope**: all hosts, filtered hosts, or selected hosts
- **Configurable content**: toggle ports, OS, scripts, traceroute data
- **HTML report** with professional dark-themed styling, print-ready
- **Markdown export** with collapsible script sections

### Scan Comparison
- **Diff view**: compare two scans side-by-side
- Highlights **new, removed, and changed** hosts
- Shows **per-port changes** with state transitions
- Summary statistics for quick triage

### Accessibility & UX
- **Light/dark theme** toggle with persistent preference
- **Keyboard shortcuts**: Ctrl+O (open), Ctrl+E (export), Ctrl+F (search), Ctrl+D (compare), Escape (back/close)
- **Right-click context menus** on host rows (copy IP, ports, details)
- **Column visibility picker** — show/hide columns in the host table
- **Copy to clipboard** — IPs, ports, host data, bulk selection
- **Pagination** for large scans (200 hosts per page with load-more)
- **ARIA labels**, roles, keyboard navigation, and screen reader support
- **Error boundary** for graceful crash recovery

### Cross-Platform
- **macOS**: DMG and ZIP builds, `hiddenInset` title bar, Dock file association
- **Linux**: AppImage, DEB, and RPM packages
- **Windows**: NSIS installer and portable builds
- Native menus with keyboard shortcuts (Cmd/Ctrl+O, Cmd/Ctrl+E)
- Electron IPC fully wired to React renderer

## Security

NmapUI takes a defense-in-depth approach:

- **HTML sanitization** — all note content rendered via `dangerouslySetInnerHTML` is sanitized with DOMPurify, allowing only safe formatting tags and `data:image/*` sources (SVG explicitly rejected to prevent embedded scripts)
- **ReDoS protection** — user-supplied regex filters are checked for catastrophic backtracking patterns (nested quantifiers, alternation in groups, adjacent unbounded quantifiers) and input is truncated to 1,000 characters
- **Input validation** — IP addresses and script names are validated before generating nmap commands; project file imports validate magic headers, field types, and note structure
- **Export escaping** — HTML/XML exports escape `&`, `<`, `>`, `"`, and `'`; CSV exports quote cells containing commas, quotes, newlines, and carriage returns; Markdown escapes pipe characters in table cells
- **IPC hardening** — save-file handler uses byte-length size checks and validates dialog filter shapes from the renderer
- **Secure IDs** — `crypto.randomUUID()` for note and host IDs

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | Electron 28 |
| UI | React 18 + TypeScript |
| Build | Vite 5 |
| Rich Text Editor | Tiptap 3 (ProseMirror) |
| XML Parsing | fast-xml-parser |
| HTML Sanitization | DOMPurify |
| Post-Quantum Crypto | @noble/post-quantum (ML-KEM-768) |
| Testing | Vitest + jsdom |
| Packaging | electron-builder |

## Getting Started

### Prerequisites

- Node.js 18+ and npm

### Development

```bash
# Install dependencies
npm install

# Run in browser (no Electron)
npm run dev

# Run with Electron
npm run electron:dev
```

### Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch
```

152 tests across 6 test suites covering the parser, crypto, filter engine, export engine, storage/import validation, and HTML sanitization.

### Production Build

```bash
# Build for current platform
npm run electron:build

# Build for specific platforms
npm run electron:build:mac
npm run electron:build:win
npm run electron:build:linux
```

Build artifacts are placed in the `release/` directory.

### Usage

1. Launch the app
2. Drag & drop an Nmap XML file, or click to browse
3. Explore results in Dashboard, Hosts, Ports, or Services views
4. Use the search bar and filter panel for advanced queries
5. Add rich-text notes with inline screenshots to any host or port
6. Select hosts and export in your preferred format

### Generating Nmap Output

```bash
# XML output (recommended - most complete)
nmap -oX scan.xml target

# Full scan with OS detection and scripts
sudo nmap -sV -sC -O -oX scan.xml target

# Greppable output (also supported)
nmap -oG scan.gnmap target
```

## Data Storage

Notes and project data are persisted locally using **IndexedDB** in the browser/Electron renderer process.

- **Database name:** `nmapui`
- **Object stores:** `projects`, `notes`
- **Default location (Electron):**
  - **macOS:** `~/Library/Application Support/nmapui/IndexedDB/`
  - **Linux:** `~/.config/nmapui/IndexedDB/`
  - **Windows:** `%APPDATA%\nmapui\IndexedDB\`
- **Browser (dev mode):** Stored in the browser's IndexedDB under the origin's storage (accessible via DevTools > Application > IndexedDB)

Notes are auto-saved with an 800ms debounce after any change. Each scan file generates a unique project ID based on the filename and scan start time, so notes are associated with specific scans.

## Project Structure

```
src/
  main.tsx                 # React entry point
  App.tsx                  # Root component, IPC wiring, keyboard shortcuts
  vite-env.d.ts            # Type definitions including Electron API
  types/
    nmap.ts                # Complete Nmap data models and type definitions
  parser/
    nmapParser.ts          # XML, greppable, and normal output parsers
    nmapParser.test.ts     # Parser tests (40 tests)
  store/
    appStore.ts            # Application state management with typed store
  utils/
    filterEngine.ts        # Filter, search, and sort engine
    filterEngine.test.ts   # Filter/search/sort tests (38 tests)
    exportEngine.ts        # Multi-format export system
    exportEngine.test.ts   # Export format tests (22 tests)
    storage.ts             # IndexedDB persistence and project file import/export
    storage.test.ts        # Storage/import validation tests (16 tests)
    crypto.ts              # Quantum-safe encryption (AES-256-GCM, ML-KEM-768)
    crypto.test.ts         # Crypto round-trip and validation tests (20 tests)
    sanitize.ts            # DOMPurify HTML sanitization for notes
    sanitize.test.ts       # Sanitization and XSS prevention tests (16 tests)
    helpers.ts             # Shared utilities (stateClass, clipboard, formatting)
    scriptSuggestions.ts   # NSE script suggestion engine with input validation
  components/
    Header.tsx             # App header with theme toggle and actions
    Sidebar.tsx            # Navigation sidebar with keyboard shortcuts guide
    ImportView.tsx         # File import with drag & drop, paste, and size validation
    DashboardView.tsx      # Scan overview dashboard with charts
    HostsView.tsx          # Host table with column picker, context menus, pagination
    HostDetail.tsx         # Host detail with tabbed views
    PortsView.tsx          # Aggregated port view with clickable IPs
    ServicesView.tsx       # Aggregated service view with clickable IPs
    NotesView.tsx          # Notes list with search, filtering, and inline editor
    NoteEditor.tsx         # Rich text note editor (Tiptap) with inline images
    ScriptSuggestions.tsx  # NSE script suggestions per port/service
    MergeDialog.tsx        # Scan merge configuration dialog
    FilterPanel.tsx        # Advanced filter builder (25+ fields, 12 operators)
    ExportDialog.tsx       # Export configuration dialog with encryption options
    DecryptDialog.tsx      # Decryption dialog for encrypted project files
    DiffView.tsx           # Scan comparison/diff view
    ContextMenu.tsx        # Right-click context menu component
    ErrorBoundary.tsx      # React error boundary for crash recovery
  styles/
    global.css             # Dark + light theme styles with CSS variables
  electron/
    main.ts                # Electron main process with native menus and IPC
    preload.ts             # Context bridge for IPC
vitest.config.ts           # Vitest test runner configuration
```

## License

MIT
