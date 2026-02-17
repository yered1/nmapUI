/// <reference types="vite/client" />

declare global {
  interface Window {
    electronAPI?: {
      onFileOpened: (callback: (data: { content: string; fileName: string }) => void) => (() => void) | void;
      onTriggerExport: (callback: () => void) => (() => void) | void;
      saveFile: (data: { content: string; defaultName: string; filters?: any[] }) => Promise<string | null>;
      openFileDialog: () => Promise<{ content: string; fileName: string } | null>;
    };
  }
}

export {};
