// Minimal ambient types for the chrome.* APIs the extension uses.
// Avoids pulling in @types/chrome for a handful of fields.

declare namespace chrome {
  namespace runtime {
    function getURL(path: string): string;
    const id: string | undefined;
    const lastError: { message?: string } | undefined;
    const onInstalled: { addListener(cb: (details: { reason: string }) => void): void };
  }

  namespace storage {
    type AreaName = "sync" | "local" | "session" | "managed";
    interface StorageArea {
      get(keys: string | string[] | null): Promise<Record<string, unknown>>;
      set(items: Record<string, unknown>): Promise<void>;
      remove(keys: string | string[]): Promise<void>;
      clear(): Promise<void>;
    }
    const sync: StorageArea;
    const local: StorageArea;
    const session: StorageArea;
    const onChanged: {
      addListener(cb: (changes: Record<string, { oldValue?: unknown; newValue?: unknown }>, areaName: AreaName) => void): void;
      removeListener(cb: (changes: Record<string, { oldValue?: unknown; newValue?: unknown }>, areaName: AreaName) => void): void;
    };
  }

  namespace tabs {
    interface Tab {
      id?: number;
      url?: string;
      active?: boolean;
      windowId?: number;
      index?: number;
    }
    function query(queryInfo: { active?: boolean; currentWindow?: boolean; windowId?: number }): Promise<Tab[]>;
    function update(tabId: number, updateProperties: { url?: string }): Promise<Tab | undefined>;
    function get(tabId: number): Promise<Tab>;
    function remove(tabId: number): Promise<void>;
  }

  namespace webNavigation {
    interface NavigationDetails {
      tabId: number;
      url: string;
      frameId: number;
      timeStamp: number;
    }
    const onCommitted: {
      addListener(cb: (details: NavigationDetails) => void, filters?: { url: Array<{ schemes?: string[] }> }): void;
    };
    const onBeforeNavigate: {
      addListener(cb: (details: NavigationDetails) => void): void;
    };
  }
}
