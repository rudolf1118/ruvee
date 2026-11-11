/**
 * The part of the Chrome extension API this extension uses, declared by hand: it is the whole
 * browser surface the extension depends on, and a new use has to be added here on purpose.
 */
declare namespace chrome {
  namespace runtime {
    const id: string;
    interface MessageSender {
      id?: string;
      origin?: string;
      url?: string;
      tab?: tabs.Tab;
      frameId?: number;
    }
    interface ContextFilter {
      contextTypes?: ('POPUP' | 'TAB' | 'OFFSCREEN_DOCUMENT' | 'SIDE_PANEL' | 'BACKGROUND')[];
    }
    interface ExtensionContext {
      contextType: string;
      documentUrl?: string;
      tabId: number;
    }
    function getContexts(filter: ContextFilter): Promise<ExtensionContext[]>;
    const onMessage: {
      addListener(
        callback: (
          message: unknown,
          sender: MessageSender,
          sendResponse: (response: unknown) => void,
        ) => boolean | undefined,
      ): void;
    };
    function sendMessage(message: unknown): Promise<unknown>;
    function openOptionsPage(): Promise<void>;
    function getURL(path: string): string;
  }

  namespace storage {
    interface StorageArea {
      get(keys: string | string[]): Promise<Record<string, unknown>>;
      set(items: Record<string, unknown>): Promise<void>;
      remove(keys: string | string[]): Promise<void>;
    }
    const local: StorageArea;
    const session: StorageArea & {
      setAccessLevel(options: { accessLevel: 'TRUSTED_CONTEXTS' }): Promise<void>;
    };
  }

  namespace tabs {
    interface Tab {
      id?: number;
      url?: string;
      active: boolean;
      windowId?: number;
    }
    function get(tabId: number): Promise<Tab>;
    function query(query: { active?: boolean; lastFocusedWindow?: boolean }): Promise<Tab[]>;
  }

  namespace scripting {
    interface InjectionResult<T> {
      frameId: number;
      result?: T;
    }
    function executeScript<A extends unknown[], R>(injection: {
      target: { tabId: number; frameIds?: number[] };
      func: (...args: A) => R;
      args: A;
      world?: 'ISOLATED' | 'MAIN';
    }): Promise<InjectionResult<R>[]>;
    interface RegisteredContentScript {
      id: string;
      js?: string[];
      matches?: string[];
      allFrames?: boolean;
      runAt?: 'document_start' | 'document_end' | 'document_idle';
      world?: 'ISOLATED' | 'MAIN';
      persistAcrossSessions?: boolean;
    }
    function registerContentScripts(scripts: RegisteredContentScript[]): Promise<void>;
    function unregisterContentScripts(filter?: { ids?: string[] }): Promise<void>;
    function getRegisteredContentScripts(filter?: {
      ids?: string[];
    }): Promise<RegisteredContentScript[]>;
  }

  namespace action {
    function openPopup(options?: { windowId?: number }): Promise<void>;
    function setBadgeText(details: { tabId?: number; text: string }): Promise<void>;
    function setBadgeBackgroundColor(details: { tabId?: number; color: string }): Promise<void>;
  }

  namespace permissions {
    function request(permissions: { origins: string[] }): Promise<boolean>;
    function contains(permissions: { origins: string[] }): Promise<boolean>;
    function remove(permissions: { origins: string[] }): Promise<boolean>;
    const onRemoved: {
      addListener(callback: (permissions: { origins?: string[] }) => void): void;
    };
  }

  namespace alarms {
    interface Alarm {
      name: string;
    }
    function create(name: string, info: { periodInMinutes: number }): Promise<void>;
    function get(name: string): Promise<Alarm | undefined>;
    function clear(name: string): Promise<boolean>;
    const onAlarm: { addListener(callback: (alarm: Alarm) => void): void };
  }
}

/** Replaced at build time; true only in the test build (extension-design.md §6). */
declare const __RUVEE_TEST__: boolean;
