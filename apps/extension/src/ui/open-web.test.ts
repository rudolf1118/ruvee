import { openWebVault } from './open-web';

const SERVER = 'https://vault.synthetic.example';

function stubTabs(open: chrome.tabs.Tab[] | Error) {
  const api = {
    query: vi.fn(() => (open instanceof Error ? Promise.reject(open) : Promise.resolve(open))),
    create: vi.fn(() => Promise.resolve({ id: 99, active: true })),
    update: vi.fn(() => Promise.resolve({ id: 1, active: true })),
  };
  const windows = { update: vi.fn(() => Promise.resolve()) };
  vi.stubGlobal('chrome', { tabs: api, windows });
  return { tabs: api, windows };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('Open Ruvee', () => {
  it('opens the web vault of the paired server in a new tab', async () => {
    const { tabs } = stubTabs([]);
    await openWebVault(SERVER);
    expect(tabs.query).toHaveBeenCalledWith({ url: `${SERVER}/*` });
    expect(tabs.create).toHaveBeenCalledWith({ url: `${SERVER}/` });
    expect(tabs.update).not.toHaveBeenCalled();
  });

  it('brings a tab already on that server to the front instead', async () => {
    const { tabs, windows } = stubTabs([
      { id: 4, url: `${SERVER}/#vault`, active: false, windowId: 2 },
    ]);
    await openWebVault(SERVER);
    expect(tabs.update).toHaveBeenCalledWith(4, { active: true });
    expect(windows.update).toHaveBeenCalledWith(2, { focused: true });
    expect(tabs.create).not.toHaveBeenCalled();
  });

  it('ignores a tab the query returns for another origin', async () => {
    const { tabs } = stubTabs([
      { id: 4, url: 'https://vault.synthetic.example.evil.example/', active: false },
    ]);
    await openWebVault(SERVER);
    expect(tabs.update).not.toHaveBeenCalled();
    expect(tabs.create).toHaveBeenCalledWith({ url: `${SERVER}/` });
  });

  it('opens a new tab when the tab found has closed before it could be brought forward', async () => {
    const { tabs } = stubTabs([{ id: 4, url: `${SERVER}/`, active: false, windowId: 2 }]);
    tabs.update.mockImplementationOnce(() => Promise.reject(new Error('No tab with id: 4.')));
    await openWebVault(SERVER);
    expect(tabs.create).toHaveBeenCalledWith({ url: `${SERVER}/` });
  });

  it('opens a new tab when the browser refuses the query', async () => {
    const { tabs } = stubTabs(new Error('no permission'));
    await openWebVault(SERVER);
    expect(tabs.create).toHaveBeenCalledWith({ url: `${SERVER}/` });
  });

  it('does nothing without a paired server, or for an address Ruvee would not talk to', async () => {
    const { tabs } = stubTabs([]);
    await openWebVault(null);
    await openWebVault('http://vault.synthetic.example');
    await openWebVault(`${SERVER}/path`);
    await openWebVault('javascript:alert(1)');
    expect(tabs.query).not.toHaveBeenCalled();
    expect(tabs.create).not.toHaveBeenCalled();
  });
});
