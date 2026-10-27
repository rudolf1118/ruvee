// The phone's network to the test server, under the test's control. The phone connects to
// 127.0.0.1:<webPort> on the device; `adb reverse` carries that to this proxy on the host, which
// forwards to the web server (and its /api proxy). Removing the reverse rule alone is not "offline":
// connections already open (OkHttp keeps them alive) would still work. `cut()` destroys every open
// connection and refuses new ones until `restore()`.

import { createConnection, createServer, type Socket } from 'node:net';

export interface PhoneNetwork {
  readonly port: number;
  cut(): void;
  restore(): void;
  close(): Promise<void>;
}

export async function phoneNetwork(params: {
  listenPort: number;
  targetPort: number;
  /** Receives one line per connection event, for diagnosing the tests themselves. */
  trace?: (line: string) => void;
}): Promise<PhoneNetwork> {
  let up = true;
  const open = new Set<Socket>();
  const trace = (event: string) => {
    if (params.trace) params.trace(`${new Date().toISOString()} ${event}`);
  };
  const server = createServer((client) => {
    if (!up) {
      trace('refused while cut');
      client.destroy();
      return;
    }
    trace('accepted');
    const upstream = createConnection({ host: '127.0.0.1', port: params.targetPort });
    open.add(client);
    open.add(upstream);
    const drop = () => {
      client.destroy();
      upstream.destroy();
      open.delete(client);
      open.delete(upstream);
    };
    client.on('error', drop).on('close', drop);
    upstream.on('error', drop).on('close', drop);
    client.pipe(upstream);
    upstream.pipe(client);
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(params.listenPort, '127.0.0.1', resolve);
  });
  return {
    port: params.listenPort,
    cut() {
      trace(`cut (${String(open.size)} open sockets)`);
      up = false;
      for (const socket of open) socket.destroy();
      open.clear();
    },
    restore() {
      trace('restored');
      up = true;
    },
    close: () =>
      new Promise<void>((resolve) => {
        for (const socket of open) socket.destroy();
        server.close(() => resolve());
      }),
  };
}
