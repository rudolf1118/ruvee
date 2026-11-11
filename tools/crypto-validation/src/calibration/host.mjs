// Read-only description of the machine running the benchmark. Changes no settings.

import { execFileSync } from 'node:child_process';
import os from 'node:os';

const run = (cmd, args) => {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', timeout: 5000 }).trim();
  } catch {
    return null;
  }
};

export function hostInfo() {
  const cpus = os.cpus();
  const info = {
    platform: `${os.platform()} ${os.arch()}`,
    osType: os.type(),
    osRelease: os.release(),
    osVersion: os.version(),
    cpuModel: cpus[0]?.model ?? null,
    logicalCpus: cpus.length,
    totalMemoryBytes: os.totalmem(),
    freeMemoryBytes: os.freemem(),
    loadAverage1m5m15m: os.loadavg().map((x) => Math.round(x * 100) / 100),
  };
  if (os.platform() === 'darwin') {
    const sysctl = (k) => run('sysctl', ['-n', k]);
    Object.assign(info, {
      hardwareModel: sysctl('hw.model'),
      cpuBrand: sysctl('machdep.cpu.brand_string'),
      performanceCores: Number(sysctl('hw.perflevel0.physicalcpu')) || null,
      efficiencyCores: Number(sysctl('hw.perflevel1.physicalcpu')) || null,
      macosVersion: run('sw_vers', ['-productVersion']),
      macosBuild: run('sw_vers', ['-buildVersion']),
      powerSource: /'(.+?)'/.exec(run('pmset', ['-g', 'batt']) ?? '')?.[1] ?? null,
      lowPowerMode: /lowpowermode\s+(\d)/.exec(run('pmset', ['-g']) ?? '')?.[1] === '1',
      thermal: run('pmset', ['-g', 'therm']),
    });
  } else if (os.platform() === 'linux') {
    info.cpuBrand = /model name\s*:\s*(.+)/.exec(run('cat', ['/proc/cpuinfo']) ?? '')?.[1] ?? null;
  }
  return info;
}
