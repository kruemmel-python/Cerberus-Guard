import os from 'node:os';
import net from 'node:net';
import { spawn } from 'node:child_process';

const executeCommand = (command, args) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: false,
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', chunk => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', chunk => {
      stderr += chunk.toString();
    });

    child.on('error', reject);
    child.on('close', code => {
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(new Error(stderr || stdout || `Command exited with code ${code}`));
      }
    });
  });

const commandExists = async (command) => {
  const checker = os.platform() === 'win32' ? 'where' : 'which';
  try {
    await executeCommand(checker, [command]);
    return true;
  } catch {
    return false;
  }
};

export class FirewallManager {
  constructor() {
    this.blockedIps = new Set();
    this.platform = os.platform();
    this.linuxProviderPromise = null;
  }

  async getLinuxProvider() {
    if (this.linuxProviderPromise) {
      return this.linuxProviderPromise;
    }

    this.linuxProviderPromise = (async () => {
      if (await commandExists('ufw')) {
        return 'ufw';
      }
      if (await commandExists('iptables')) {
        return 'iptables';
      }
      throw new Error('No supported Linux firewall command found. Install ufw or iptables.');
    })();

    return this.linuxProviderPromise;
  }

  validateIpAddress(ipAddress) {
    if (net.isIP(ipAddress) === 0) {
      throw new Error(`Invalid IP address: ${ipAddress}`);
    }
  }

  async blockIp(ipAddress) {
    this.validateIpAddress(ipAddress);

    if (this.blockedIps.has(ipAddress)) {
      return {
        applied: false,
        provider: this.platform,
        message: 'IP address is already blocked by NetGuard.',
      };
    }

    if (this.platform === 'win32') {
      await executeCommand('netsh', [
        'advfirewall',
        'firewall',
        'add',
        'rule',
        `name=NetGuard Block ${ipAddress}`,
        'dir=in',
        'action=block',
        `remoteip=${ipAddress}`,
      ]);
      this.blockedIps.add(ipAddress);
      return {
        applied: true,
        provider: 'netsh',
        message: `Windows firewall rule created for ${ipAddress}.`,
      };
    }

    if (this.platform === 'linux') {
      const provider = await this.getLinuxProvider();
      if (provider === 'ufw') {
        await executeCommand('ufw', ['deny', 'from', ipAddress]);
      } else {
        await executeCommand('iptables', ['-A', 'INPUT', '-s', ipAddress, '-j', 'DROP']);
      }

      this.blockedIps.add(ipAddress);
      return {
        applied: true,
        provider,
        message: `Linux firewall rule created for ${ipAddress}.`,
      };
    }

    throw new Error(`Firewall integration is not supported on platform: ${this.platform}`);
  }
}
