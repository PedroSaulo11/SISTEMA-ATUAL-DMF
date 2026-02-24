/* eslint-disable no-console */
const { spawnSync } = require('child_process');

function run(command, args, env = process.env) {
  let res;
  if (process.platform === 'win32') {
    const quote = (value) => {
      const v = String(value);
      if (!/[\s"]/g.test(v)) return v;
      return `"${v.replace(/"/g, '\\"')}"`;
    };
    const cmdline = [command, ...args].map(quote).join(' ');
    res = spawnSync('cmd.exe', ['/d', '/s', '/c', cmdline], { stdio: 'inherit', env });
  } else {
    res = spawnSync(command, args, { stdio: 'inherit', env });
  }
  if (res.error) {
    throw res.error;
  }
  if (res.status !== 0) {
    throw new Error(`Command failed: ${command} ${args.join(' ')}`);
  }
}

function has(name) {
  return String(process.env[name] || '').trim().length > 0;
}

function main() {
  run('npm', ['run', 'check:phase3']);

  if (has('BASE_URL')) {
    run('npm', ['run', 'smoke:prod']);
    run('npm', ['run', 'check:audit-fallback:prod']);
  } else {
    console.log('[go-live] SKIP smoke:prod/check:audit-fallback:prod (BASE_URL not set)');
  }

  if (has('BASE_URL') && has('ACCESS_TOKEN')) {
    run('npm', ['run', 'load:prod:multiuser']);
  } else {
    console.log('[go-live] SKIP load:prod:multiuser (BASE_URL/ACCESS_TOKEN not set)');
  }

  console.log('[go-live] PASS');
}

main();
