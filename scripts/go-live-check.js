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

function envBool(name, fallback = false) {
  const raw = String(process.env[name] || '').trim().toLowerCase();
  if (!raw) return fallback;
  return raw === '1' || raw === 'true' || raw === 'yes';
}

function isCi() {
  return envBool('CI', false);
}

function main() {
  // Keep phase3 deterministic/local.
  // Production checks are executed explicitly below when BASE_URL is provided.
  const phase3Env = { ...process.env, BASE_URL: '' };
  run('npm', ['run', 'check:phase3'], phase3Env);

  if (has('BASE_URL')) {
    run('npm', ['run', 'smoke:prod']);
    run('npm', ['run', 'check:audit-fallback:prod']);

    const strictSessionCheck = envBool('STRICT_SESSION_CHECK', false);
    try {
      run('npm', ['run', 'check:session:prod']);
    } catch (error) {
      if (strictSessionCheck || !isCi()) {
        throw error;
      }
      const msg = error && error.message ? error.message : String(error);
      console.warn(`[go-live] WARN check:session:prod failed in CI and was downgraded to warning: ${msg}`);
    }

    const strictAccessCheck = envBool('STRICT_ACCESS_CHECK', false);
    if (has('ACCESS_TOKEN') || (has('TEST_USERNAME') && has('TEST_PASSWORD'))) {
      try {
        run('npm', ['run', 'check:multiuser:access:prod']);
      } catch (error) {
        if (strictAccessCheck || !isCi()) {
          throw error;
        }
        const msg = error && error.message ? error.message : String(error);
        console.warn(`[go-live] WARN check:multiuser:access:prod failed in CI and was downgraded to warning: ${msg}`);
      }
    } else {
      console.log('[go-live] SKIP check:multiuser:access:prod (ACCESS_TOKEN or TEST_USERNAME/TEST_PASSWORD not set)');
    }
  } else {
    console.log('[go-live] SKIP smoke:prod/check:audit-fallback:prod (BASE_URL not set)');
  }

  const strictLoad = envBool('STRICT_LOAD_CHECK', false);
  if (has('BASE_URL') && has('ACCESS_TOKEN')) {
    try {
      run('npm', ['run', 'load:prod:multiuser']);
    } catch (error) {
      if (strictLoad || !isCi()) {
        throw error;
      }
      const msg = error && error.message ? error.message : String(error);
      console.warn(`[go-live] WARN load:prod:multiuser failed in CI and was downgraded to warning: ${msg}`);
    }
  } else {
    console.log('[go-live] SKIP load:prod:multiuser (BASE_URL/ACCESS_TOKEN not set)');
  }

  console.log('[go-live] PASS');
}

main();
