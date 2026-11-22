// No npm dependencies: npm supplies memorable aliases for the Python project.
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const python = path.join(root, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
const [action = 'help', ...args] = process.argv.slice(2);

function run(command, arguments_) {
  const result = spawnSync(command, arguments_, { cwd: root, stdio: 'inherit' });
  if (result.error) {
    console.error(`Could not start ${command}: ${result.error.message}`);
  }
  return result.status ?? 1;
}

if (action === 'setup') {
  if (!existsSync(python)) {
    const candidates = process.platform === 'win32'
      ? [['py', ['-3']], ['python', []], ['uv', ['run', '--no-project', '--python', '3', 'python']]]
      : [['python3', []], ['python', []]];
    const available = candidates.find(([command, prefix]) => {
      const probe = spawnSync(command, [...prefix, '--version'], { cwd: root, stdio: 'ignore' });
      return !probe.error && probe.status === 0;
    });
    if (!available) {
      console.error('Python was not found. Install Python 3, then run npm run setup again.');
      process.exit(1);
    }
    const [command, prefix] = available;
    if (run(command, [...prefix, '-m', 'venv', '.venv']) !== 0) process.exit(1);
  }
  const pip = spawnSync(python, ['-m', 'pip', '--version'], { cwd: root, stdio: 'ignore' });
  let status;
  if (pip.status === 0) {
    status = run(python, ['-m', 'pip', 'install', '-r', 'requirements.txt']);
  } else if (spawnSync('uv', ['--version'], { cwd: root, stdio: 'ignore' }).status === 0) {
    status = run('uv', ['pip', 'install', '--python', python, '-r', 'requirements.txt']);
  } else {
    status = run(python, ['-m', 'ensurepip', '--upgrade']);
    if (status === 0) status = run(python, ['-m', 'pip', 'install', '-r', 'requirements.txt']);
  }
  if (status === 0) console.log('\nSetup complete. Run npm start, then use a second terminal for the demo.');
  process.exit(status);
}

if (!existsSync(python)) {
  console.error('Run npm run setup first to create the Python environment.');
  process.exit(1);
}
process.exit(run(python, ['-u', 'scripts/demo.py', action, ...args]));
