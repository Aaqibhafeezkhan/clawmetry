"""Owner-side queue consumer. Uses local gh auth; never executes candidate code."""
import argparse
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import time

SOURCE = 'vivekchand/clawmetry-pro'
DESTINATION = 'vivekchand/clawmetry'
CONTEXT = 'OSS runtime compatibility'
PRO_WORKFLOW = 'oss-runtime-compatibility.yml'
OSS_WORKFLOW = 'runtime-compatibility.yml'
ROOT = Path.home() / 'Library/Application Support/ClawMetryCI'
LABEL = 'com.clawmetry.runtime-dispatch'
TRUSTED = {'github-actions[bot]', 'vivekchand'}
MARKER = re.compile(r'CM_OSS_(REQUEST|QUEUED):(?:(?P<nonce>[a-f0-9]{16}):)?(?P<base>[a-f0-9]{40}|full):(?P<pr>[0-9]{1,10})\Z')


def api(path, body=None, query=None):
    command = ['gh', 'api', '--method', 'POST' if body else 'GET', path]
    if query:
        command += ['--paginate', '--slurp']
        for key, value in query.items():
            command += ['-f', f'{key}={value}']
    if body:
        command += ['--input', '-']
    result = subprocess.run(command, input=json.dumps(body) if body else None,
                            text=True, capture_output=True, timeout=90, check=False)
    if result.returncode:
        # gh stderr may contain private response data; keep diagnostics generic.
        raise RuntimeError('GitHub API request failed')
    return json.loads(result.stdout) if result.stdout.strip() else {}


def runs(repository, workflow, since, event=None):
    query = {'per_page': '100', 'created': '>=' + since}
    if event:
        query['event'] = event
    pages = api(f'repos/{repository}/actions/workflows/{workflow}/runs', query=query)
    return [run for page in pages for run in page['workflow_runs']]


def latest_status(sha):
    statuses = api(f'repos/{SOURCE}/commits/{sha}/status')['statuses']
    return next((s for s in statuses if s['context'] == CONTEXT), None)


def request_from(run, status):
    if (run.get('head_repository', {}).get('full_name') != SOURCE
            or run.get('event') not in {'push', 'pull_request', 'workflow_dispatch'}
            or run.get('conclusion') != 'success'
            or not re.fullmatch('[a-f0-9]{40}', run.get('head_sha', ''))):
        return None
    if (not status or status.get('state') != 'pending'
            or status.get('creator', {}).get('login') not in TRUSTED):
        return None
    match = MARKER.fullmatch(status.get('description') or '')
    if not match or (match[1] == 'QUEUED') != bool(match['nonce']):
        return None
    nonce = match['nonce'] or hashlib.sha256(str(status['id']).encode()).hexdigest()[:16]
    return {'sha': run['head_sha'], 'base': match['base'], 'pr': int(match['pr']),
            'nonce': nonce, 'request_description': status['description'], 'request_status_id': status['id'],
            'attempts': 0, 'last_dispatch': 0, 'claimed': match[1] == 'QUEUED'}


def title(record):
    return f"Runtime compatibility {record['sha']} [{record['nonce']}]"


def queued_marker(record):
    return f"CM_OSS_QUEUED:{record['nonce']}:{record['base']}:{record['pr']}"


def post_status(record, state, description, run=None):
    body = {'state': state, 'context': CONTEXT, 'description': description,
            'target_url': f'https://github.com/{DESTINATION}/actions/' +
                          (f"runs/{int(run['id'])}" if run else f'workflows/{OSS_WORKFLOW}')}
    api(f"repos/{SOURCE}/statuses/{record['sha']}", body=body)


def save(path, state):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as stream:
        os.chmod(temporary, 0o600)
        json.dump(state, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def reconcile(record, receipts, now, persist):
    if record.get('done'):
        return
    status = latest_status(record['sha'])
    expected = queued_marker(record) if record['claimed'] else record['request_description']
    if (not status or status.get('state') != 'pending'
            or status.get('creator', {}).get('login') not in TRUSTED
            or status.get('description') != expected
            or (not record['claimed'] and status['id'] != record['request_status_id'])):
        record['done'] = 'superseded'
        persist()
        return
    receipt = next((r for r in receipts if r.get('display_title') == title(record)), None)
    if receipt:
        record['run_id'] = receipt['id']
        if receipt['status'] == 'completed':
            state = 'success' if receipt['conclusion'] == 'success' else 'failure'
            post_status(record, state, 'Cross-platform runtime fixture and adapter validation', receipt)
            record['done'] = state
            persist()
        return
    if not record['claimed']:
        post_status(record, 'pending', queued_marker(record))
        record['claimed'] = True
        persist()
    # Recover an uncertain POST by looking for its nonce-bearing receipt before retrying.
    if now - record['last_dispatch'] < 300:
        return
    if record['attempts'] >= 3:
        post_status(record, 'failure', 'No OSS workflow receipt after dispatch retries')
        record['done'] = 'failure'
        persist()
        return
    record['attempts'] += 1
    record['last_dispatch'] = now
    persist()  # A crash or timeout after delivery must not cause an immediate duplicate.
    api(f'repos/{DESTINATION}/dispatches', body={
        'event_type': 'pro-runtime-compatibility', 'client_payload': {
            'source_repository': SOURCE, 'pro_sha': record['sha'],
            'base_sha': '' if record['base'] == 'full' else record['base'],
            'pull_request': record['pr'], 'request_id': record['nonce'], 'local_bridge': True}})


def once(path):
    now = time.time()
    state = json.loads(path.read_text()) if path.exists() else {'requests': {}, 'seen': []}
    persist = lambda: save(path, state)
    since = datetime.fromtimestamp(state.get('last_poll', now - 30 * 86400), timezone.utc)
    since = (since - timedelta(days=1)).strftime('%Y-%m-%d')
    seen = set(state['seen'])
    for run in runs(SOURCE, PRO_WORKFLOW, since):
        if run['id'] in seen or run['status'] != 'completed':
            continue
        candidate = run.get('head_sha', '')
        if (run.get('head_repository', {}).get('full_name') != SOURCE
                or run.get('conclusion') != 'success'
                or run.get('event') not in {'push', 'pull_request', 'workflow_dispatch'}
                or not re.fullmatch('[a-f0-9]{40}', candidate)):
            seen.add(run['id'])
            continue
        request = request_from(run, latest_status(candidate))
        if request:
            state['requests'].setdefault(request['nonce'], request)
        seen.add(run['id'])
    state['seen'] = sorted(seen)[-10000:]
    state['last_poll'] = now
    persist()
    pending = [r for r in state['requests'].values() if not r.get('done')]
    if pending:
        oldest = min(r['last_dispatch'] or now for r in pending) - 86400
        receipts = runs(DESTINATION, OSS_WORKFLOW,
                        datetime.fromtimestamp(oldest, timezone.utc).strftime('%Y-%m-%d'),
                        event='repository_dispatch')
        for record in pending:
            reconcile(record, receipts, now, persist)
    print(f"Runtime bridge: {len(pending)} pending request(s) reconciled.")


def install():
    if sys.platform != 'darwin':
        raise RuntimeError('LaunchAgent installation requires macOS')
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(ROOT, 0o700)
    installed = ROOT / 'local_runtime_dispatch.py'
    shutil.copyfile(__file__, installed)
    os.chmod(installed, 0o700)
    destination = Path.home() / f'Library/LaunchAgents/{LABEL}.plist'
    destination.parent.mkdir(parents=True, exist_ok=True)
    definition = {'Label': LABEL, 'ProgramArguments': [sys.executable, str(installed)],
                  'RunAtLoad': True, 'StartInterval': 60, 'ProcessType': 'Background',
                  'EnvironmentVariables': {'PATH': '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin'},
                  'StandardOutPath': str(ROOT / 'bridge.log'), 'StandardErrorPath': str(ROOT / 'bridge-error.log')}
    destination.write_bytes(plistlib.dumps(definition))
    os.chmod(destination, 0o600)
    subprocess.run(['launchctl', 'bootout', f'gui/{os.getuid()}/{LABEL}'], capture_output=True, check=False)
    subprocess.run(['launchctl', 'bootstrap', f'gui/{os.getuid()}', str(destination)], check=True)
    print('Installed local runtime dispatch bridge. GitHub credentials remain in local gh authentication.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--install', action='store_true')
    args = parser.parse_args()
    try:
        if args.install:
            install()
        else:
            ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
            with (ROOT / 'bridge.lock').open('w') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                once(ROOT / 'state.json')
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f'Runtime bridge stopped safely ({type(exc).__name__}).', file=sys.stderr)
        raise SystemExit(1)
