/* Playwright acceptance flow without adding or editing any Python test file.
   Needs the repository's existing requirements-dev.txt and Chromium install. */
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const { once } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');

const root = path.resolve(__dirname, '../..');
const python = process.env.PYTHON || 'python';

async function freePort() {
  const server = net.createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  await new Promise((resolve, reject) => server.close((err) => err ? reject(err) : resolve()));
  return port;
}

async function waitForHealth(url, proc) {
  for (let attempt = 0; attempt < 150; attempt++) {
    if (proc.exitCode !== null) throw new Error('temporary app server exited before health check');
    try {
      const response = await fetch(url + '/health');
      if (response.status === 200) return;
    } catch (_) {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('temporary app server did not become healthy');
}

test('paste check gets a verdict immediately; report completes in at most three actions', { timeout: 120_000 }, async () => {
  const port = await freePort();
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'scammap-paste-'));
  const sqlite = path.join(temp, 'paste.sqlite').replace(/\\/g, '/');
  const env = {
    ...process.env,
    DATABASE_URL: 'sqlite:///' + sqlite,
    TRUST_SALT: 'paste-anything-playwright-synthetic',
    ALLOW_RESET: '0',
  };
  const server = spawn(python, ['-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', String(port), '--no-access-log'], {
    cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverOutput = '';
  server.stdout.on('data', (chunk) => { serverOutput += chunk; });
  server.stderr.on('data', (chunk) => { serverOutput += chunk; });
  const url = `http://127.0.0.1:${port}`;
  try {
    await waitForHealth(url, server);
    const script = String.raw`
import json
from playwright.sync_api import sync_playwright

def paste(page, selector, message):
    page.locator(selector).evaluate("""(el, text) => {
      const data = new DataTransfer();
      data.setData('text/plain', text);
      el.dispatchEvent(new ClipboardEvent('paste', {bubbles: true, clipboardData: data}));
    }""", message)

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True)
    page.goto(${JSON.stringify(url)} + '/#check')
    paste(page, '#q', 'Parcel update. Call +91 90000 25001 for details.')
    page.locator('#result .verdict').wait_for(timeout=10000)
    check_verdict = page.locator('#result .verdict').inner_text()
    assert check_verdict == 'No reports', check_verdict

    page.goto(${JSON.stringify(url)} + '/')
    sent = []
    page.on('request', lambda request: sent.append(request.post_data_json)
            if request.method == 'POST' and request.url.endswith('/reports') else None)
    message = 'WhatsApp parcel update: call +91 90000 25002 or open hxxps://parcel[.]example/track'
    paste(page, '#rv', message)
    assert page.input_value('#rv') == '+91 90000 25002'
    assert page.locator('#channels .tile.on').get_attribute('data-ch') == 'SMS or WhatsApp'
    assert page.locator('#kinds .tile.on').get_attribute('data-kind') == 'digital-arrest'
    choices = page.locator('#rfoundchips button')
    assert choices.count() == 2
    choices.nth(1).tap()
    assert page.input_value('#rv') == 'https://parcel.example/track'
    page.locator('#post').tap()
    page.locator('#rdone .verdict').wait_for(timeout=10000)
    assert len(sent) == 1, len(sent)
    body = sent[0]
    assert body['identifier_type'] == 'url', body
    assert body['identifier_value'] == 'https://parcel.example/track', body
    assert body['channel'] == 'SMS or WhatsApp', body
    assert body['scam_type'] == 'digital-arrest', body
    assert body['note'] == '', body
    browser.close()
    print(json.dumps({'check_verdict': check_verdict, 'report_actions': 3, 'note_empty': True}))
`;
    const result = spawnSync(python, ['-c', script], { cwd: root, env, encoding: 'utf8', maxBuffer: 2 * 1024 * 1024 });
    assert.equal(result.status, 0, (result.stdout || '') + (result.stderr || '') + serverOutput);
    assert.match(result.stdout, /"check_verdict": "No reports"/);
    assert.match(result.stdout, /"report_actions": 3/);
    assert.match(result.stdout, /"note_empty": true/);
  } finally {
    server.kill();
    await new Promise((resolve) => server.once('exit', resolve));
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
