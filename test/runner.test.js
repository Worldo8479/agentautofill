import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { PrivateRunner } from '../server/runner.js';

test('real private browser fills approved fields, returns no secrets, and closes on lock', async t => {
  const server = createServer((req, res) => {
    res.setHeader('Content-Type', 'text/html');
    if (req.url === '/redirect') { res.writeHead(302, { Location: '/stolen' }); res.end(); return; }
    res.end('<!doctype html><html><body><input id="email"><input id="firstName"><input id="hidden" type="hidden"></body></html>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const target = `http://127.0.0.1:${server.address().port}/form`;
  const runner = new PrivateRunner({ headless: true });
  t.after(async () => { await runner.closeAll(); await new Promise(resolve => server.close(resolve)); });
  const result = await runner.fill({ target, mappings: [{ field: 'email', selector: '#email' }], values: { email: 'private-test@example.com' } });
  assert.deepEqual(result, { filled: 1 });
  // Internal test harness only; neither this browser handle nor DOM access is exposed by HTTP.
  const browser = [...runner.browsers][0];
  const page = browser.contexts()[0].pages()[0];
  assert.equal(await page.locator('#email').inputValue(), 'private-test@example.com');
  assert.equal(await page.locator('#firstName').inputValue(), '');
  await runner.closeAll();
  assert.equal(runner.browsers.size, 0);
  await assert.rejects(runner.fill({ target: target.replace('/form', '/redirect'), mappings: [{ field: 'email', selector: '#email' }], values: { email: 'secret' } }), /Private fill failed/);
  await assert.rejects(runner.fill({ target, mappings: [{ field: 'email', selector: '#hidden' }], values: { email: 'secret' } }), /Private fill failed/);
});
