import { chromium } from 'playwright';
import { existsSync } from 'node:fs';

export class PrivateRunner {
  constructor({ headless = false } = {}) { this.headless = headless; this.browsers = new Set(); this.generation = 0; this.pending = 0; }
  async fill({ target, mappings, values, resolvedAddress }) {
    if (this.browsers.size + this.pending >= 5) throw new Error('Too many private windows.');
    const generation = this.generation;
    const options = { headless: this.headless };
    if (resolvedAddress) {
      const address = resolvedAddress.includes(':') ? `[${resolvedAddress}]` : resolvedAddress;
      options.args = [`--host-resolver-rules=MAP ${new URL(target).hostname} ${address}`, '--no-proxy-server'];
    }
    if (process.env.BROWSER_CHANNEL) options.channel = process.env.BROWSER_CHANNEL;
    else if (existsSync('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')) options.channel = 'chrome';
    this.pending++;
    let browser;
    try { browser = await chromium.launch(options); } finally { this.pending--; }
    this.browsers.add(browser);
    browser.on('disconnected', () => this.browsers.delete(browser));
    try {
      if (generation !== this.generation) throw new Error('Vault was locked during launch.');
      const context = await browser.newContext({ serviceWorkers: 'block', acceptDownloads: false });
      // No CDP server, screenshots, DOM reads, logs or cookies are exposed to agents.
      const allowed = new URL(target);
      await context.route('**/*', async route => {
        const url = new URL(route.request().url());
        const request = route.request();
        const sameOrigin = url.origin === allowed.origin;
        const exactPage = url.pathname === allowed.pathname && url.search === allowed.search;
        // The user may manually submit later, but automatic navigation never changes destination.
        const permitted = sameOrigin && (!request.isNavigationRequest() || exactPage);
        await (permitted ? route.continue() : route.abort());
      });
      await context.routeWebSocket('**/*', socket => socket.close());
      const page = await context.newPage();
      context.on('page', other => { if (other !== page) void other.close(); });
      page.on('dialog', dialog => void dialog.dismiss());
      page.setDefaultTimeout(8000);
      await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 25000 });
      if (page.url() !== allowed.href) throw new Error('The target redirected.');
      // Check every destination before inserting any secret.
      for (const { selector } of mappings) {
        const input = page.locator(selector);
        if (await input.count() !== 1 || !await input.isVisible() || !await input.isEditable()) throw new Error('Invalid destination.');
        const valid = await input.evaluate(el => ['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName) && !['hidden', 'file', 'submit', 'button'].includes(el.type));
        if (!valid) throw new Error('Invalid destination.');
      }
      for (const { field, selector } of mappings) {
        if (page.url() !== allowed.href) throw new Error('The target changed.');
        const input = page.locator(selector);
        if (await input.evaluate(el => el.tagName === 'SELECT')) await input.selectOption(values[field]);
        else await input.fill(values[field]);
      }
      // Keep the private window available to the owner, then close automatically.
      const timer = setTimeout(() => void browser.close(), 15 * 60 * 1000);
      timer.unref();
      browser.on('disconnected', () => clearTimeout(timer));
      return { filled: mappings.length };
    } catch {
      await browser.close();
      // Never propagate Playwright errors: these can contain values or page content.
      throw new Error('Private fill failed. Check the destination and field selectors, then create a new pass.');
    }
  }
  async closeAll() { this.generation++; await Promise.allSettled([...this.browsers].map(browser => browser.close())); }
}
