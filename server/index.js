import { createApp } from './app.js';
const port = Number(process.env.PORT || 4317);
const app = createApp({ dataPath: process.env.VAULT_PATH });
app.server.listen(port, '127.0.0.1', () => console.log(`agentautofill is ready at http://127.0.0.1:${port}`));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => { await app.close(); process.exit(0); });
