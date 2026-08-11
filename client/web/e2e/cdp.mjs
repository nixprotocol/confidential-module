// node cdp.mjs <url> <js-file>
const [,, url, jsFile] = process.argv;
const fs = await import('node:fs/promises');
const targets = await (await fetch('http://localhost:9222/json')).json();
const page = targets.find(t => t.type === 'page');
const ws = new WebSocket(page.webSocketDebuggerUrl);
let id = 0; const pending = new Map();
ws.addEventListener('message', e => {
  const m = JSON.parse(e.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
});
const send = (method, params={}) => new Promise(res => {
  const i = ++id; pending.set(i, res);
  ws.send(JSON.stringify({ id: i, method, params }));
});
await new Promise(r => ws.addEventListener('open', r));
await send('Runtime.enable'); await send('Page.enable');
await send('Page.navigate', { url });
for (let i = 0; i < 120; i++) {
  const r = await send('Runtime.evaluate', { expression: 'document.readyState', returnByValue: true });
  if (r.result?.result?.value === 'complete') break;
  await new Promise(r => setTimeout(r, 500));
}
const r = await send('Runtime.evaluate', {
  expression: await fs.readFile(jsFile, 'utf8'),
  awaitPromise: true, returnByValue: true, timeout: 600000 });
if (r.result?.exceptionDetails || r.result?.result?.subtype === 'error') {
  console.error(JSON.stringify(r.result, null, 2)); process.exit(1);
}
console.log(JSON.stringify(r.result?.result?.value, null, 2));
process.exit(0);
