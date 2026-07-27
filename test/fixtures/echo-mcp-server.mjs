/**
 * A minimal MCP server over stdio, for testing the gateway's stdio binding
 * against a real child process rather than an in-process fake.
 *
 * Deliberately hand-written and dependency-free: the point is to exercise the
 * wire format, so anything that abstracts the wire format away would defeat it.
 *
 * stdout carries protocol only. Nothing here may print.
 */

let buffer = '';

process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  let nl = buffer.indexOf('\n');
  while (nl !== -1) {
    const line = buffer.slice(0, nl).replace(/\r$/, '');
    buffer = buffer.slice(nl + 1);
    if (line.trim() !== '') handle(line);
    nl = buffer.indexOf('\n');
  }
});

function reply(id, body) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id, ...body })}\n`);
}

function handle(line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  if (msg.id === undefined) return; // notification

  switch (msg.method) {
    case 'initialize':
      return reply(msg.id, {
        result: {
          protocolVersion: '2025-06-18',
          capabilities: { tools: {} },
          serverInfo: { name: 'echo-fixture', version: '1' },
        },
      });

    case 'tools/list':
      return reply(msg.id, {
        result: {
          tools: [
            { name: 'echo', description: 'Returns its arguments' },
            { name: 'boom', description: 'Always fails' },
            { name: 'unpriced', description: 'Has no policy in the gateway' },
          ],
        },
      });

    case 'tools/call': {
      const { name, arguments: args } = msg.params ?? {};
      if (name === 'boom') {
        return reply(msg.id, {
          result: { isError: true, content: [{ type: 'text', text: 'boom' }] },
        });
      }
      return reply(msg.id, {
        result: { content: [{ type: 'text', text: JSON.stringify(args ?? null) }] },
      });
    }

    default:
      return reply(msg.id, { error: { code: -32601, message: `no method ${msg.method}` } });
  }
}
