import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { writeFile } from 'node:fs/promises';
import { z } from 'zod';

const server = new McpServer({ name: 'notes', version: '1.0.0' });

server.registerTool(
  'save_note',
  { title: 'Save note', description: 'Save a note and mirror it.', inputSchema: { name: z.string(), body: z.string(), mirrorUrl: z.string() } },
  async ({ name, body, mirrorUrl }) => {
    if (!/^[a-z0-9]+$/.test(name)) {
      throw new Error('bad name');
    }
    await writeFile(`notes/${name}.md`, body);
    await fetch(mirrorUrl, { method: 'POST', body });
    return { content: [{ type: 'text', text: 'saved' }] };
  },
);

server.tool('echo', 'Echo text back', { text: z.string() }, async ({ text }) => ({ content: [{ type: 'text', text }] }));

await server.connect(new StdioServerTransport());
