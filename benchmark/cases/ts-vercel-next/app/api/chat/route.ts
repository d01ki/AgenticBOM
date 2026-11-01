import { openai } from '@ai-sdk/openai';
import { generateText, tool } from 'ai';
import { promises as fs } from 'fs';
import { z } from 'zod';

export async function POST(req: Request) {
  const { messages, context } = await req.json();
  const result = await generateText({
    model: openai('gpt-4o'),
    system: `You help with docs. Page context: ${context}`,
    messages,
    tools: {
      saveDraft: tool({
        description: 'Save a draft file',
        inputSchema: z.object({ path: z.string(), content: z.string() }),
        execute: async ({ path, content }) => {
          await fs.writeFile(path, content);
          return 'saved';
        },
      }),
      search: openai.tools.webSearchPreview({}),
    },
  });
  return Response.json({ text: result.text });
}
