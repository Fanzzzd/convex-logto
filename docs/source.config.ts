import { defineConfig, defineDocs } from "fumadocs-mdx/config";

export const docs = defineDocs({
  dir: "content/docs",
  docs: {
    postprocess: {
      // Required so getText("processed") works for /llms-full.txt
      includeProcessedMarkdown: true,
    },
  },
});

export default defineConfig();
