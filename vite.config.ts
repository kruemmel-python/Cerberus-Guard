import path from 'path';
import { defineConfig, loadEnv } from 'vite';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '');
  const llmEnv = {
    GEMINI_API_KEY: env.GEMINI_API_KEY || env.VITE_GEMINI_API_KEY || '',
    OPENAI_API_KEY: env.OPENAI_API_KEY || env.VITE_OPENAI_API_KEY || '',
    ANTHROPIC_API_KEY: env.ANTHROPIC_API_KEY || env.VITE_ANTHROPIC_API_KEY || '',
    OPENROUTER_API_KEY: env.OPENROUTER_API_KEY || env.VITE_OPENROUTER_API_KEY || '',
    GROQ_API_KEY: env.GROQ_API_KEY || env.VITE_GROQ_API_KEY || '',
    MISTRAL_API_KEY: env.MISTRAL_API_KEY || env.VITE_MISTRAL_API_KEY || '',
    DEEPSEEK_API_KEY: env.DEEPSEEK_API_KEY || env.VITE_DEEPSEEK_API_KEY || '',
    XAI_API_KEY: env.XAI_API_KEY || env.VITE_XAI_API_KEY || '',
  };

  return {
    define: {
      __LLM_ENV__: JSON.stringify(llmEnv),
      'process.env.API_KEY': JSON.stringify(llmEnv.GEMINI_API_KEY),
      'process.env.GEMINI_API_KEY': JSON.stringify(llmEnv.GEMINI_API_KEY),
    },
    build: {
      rollupOptions: {
        output: {
          manualChunks: {
            react: ['react', 'react-dom'],
            charts: ['recharts'],
            llm: ['@google/genai'],
            storage: ['dexie'],
          },
        },
      },
    },
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
  };
});
