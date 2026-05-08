
import type { UserConfig, ConfigEnv } from 'vite';
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from "path";
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'
//https://github.com/element-plus/unplugin-element-plus/blob/HEAD/README.zh-CN.md
import ElementPlus from 'unplugin-element-plus/vite'
export default defineConfig(({ command, mode }: ConfigEnv): UserConfig => {

  // const env = loadEnv(mode, process.cwd(), '')
  console.log(command, mode);
  return {
    plugins: [vue(),
    AutoImport({
      resolvers: [ElementPlusResolver()],
    }),
    Components({
      resolvers: [ElementPlusResolver()],
    }),
    ElementPlus({
      // useSource: true
    })
    ],
    publicDir: "public",
    base: "./",
    server: {
      host: '0.0.0.0',
      port: 8112,
      open: false,
      strictPort: false,
      proxy: {
        // Wazuh API 代理
        '/wazuh-api': {
          target: 'https://192.168.109.138:55000', 
          changeOrigin: true,
          secure: false, // 必须为 false，因为 Wazuh 使用自签名证书
          rewrite: (path) => path.replace(/^\/wazuh-api/, '')
        },
        // Wazuh Indexer 代理
        '/wazuh-indexer': {
          target: 'https://192.168.109.138:9200',
          changeOrigin: true,
          secure: false,
          rewrite: (path) => path.replace(/^\/wazuh-indexer/, '')
        },
        // AI 智能体 Agent 代理
        '/agent-api': {
          target: 'http://127.0.0.1:2024', 
          changeOrigin: true,
          secure: false,
          rewrite: (path) => path.replace(/^\/agent-api/, '')
        }
      }
    },
    resolve: {
      alias: {
        "@": resolve(__dirname, "./src"),
        "components": resolve(__dirname, "./src/components"),
        "api": resolve(__dirname, "./src/api"),
      },
    },
    css: {
      // css预处理器
      preprocessorOptions: {
        scss: {
          // charset: false,
          additionalData: `@use "./src/assets/css/variable.scss" as *;`,
        },
      },
    },
    build: {
      outDir: 'dist',
    },
  }

})