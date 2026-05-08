
import type { UserConfig, ConfigEnv } from 'vite';
import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from "path";
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'
//https://github.com/element-plus/unplugin-element-plus/blob/HEAD/README.zh-CN.md
import ElementPlus from 'unplugin-element-plus/vite'
export default defineConfig(({ command, mode }: ConfigEnv): UserConfig => {
  const env = loadEnv(mode, __dirname, '')
  const wazuhProtocol = env.VITE_WAZUH_SERVER_API_PROTOCOL || 'https'
  const wazuhHost = env.VITE_WAZUH_SERVER_API_HOST || '127.0.0.1'
  const wazuhPort = env.VITE_WAZUH_SERVER_API_PORT || '55000'
  const wazuhIndexerPort = env.VITE_WAZUH_INDEXER_PORT || '9200'
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
          target: `${wazuhProtocol}://${wazuhHost}:${wazuhPort}`,
          changeOrigin: true,
          secure: false, // 必须为 false，因为 Wazuh 使用自签名证书
          rewrite: (path) => path.replace(/^\/wazuh-api/, '')
        },
        // Wazuh Indexer 代理
        '/wazuh-indexer': {
          target: `${wazuhProtocol}://${wazuhHost}:${wazuhIndexerPort}`,
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
