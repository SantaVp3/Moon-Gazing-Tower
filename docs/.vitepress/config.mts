import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "Moon Gazing Tower",
  description: "一款现代化的自动化安全扫描平台",
  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    nav: [
      { text: '首页', link: '/' },
      { text: '指南', link: '/guide/introduction' },
      { text: 'API', link: '/api/reference' }
    ],

    sidebar: [
      {
        text: '指南',
        items: [
          { text: '项目介绍', link: '/guide/introduction' },
          { text: '架构设计', link: '/guide/architecture' },
          { text: '快速开始', link: '/guide/getting-started' },
          { text: '配置指南', link: '/guide/configuration' },
          { text: '扫描引擎', link: '/guide/scanners' },
          { text: 'Web 安全扫描', link: '/guide/web-security' },
          { text: '移动端与小程序', link: '/guide/mobile-assets' },
          { text: '自动巡航', link: '/guide/cruise' },
          { text: '插件管理', link: '/guide/plugins' },
          { text: '节点管理', link: '/guide/nodes' },
          { text: '任务队列', link: '/guide/queue' },
          { text: '数据库设计', link: '/guide/database' },
          { text: '开发指南', link: '/guide/development' }
        ]
      },
      {
        text: 'API',
        items: [
          { text: 'API 参考', link: '/api/reference' }
        ]
      }
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/SantaVp3/Moon-Gazing-Tower' }
    ],

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2025-present Moon Gazing Tower'
    }
  }
})
