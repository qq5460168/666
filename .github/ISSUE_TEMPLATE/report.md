---
name: "🚩 规则提交提案"
about: 仅接受符合格式规范的拦截/白名单规则提交
title: "[规则提交] 简要描述规则用途"
labels: "规则提案,待审核"
assignees: project-maintainer
---

<!-- 提交前请完成以下检查 -->
- [ ] 已在最新版 AdGuard/uBlock Origin 中验证规则有效性
- [ ] 已通过 `Ctrl+F` 搜索确认无重复规则
- [ ] 已阅读 [贡献指南](https://github.com/yourrepo/CONTRIBUTING.md)
- [ ] 知晓无效/格式错误提交将被标记为 spam

### Ⅰ. 规则基本信息
**规则作用描述**：(20字内简要说明)  
`示例：拦截 example.com 的弹窗广告 / 解除 example.net 的误拦截`

**规则类型**：(单选)
- [ ] 拦截规则 (`||example.com^`)
- [ ] 白名单规则 (`@@||example.com^`)
- [ ] 高级规则 (`$domain=...`)

**影响范围**：(多选)
- [ ] 网页端 (PC/Mobile)
- [ ] Android 应用
- [ ] iOS 应用
- [ ] 桌面客户端
- [ ] 浏览器扩展
- [ ] DNS 级别

### Ⅱ. 问题详情
**触发场景描述**：  
`示例：访问 https://example.com/article?id=123 时，页面底部出现浮动赌博广告`

**重现步骤**：
1. 访问目标地址：`https://example.com/...`
2. 执行操作：`点击登录按钮/滚动到页面底部`
3. 触发现象：`等待5秒后弹出全屏广告`
4. 受影响元素：`视频播放器/登录框`

**技术细节**：
```plaintext
受影响域名：ads.example.com
元素特征：<div id="popup-ad">
触发方式：DOM加载完成后执行
