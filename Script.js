// Clash Verge 全局扩展脚本 (Global Script)
// 适配：极简纯净模式
// 1. 包含「下载专用」和「免费」等所有节点（共 46 个节点全量参与测速）
// 2. 移除所有冗余的细分策略组（爱奇艺、动画疯、Steam、Cloudflare、OneDrive 等全清理）
// 3. 仅保留单个「⚡ 30s自动最优」策略组，所有规则精准重定向（国外走自动最优，国内走直连，广告走拦截）

function main(config) {
  // 1. 直连规则保障（内网与常用服务直连）
  if (!config.rules) {
    config.rules = [];
  }
  config.rules.unshift(
    // 校园网内部系统直连
    'DOMAIN-SUFFIX,yungu.org,DIRECT',
    // 办公通信直连
    'DOMAIN-SUFFIX,dingtalk.com,DIRECT',
    'DOMAIN-SUFFIX,dingtalkapps.com,DIRECT',
    'DOMAIN-KEYWORD,dingtalk,DIRECT',
    'DOMAIN-SUFFIX,laiwang.com,DIRECT',
    // 小米/米柚生态服务直连
    'DOMAIN-SUFFIX,miui.com,DIRECT',
    'DOMAIN-SUFFIX,xiaomi.com,DIRECT',
    'DOMAIN-KEYWORD,xiaomi,DIRECT',
    'DOMAIN-KEYWORD,miui,DIRECT'
  );

  // 2. 检查策略组是否存在
  if (!config['proxy-groups']) {
    return config;
  }

  // 3. 提取所有有效节点（保留「下载专用」和「免费」，仅过滤通知提示类非代理节点）
  const skipKeywords = ['剩余', '流量', '过期', '到期', '官网', '重置', '通知'];
  const proxyNames = (config.proxies || [])
    .map(p => p.name)
    .filter(name => !skipKeywords.some(kw => name.includes(kw)));

  if (proxyNames.length === 0) {
    return config;
  }

  // 4. 清理所有冗余策略组，仅保留「⚡ 30s自动最优」
  const autoGroupName = '⚡ 30s自动最优';
  config['proxy-groups'] = [
    {
      name: autoGroupName,
      type: 'url-test',
      url: 'https://www.google.com',
      interval: 30,     // 每 30 秒自动探测并切换到延迟最低的节点
      tolerance: 50,    // 50ms 容差，防止频繁跳变
      lazy: false,      // 主动保活测速
      proxies: proxyNames
    }
  ];

  // 5. 重定向既有规则：
  // - 广告类 -> REJECT
  // - 国内/直连/流媒体国内版/Steam登录等 -> DIRECT
  // - 其余所有外网/未匹配流量 -> ⚡ 30s自动最优
  const directKeywords = ['国内', '直连', 'direct', '爱奇艺', '学术', 'steam 登录'];
  const rejectKeywords = ['广告', 'reject'];

  config.rules = config.rules.map(rule => {
    const parts = rule.split(',');
    if (parts.length >= 3) {
      const target = parts[2].trim().toLowerCase();
      if (rejectKeywords.some(k => target.includes(k))) {
        parts[2] = 'REJECT';
      } else if (directKeywords.some(k => target.includes(k))) {
        parts[2] = 'DIRECT';
      } else if (parts[2].trim() !== 'DIRECT' && parts[2].trim() !== 'REJECT') {
        parts[2] = autoGroupName;
      }
      return parts.join(',');
    }
    return rule;
  });

  return config;
}
