// Clash Verge 全局扩展脚本 (Global Script)
// 1. 保留原有全部策略组，避免 rules not found 错误
// 2. 所有 46 个节点（包含「下载专用」和「免费」节点）全量加入「⚡ 30s自动最优」
// 3. 其它策略组不进行单独测速，直接把「⚡ 30s自动最优」置顶作为首选走它
// 4. 保留校园网系统（yungu.org）、钉钉、小米等国内直连规则

function main(config) {
  // 1. 直连规则保障（内网系统与常用国内服务不走外网代理）
  if (!config.rules) {
    config.rules = [];
  }
  config.rules.unshift(
    'DOMAIN-SUFFIX,yungu.org,DIRECT',
    'DOMAIN-SUFFIX,dingtalk.com,DIRECT',
    'DOMAIN-SUFFIX,dingtalkapps.com,DIRECT',
    'DOMAIN-KEYWORD,dingtalk,DIRECT',
    'DOMAIN-SUFFIX,laiwang.com,DIRECT',
    'DOMAIN-SUFFIX,miui.com,DIRECT',
    'DOMAIN-SUFFIX,xiaomi.com,DIRECT',
    'DOMAIN-KEYWORD,xiaomi,DIRECT',
    'DOMAIN-KEYWORD,miui,DIRECT'
  );

  // 2. 检查策略组
  if (!config['proxy-groups']) {
    return config;
  }

  // 3. 提取所有有效节点（全量包含「下载专用」和「免费」，仅过滤通知提示节点）
  const skipKeywords = ['剩余', '流量', '过期', '到期', '官网', '重置', '通知'];
  const proxyNames = (config.proxies || [])
    .map(p => p.name)
    .filter(name => !skipKeywords.some(kw => name.includes(kw)));

  if (proxyNames.length === 0) {
    return config;
  }

  // 4. 保持唯一做 30 秒测速的策略组：⚡ 30s自动最优
  const autoGroupName = '⚡ 30s自动最优';
  if (!config['proxy-groups'].some(g => g.name === autoGroupName)) {
    const autoGroup = {
      name: autoGroupName,
      type: 'url-test',
      url: 'https://www.google.com',
      interval: 30,     // 仅此组每 30 秒自动探测并选出最低延迟节点
      tolerance: 50,    // 50ms 容差
      lazy: false,
      proxies: proxyNames
    };
    config['proxy-groups'].unshift(autoGroup);
  } else {
    const existing = config['proxy-groups'].find(g => g.name === autoGroupName);
    if (existing) {
      existing.proxies = proxyNames;
      existing.interval = 30;
      existing.url = 'https://www.google.com';
    }
  }

  // 5. 其余原有策略组全部保留！清除单独测速设置，将「⚡ 30s自动最优」置顶为首选项
  config['proxy-groups'].forEach(group => {
    if (group.name === autoGroupName) {
      return;
    }
    // 普通选择组不设定时自动测速
    if (group.type === 'select') {
      delete group.url;
      delete group.interval;
    }
    // 将 ⚡ 30s自动最优 注入到可选手选位
    if (group.proxies && Array.isArray(group.proxies)) {
      if (!group.proxies.includes(autoGroupName)) {
        group.proxies.unshift(autoGroupName);
      }
    }
  });

  return config;
}
