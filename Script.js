// Clash Verge 全局扩展脚本 (Global Script)
// 适配：规则模式 (Rule Mode) 与 全局模式 (Global Mode) 均可自动最优分流

function main(config) {
  // 1. 直连规则保障（内网系统与常用国内服务不走外网代理）
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
    // 小米/米柚服务直连
    'DOMAIN-SUFFIX,miui.com,DIRECT',
    'DOMAIN-SUFFIX,xiaomi.com,DIRECT',
    'DOMAIN-KEYWORD,xiaomi,DIRECT',
    'DOMAIN-KEYWORD,miui,DIRECT'
  );

  // 2. 检查策略组是否存在
  if (!config['proxy-groups']) {
    return config;
  }

  // 3. 提取并过滤所有有效代理节点（排除下载专用、免费、流量提示等特殊节点）
  const skipKeywords = ['下载专用', '免费', '剩余', '流量', '过期', '到期', '官网', '重置'];
  const proxyNames = (config.proxies || [])
    .map(p => p.name)
    .filter(name => !skipKeywords.some(kw => name.includes(kw)));

  if (proxyNames.length === 0) {
    return config;
  }

  // 4. 创建 30 秒自动最低延迟测速组
  const autoGroupName = '⚡ 30s自动最优';
  if (!config['proxy-groups'].some(g => g.name === autoGroupName)) {
    const autoGroup = {
      name: autoGroupName,
      type: 'url-test',
      url: 'https://www.google.com',
      interval: 30,     // 每 30 秒自动测速
      tolerance: 50,    // 延迟差距在 50ms 内不频繁跳变
      lazy: false,      // 主动保活测速
      proxies: proxyNames
    };
    // 插入到策略组列表最前列
    config['proxy-groups'].unshift(autoGroup);
  }

  // 5. 适配 规则模式 (Rule) 与 全局模式 (Global)
  // 将「⚡ 30s自动最优」注入到所有主要的调度组（如 🔰 选择节点、GLOBAL、PROXY 等）
  const targetGroupNames = [
    '🔰 选择节点',
    'GLOBAL',
    'PROXY',
    '节点选择',
    '🐟 漏网之鱼'
  ];

  config['proxy-groups'].forEach(group => {
    if (targetGroupNames.includes(group.name) || group.name === 'GLOBAL') {
      if (group.proxies && !group.proxies.includes(autoGroupName)) {
        group.proxies.unshift(autoGroupName);
      }
    }
  });

  return config;
}
