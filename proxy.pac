function FindProxyForURL(url, host) {
    if (!host) return "DIRECT";
    host = host.toLowerCase();
    var pacHosts = ["127.0.0.1", "localhost", "10.0.165.45", "10.0.165.32", "10.0.165.30"];
    var h;
    for (h = 0; h < pacHosts.length; h++) {
        if (host === pacHosts[h]) return "DIRECT";
    }
    var exact = ["task.yungu.org"];
    var suffixes = [".dingtalk.com", ".dingtalkapps.com", ".dingtalk-inc.com", ".laiwang.com"];
    var contains = ["dingtalk"];
    var i;
    for (i = 0; i < exact.length; i++) {
        if (host === exact[i] || dnsDomainIs(host, "." + exact[i])) return "DIRECT";
    }
    for (i = 0; i < suffixes.length; i++) {
        if (host === suffixes[i].slice(1) || dnsDomainIs(host, suffixes[i])) return "DIRECT";
    }
    for (i = 0; i < contains.length; i++) {
        if (host.indexOf(contains[i]) !== -1) return "DIRECT";
    }
    var proxies = ["PROXY 10.0.165.45:8080", "PROXY 10.0.165.32:8080", "PROXY 10.0.165.30:8080"];
    var n = proxies.length;
    if (n === 0) return "DIRECT";
    var client = "";
    try { client = myIpAddress(); } catch (e) { client = ""; }
    var key = host;
    if (client && client !== "127.0.0.1") key = client + "|" + host;
    var hash = 0;
    for (i = 0; i < key.length; i++) {
        hash = (hash * 31 + key.charCodeAt(i)) % 2147483647;
    }
    var start = hash % n;
    var ordered = [];
    for (i = 0; i < n; i++) {
        ordered.push(proxies[(start + i) % n]);
    }
    return ordered.join("; ") + "; DIRECT";
}
