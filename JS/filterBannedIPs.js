const ipList = new Set(require('../JSON/banned-ips.json'));

function isBannedIP(ip) {
    return ipList.has(ip);  // O(1) lookup as this uses a Set
}

module.exports = isBannedIP;