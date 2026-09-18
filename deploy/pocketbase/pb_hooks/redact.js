// Defense in depth; callers must send deliberately selected, non-personal text.
exports.redact = (value) => {
    // Normalize before pattern matching so embedded controls cannot hide keys.
    let text = value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g, "")
    text = text.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, "[REDACTED_KEY]")
    // Paths, userinfo, query strings and fragments can all contain secrets.
    text = text.replace(/\b(?:https?|wss?|ftp):\/\/[^\s"'<>]+/gi, "[REDACTED_URL]")
    text = text.replace(/\b(?:set-cookie|cookie)["']?\s*[:=]\s*[^\r\n]+/gi, "cookie=[REDACTED]")
    text = text.replace(
        /\b(?:authorization|(?:[a-z0-9]+[_-])*(?:api[_ -]?key|password|passwd|secret|token|license[_ -]?key|client[_ -]?secret))["']?\s*[:=]\s*(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|(?:bearer|basic)\s+[^\s,;}]+|[^\s,;}]+)/gi,
        "[REDACTED_CREDENTIAL]",
    )
    text = text.replace(/\b(?:bearer|basic)\s+[a-z0-9+/_.=-]+/gi, "[REDACTED_AUTH]")
    text = text.replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[REDACTED_EMAIL]")
    // IPv6 before IPv4, including IPv4-mapped IPv6.
    text = text.replace(/(?<![0-9A-Fa-f:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){6}(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:.]*::[0-9A-Fa-f:.]*)(?![0-9A-Fa-f:])/g, "[REDACTED_IP]")
    text = text.replace(/(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])/g, "[REDACTED_IP]")
    // Redaction can expand the text. Bound the result without a split surrogate.
    return text.trim().slice(0, 2000).replace(/[\uD800-\uDBFF]$/, "")
}
