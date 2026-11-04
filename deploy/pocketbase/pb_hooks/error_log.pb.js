// Bounded diagnostic intake, including full tracebacks and reproduction URLs.
$app.onServe().bindFunc((e) => {
    e.server.readHeaderTimeout = 5 * 1000000000
    e.server.readTimeout = 10 * 1000000000
    e.server.writeTimeout = 15 * 1000000000
    e.server.idleTimeout = 60 * 1000000000
    e.server.maxHeaderBytes = 16384
    return e.next()
})

routerUse(new Middleware(
    (e) => {
        if (e.request.url.path !== "/error_log") return e.next()
        e.response.header().set("Cache-Control", "no-store")
        // Anonymous intake must never acquire an authenticated rate-limit bypass.
        e.request.header.del("Authorization")
        e.request.header.del("Cookie")
        // One atomic, constant-size shared token bucket, including invalid traffic.
        // Store serialized primitives, never VM-owned mutable objects across runtimes.
        let allowed = false
        const now = Date.now()
        e.app.store().setFunc("errorLogAdmission", (old) => {
            const state = old ? JSON.parse(old) : { at: now, tokens: 120 }
            const tokens = Math.min(120, state.tokens + Math.max(0, now - state.at) / 500)
            allowed = tokens >= 1
            return JSON.stringify({ at: now, tokens: allowed ? tokens - 1 : tokens })
        })
        if (!allowed) {
            e.response.header().set("Retry-After", "1")
            throw e.tooManyRequestsError("Diagnostic intake is busy.", {})
        }
        if (e.request.url.rawQuery) {
            throw e.badRequestError("Query parameters are not accepted.", {})
        }
        return e.next()
    },
    -1050, // Before native authentication and per-IP limiter allocation.
    "errorLogAdmission",
))

routerAdd(
    "POST",
    "/error_log",
    (e) => {
        const maxBodyBytes = 1048576
        const contentType = e.request.header.get("Content-Type") || ""
        if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
            throw e.error(415, "Unsupported media type.", {})
        }
        if (e.request.contentLength > maxBodyBytes) {
            throw e.error(413, "Request body exceeds 1 MiB.", {})
        }
        let body
        try {
            // Read one byte beyond the contract limit: LimitReader alone silently
            // accepts a valid JSON prefix and ignores the rest of a chunked body.
            body = readerToString(e.request.body, maxBodyBytes + 1)
        } catch (error) {
            if (String(error).includes("request body too large")) {
                throw e.error(413, "Request body exceeds 1 MiB.", {})
            }
            throw e.badRequestError("Unable to read request body.", {})
        }
        if (toBytes(body).length > maxBodyBytes) {
            throw e.error(413, "Request body exceeds 1 MiB.", {})
        }
        let payload
        try {
            payload = JSON.parse(body)
        } catch (_) {
            throw e.badRequestError("Invalid JSON body.", {})
        }
        if (
            payload === null || Array.isArray(payload) || typeof payload !== "object" ||
            Object.keys(payload).length !== 1 ||
            !Object.prototype.hasOwnProperty.call(payload, "message") ||
            typeof payload.message !== "string"
        ) {
            throw e.badRequestError("Expected only a string message field.", {})
        }
        const message = payload.message
        if (!/[^\s\u0000-\u001f\u007f]/.test(message)) {
            throw e.badRequestError("Message must contain diagnostic text.", {})
        }
        // Cached schema avoids an unnecessary metadata query on each report.
        const record = new Record(e.app.findCachedCollectionByNameOrId("error_logs"))
        // Preserve the opted-in diagnostic verbatim. Redaction would remove the
        // video URLs, exception messages and source details needed to reproduce it.
        record.set("message", message)
        try {
            e.app.save(record)
        } catch (_) {
            let emit = false
            const now = Date.now()
            e.app.store().setFunc("errorLogStorageFailure", (last) => {
                emit = !last || now - last >= 60000
                return emit ? now : last
            })
            if (emit) console.error("Diagnostic storage unavailable; inspect local database capacity and health.")
            // Never return database internals or echo input in error responses.
            e.response.header().set("Retry-After", "3600")
            throw e.error(503, "Diagnostic storage is unavailable.", {})
        }
        return e.noContent(204)
    },
    // The extra byte is only a sentinel; the handler still enforces 1 MiB.
    $apis.bodyLimit(1048577),
    $apis.skipSuccessActivityLog(),
)
