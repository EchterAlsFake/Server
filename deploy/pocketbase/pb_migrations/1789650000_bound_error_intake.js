migrate((app) => {
    const settings = app.settings()
    settings.rateLimits.rules = [
        { label: "POST /error_log", audience: "", duration: 60, maxRequests: 10 },
        { label: "*:auth", audience: "", duration: 60, maxRequests: 5 },
        { label: "/api/", audience: "", duration: 60, maxRequests: 120 },
    ]
    settings.rateLimits.enabled = true
    settings.rateLimits.excludedIPs = []
    app.save(settings)
    // This receiver has no public signup use case. Keep existing users intact.
    const users = app.findCollectionByNameOrId("users")
    users.createRule = null
    app.save(users)
    // Bound disk growth without silently deleting any existing diagnostic data.
    // Runs atomically with the INSERT, including concurrent submissions.
    app.db().newQuery("CREATE TRIGGER IF NOT EXISTS error_logs_capacity BEFORE INSERT ON error_logs WHEN (SELECT count(*) FROM error_logs) >= 100000 BEGIN SELECT RAISE(ABORT, 'error_log_capacity'); END").execute()
}, (app) => {
    app.db().newQuery("DROP TRIGGER IF EXISTS error_logs_capacity").execute()
    // Deliberately retain privacy/access hardening on rollback.
})
