migrate(
    (app) => {
        const collection = new Collection({
            type: "base",
            name: "error_logs",
            listRule: null,
            viewRule: null,
            createRule: null,
            updateRule: null,
            deleteRule: null,
            fields: [
                {
                    type: "text",
                    name: "message",
                    required: true,
                    max: 2000,
                },
                {
                    type: "autodate",
                    name: "created",
                    onCreate: true,
                    onUpdate: false,
                },
                {
                    type: "autodate",
                    name: "updated",
                    onCreate: true,
                    onUpdate: true,
                },
            ],
        })
        app.save(collection)

        const settings = app.settings()
        settings.meta.appName = "EAF Error Log"
        settings.meta.appURL = "https://api.echteralsfake.me/error_log"
        settings.meta.hideControls = true
        settings.logs.maxDays = 0
        settings.logs.minLevel = 8
        settings.logs.logIP = false
        settings.logs.logAuthId = false
        settings.rateLimits.enabled = true
        settings.rateLimits.rules = [
            {
                label: "POST /error_log",
                audience: "@guest",
                duration: 60,
                maxRequests: 10,
            },
        ]
        settings.trustedProxy.headers = ["X-Forwarded-For"]
        settings.trustedProxy.useLeftmostIP = true
        settings.superuserIPs = ["127.0.0.1", "::1"]
        app.save(settings)
    },
    (app) => {
        const collection = app.findCollectionByNameOrId("error_logs")
        app.delete(collection)
    },
)
