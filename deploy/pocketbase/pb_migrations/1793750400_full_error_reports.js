migrate((app) => {
    const collection = app.findCollectionByNameOrId("error_logs")
    collection.fields.getByName("message").max = 1048576
    app.save(collection)
}, (app) => {
    // Existing reports stay intact; restore the matching older hook on rollback.
    const collection = app.findCollectionByNameOrId("error_logs")
    collection.fields.getByName("message").max = 2000
    app.save(collection)
})
