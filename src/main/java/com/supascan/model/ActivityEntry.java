package com.supascan.model;

/** One audit-log row: every active request the extension sends is recorded here. */
public class ActivityEntry {
    public String id;
    public String timestamp;
    public String method;
    public String url;
    public Integer statusCode;
    public String note;

    public ActivityEntry() {
    }

    public ActivityEntry(String id, String timestamp, String method, String url, Integer statusCode, String note) {
        this.id = id;
        this.timestamp = timestamp;
        this.method = method;
        this.url = url;
        this.statusCode = statusCode;
        this.note = note;
    }
}
