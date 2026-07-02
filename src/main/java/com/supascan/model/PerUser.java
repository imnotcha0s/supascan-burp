package com.supascan.model;

/** One identity's view of a table during the IDOR differential. */
public class PerUser {
    public String label;
    public Integer rowCount;
    public String sampleId;

    public PerUser() {
    }

    public PerUser(String label, Integer rowCount, String sampleId) {
        this.label = label;
        this.rowCount = rowCount;
        this.sampleId = sampleId;
    }
}
