package com.supascan.model;

/** Global (cross-project) settings, persisted in Burp preferences. */
public class PluginSettings {
    public int maxRequestsPerSecond = 5;
    public int maxConcurrency = 3;
    public String testEmail = "supascan.probe@example.com"; // supports {rand}
    public String tableWordlist = "";
    public boolean useCustomWordlist = false; // false = built-in default list
    public boolean discoveryEnabled = true;   // false = only observed tables/buckets

    public PluginSettings sanitized() {
        if (maxRequestsPerSecond < 1) {
            maxRequestsPerSecond = 1;
        }
        if (maxConcurrency < 1) {
            maxConcurrency = 1;
        }
        if (testEmail == null || testEmail.isBlank()) {
            testEmail = "supascan.probe@example.com";
        }
        return this;
    }
}
