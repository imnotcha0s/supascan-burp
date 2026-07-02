package com.supascan.model;

/**
 * Records a client-reachable {@code service_role} key. Detection/report ONLY —
 * no code path ever authenticates a request with this key (spec §7.5).
 */
public class ServiceRoleLeak {
    /** Truncated token — never the full secret. */
    public String tokenPreview;
    /** "response-body" | "js-bundle" | "header" | "manual" */
    public String source;
    /** Where it was observed. */
    public String url;
    public String detectedAt;

    public ServiceRoleLeak() {
    }

    public ServiceRoleLeak(String tokenPreview, String source, String url, String detectedAt) {
        this.tokenPreview = tokenPreview;
        this.source = source;
        this.url = url;
        this.detectedAt = detectedAt;
    }
}
