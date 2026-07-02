package com.supascan.scope;

import burp.api.montoya.MontoyaApi;
import com.supascan.model.SupabaseInstance;

/**
 * The in-scope gate (spec §7.2 — hard requirement). Every probe request must
 * pass {@link #isInScope(String)} before it is sent. There is no override.
 */
public final class Scope {

    private final MontoyaApi api;

    public Scope(MontoyaApi api) {
        this.api = api;
    }

    public boolean isInScope(String url) {
        if (url == null || url.isBlank()) {
            return false;
        }
        try {
            return api.scope().isInScope(url);
        } catch (RuntimeException e) {
            return false;
        }
    }

    public boolean instanceInScope(SupabaseInstance inst) {
        return inst != null && isInScope(inst.projectUrl);
    }

    public static final String OUT_OF_SCOPE_MESSAGE =
            "Target not in scope — add it to Burp scope to run active checks.";
}
