package com.supascan.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A single detected Supabase project. Keyed in the registry by {@link #projectRef}.
 * Gson-serializable plain data class — fields are public by design.
 */
public class SupabaseInstance {

    public String projectRef;
    public String projectUrl;

    /** anon-role JWT, if one was observed. */
    public String anonKey;
    /** decoded {@code role} claim of {@link #anonKey}. */
    public String anonKeyRole;

    /** Set only if a {@code service_role} key was seen client-side. Detection/report only. */
    public ServiceRoleLeak serviceRoleLeak;

    public Map<String, TableState> tables = new LinkedHashMap<>();
    public List<String> rpcs = new ArrayList<>();
    public List<String> buckets = new ArrayList<>();
    public Map<String, BucketState> bucketStates = new LinkedHashMap<>();
    public Map<String, RpcState> rpcStates = new LinkedHashMap<>();
    public Map<String, SchemaState> schemaStates = new LinkedHashMap<>();

    public List<SessionUser> sessions = new ArrayList<>();
    /** null = anonymous identity. */
    public String activeSessionId;

    public boolean detectionIssueRaised;

    /** Computed live from Burp scope at check time — never persisted. */
    public transient boolean inScope;

    public SupabaseInstance() {
    }

    public SupabaseInstance(String projectRef, String projectUrl) {
        this.projectRef = projectRef;
        this.projectUrl = projectUrl;
    }

    /** The currently-selected session, or null when anonymous / not found. */
    public SessionUser activeSession() {
        if (activeSessionId == null) {
            return null;
        }
        for (SessionUser s : sessions) {
            if (activeSessionId.equals(s.id)) {
                return s;
            }
        }
        return null;
    }

    /** Human label for whichever identity active checks currently run as. */
    public String activeIdentityLabel() {
        SessionUser u = activeSession();
        return u != null ? u.label() : "anon";
    }

    public TableState table(String name) {
        return tables.computeIfAbsent(name, n -> {
            TableState t = new TableState();
            t.name = n;
            t.anonRead = "untested";
            t.anonWrite = "untested";
            return t;
        });
    }

    public boolean hasServiceRoleLeak() {
        return serviceRoleLeak != null;
    }
}
