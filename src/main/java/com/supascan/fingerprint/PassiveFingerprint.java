package com.supascan.fingerprint;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.supascan.extract.Extract;
import com.supascan.findings.Findings;
import com.supascan.model.ServiceRoleLeak;
import com.supascan.model.SupabaseInstance;
import com.supascan.registry.Registry;

/**
 * Passive detection over proxied traffic (spec §3). Restricted to
 * {@link ToolType#PROXY}. <b>Never sends a new request.</b> Detection is driven
 * entirely by the observed request (via {@code initiatingRequest()}) and the
 * response body. The single most valuable catch — a client-reachable
 * {@code service_role} key — is handled here and reported without ever using it.
 */
public final class PassiveFingerprint implements HttpHandler {

    private static final int MAX_BODY_SCAN = 5_000_000;

    private final MontoyaApi api;
    private final Registry registry;
    private final Findings findings;

    public PassiveFingerprint(MontoyaApi api, Registry registry, Findings findings) {
        this.api = api;
        this.registry = registry;
        this.findings = findings;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        try {
            if (req.toolSource().isFromTool(ToolType.PROXY)) {
                registerFromRequest(req);
            }
        } catch (RuntimeException e) {
            api.logging().logToError("SupaScan passive (request) error: " + e.getMessage());
        }
        return RequestToBeSentAction.continueWith(req);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        try {
            if (resp.toolSource().isFromTool(ToolType.PROXY)) {
                analyzeResponse(resp);
            }
        } catch (RuntimeException e) {
            api.logging().logToError("SupaScan passive (response) error: " + e.getMessage());
        }
        return ResponseReceivedAction.continueWith(resp);
    }

    // -------------------------------------------------------- request side ---

    /** Register instance/creds/artifacts from a request. No issues, no evidence. */
    private void registerFromRequest(HttpRequest req) {
        Coords c = coordsForRequest(req);
        if (c == null) {
            return;
        }
        SupabaseInstance inst = registry.getOrCreate(c.ref, c.url);
        boolean changed = harvestRequestHeaders(inst, req, null);
        changed |= harvestPathArtifacts(inst, req.path());
        if (changed) {
            registry.save(inst);
            registry.fireChanged();
        }
    }

    // ------------------------------------------------------- response side ---

    private void analyzeResponse(HttpResponseReceived resp) {
        HttpRequest req = resp.initiatingRequest();
        HttpRequestResponse rr = req != null ? HttpRequestResponse.httpRequestResponse(req, resp) : null;
        boolean changed = false;

        // 1) Instance from the request itself (host/path/headers).
        Coords c = req != null ? coordsForRequest(req) : null;
        SupabaseInstance direct = null;
        if (c != null) {
            direct = registry.getOrCreate(c.ref, c.url);
            changed |= harvestRequestHeaders(direct, req, rr);
            changed |= harvestPathArtifacts(direct, req.path());
        }

        // 2) Body scan — JS bundles / HTML / JSON can reveal refs, anon keys, service_role keys.
        if (shouldScanBody(resp)) {
            String body = resp.bodyToString();
            if (body != null && body.length() > MAX_BODY_SCAN) {
                body = body.substring(0, MAX_BODY_SCAN);
            }
            changed |= scanBody(body, rr);
        }

        // 3) Informational detection issue for the directly-observed instance.
        if (direct != null) {
            findings.instanceDetected(direct, rr);
        }

        if (changed) {
            registry.fireChanged();
        }
    }

    // ---------------------------------------------------- manual (context menu) --

    /**
     * Best-effort manual analysis of a selected request/response (context-menu
     * "Analyze request"). Returns the detected project ref, or null.
     */
    public String analyzeManually(HttpRequestResponse rr) {
        if (rr == null) {
            return null;
        }
        HttpRequest req = rr.request();
        Coords c = req != null ? coordsForRequest(req) : null;
        SupabaseInstance direct = null;
        if (c != null) {
            direct = registry.getOrCreate(c.ref, c.url);
            harvestRequestHeaders(direct, req, rr);
            harvestPathArtifacts(direct, req.path());
        }
        if (rr.hasResponse()) {
            String body = rr.response().bodyToString();
            if (body != null) {
                if (body.length() > MAX_BODY_SCAN) {
                    body = body.substring(0, MAX_BODY_SCAN);
                }
                scanBody(body, rr);
            }
        }
        if (direct != null) {
            findings.instanceDetected(direct, rr);
        }
        registry.save(direct);
        registry.fireChanged();
        return direct != null ? direct.projectRef : null;
    }

    /**
     * Force-add the selected host as a Supabase instance (context-menu "Add as
     * Supabase instance"), even if the path isn't an obvious API path. Returns
     * the registry key.
     */
    public String addManualInstance(HttpRequestResponse rr) {
        if (rr == null || rr.request() == null || rr.request().httpService() == null) {
            return null;
        }
        HttpRequest req = rr.request();
        String host = req.httpService().host();
        String ref = Extract.refFromHost(host);
        boolean secure = req.httpService().secure();
        int port = req.httpService().port();
        String key;
        String url;
        if (ref != null) {
            key = ref;
            url = "https://" + host;
        } else {
            boolean defaultPort = (secure && port == 443) || (!secure && port == 80);
            key = host;
            url = (secure ? "https" : "http") + "://" + host + (defaultPort ? "" : (":" + port));
        }
        SupabaseInstance inst = registry.getOrCreate(key, url);
        harvestRequestHeaders(inst, req, rr);
        harvestPathArtifacts(inst, req.path());
        registry.save(inst);
        findings.instanceDetected(inst, rr);
        registry.fireChanged();
        return key;
    }

    private boolean shouldScanBody(HttpResponseReceived resp) {
        return resp.contains(".supabase.co", false)
                || resp.contains("createClient", true)
                || resp.contains("SUPABASE", false)
                || resp.contains("eyJ", true);
    }

    /** Scan a text body for refs, anon keys, and service_role leaks. */
    private boolean scanBody(String body, HttpRequestResponse rr) {
        if (body == null || body.isEmpty()) {
            return false;
        }
        boolean changed = false;

        for (String ref : Extract.findRefs(body)) {
            SupabaseInstance inst = registry.getOrCreate(ref, "https://" + ref + ".supabase.co");
            findings.instanceDetected(inst, rr);
            changed = true;
        }

        for (String token : Extract.findJwts(body)) {
            Extract.Jwt jwt = Extract.decodeJwt(token);
            if (jwt == null) {
                continue;
            }
            if (jwt.isServiceRole()) {
                SupabaseInstance inst = instanceForToken(jwt);
                if (inst != null) {
                    recordServiceRoleLeak(inst, token, "response body / JS bundle", rr);
                    changed = true;
                }
            } else if (jwt.isAnon() && jwt.ref != null) {
                SupabaseInstance inst = registry.getOrCreate(jwt.ref, "https://" + jwt.ref + ".supabase.co");
                if (inst.anonKey == null) {
                    inst.anonKey = jwt.token;
                    inst.anonKeyRole = jwt.role;
                    registry.save(inst);
                    findings.instanceDetected(inst, rr);
                    changed = true;
                }
            }
        }
        return changed;
    }

    // ------------------------------------------------------------ harvest ----

    /**
     * Pull anon key + service_role leak out of a request's apikey/Authorization
     * headers. When {@code rr} is non-null (response phase), service_role leaks
     * are reported with evidence; in the request phase they are only recorded.
     */
    private boolean harvestRequestHeaders(SupabaseInstance inst, HttpRequest req, HttpRequestResponse rr) {
        boolean changed = false;
        for (String header : new String[] {req.headerValue("apikey"), req.headerValue("Authorization")}) {
            Extract.Jwt jwt = Extract.decodeJwt(header);
            if (jwt == null) {
                continue;
            }
            if (jwt.isServiceRole()) {
                SupabaseInstance target = jwt.ref != null ? instanceForToken(jwt) : inst;
                if (target != null) {
                    boolean firstTime = target.serviceRoleLeak == null;
                    recordServiceRoleLeak(target, jwt.token, "client request header", rr);
                    changed |= firstTime;
                }
            } else if (jwt.isAnon() && inst.anonKey == null) {
                inst.anonKey = jwt.token;
                inst.anonKeyRole = jwt.role;
                changed = true;
            }
        }
        return changed;
    }

    private boolean harvestPathArtifacts(SupabaseInstance inst, String path) {
        boolean changed = false;
        String table = Extract.tableFromPath(path);
        if (table != null) {
            if (!inst.tables.containsKey(table)) {
                inst.table(table).observed = true;
                changed = true;
            } else if (!inst.tables.get(table).observed) {
                inst.tables.get(table).observed = true;
                changed = true;
            }
        }
        String rpc = Extract.rpcFromPath(path);
        if (rpc != null && !inst.rpcs.contains(rpc)) {
            inst.rpcs.add(rpc);
            changed = true;
        }
        String bucket = Extract.bucketFromStoragePath(path);
        if (bucket != null && !inst.buckets.contains(bucket)) {
            inst.buckets.add(bucket);
            changed = true;
        }
        return changed;
    }

    // ------------------------------------------------------------ helpers ----

    /**
     * Record a service_role leak in the model immediately (so the UI banner
     * shows right away), but only raise the deduped {@link Findings} AuditIssue
     * once real evidence ({@code rr} non-null) is available. The dedupe key
     * locks on first raise, so raising early with null evidence would
     * permanently strand this — the most important finding in the tool —
     * without a linked request/response.
     */
    private void recordServiceRoleLeak(SupabaseInstance inst, String token, String where, HttpRequestResponse rr) {
        if (inst.serviceRoleLeak == null) {
            inst.serviceRoleLeak = new ServiceRoleLeak(preview(token), where, where, Registry.now());
            registry.save(inst);
        }
        if (rr != null) {
            // Findings dedupes; safe to call repeatedly once evidence exists.
            findings.serviceRoleLeak(inst, preview(token), where, rr);
        }
    }

    private SupabaseInstance instanceForToken(Extract.Jwt jwt) {
        if (jwt.ref == null) {
            return null;
        }
        return registry.getOrCreate(jwt.ref, "https://" + jwt.ref + ".supabase.co");
    }

    private static Coords coordsForRequest(HttpRequest req) {
        if (req == null || req.httpService() == null) {
            return null;
        }
        String host = req.httpService().host();
        String ref = Extract.refFromHost(host);
        if (ref != null) {
            return new Coords(ref, "https://" + host);
        }
        if (Extract.isSupabaseApiPath(req.path())) {
            boolean secure = req.httpService().secure();
            int port = req.httpService().port();
            String scheme = secure ? "https" : "http";
            boolean defaultPort = (secure && port == 443) || (!secure && port == 80);
            String url = scheme + "://" + host + (defaultPort ? "" : (":" + port));
            return new Coords(host, url); // self-hosted: key by host
        }
        return null;
    }

    private static String preview(String token) {
        if (token == null) {
            return "";
        }
        String s = token.length() > 16 ? token.substring(0, 16) : token;
        return s + "…";
    }

    /** Project coordinates: a registry key + base URL. */
    private static final class Coords {
        final String ref;
        final String url;

        Coords(String ref, String url) {
            this.ref = ref;
            this.url = url;
        }
    }
}
