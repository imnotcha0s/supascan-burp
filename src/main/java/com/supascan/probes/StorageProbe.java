package com.supascan.probes;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.supascan.extract.Extract;
import com.supascan.findings.Findings;
import com.supascan.model.BucketState;
import com.supascan.model.PluginSettings;
import com.supascan.model.StorageObject;
import com.supascan.model.SupabaseInstance;
import com.supascan.net.Http;
import com.supascan.net.RateLimiter;
import com.supascan.registry.Registry;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Storage checks (spec §6.5). Buckets are discovered passively; the active work
 * is object enumeration to <i>find files</i>. Recurses into folders, capped at
 * ≤300 files, ≤60 requests, ≤5 depth per bucket. Records file names/sizes only —
 * downloads are operator-initiated from the Storage panel.
 */
public final class StorageProbe {

    private static final int MAX_FILES = 300;
    private static final int MAX_REQUESTS = 60;
    private static final int MAX_DEPTH = 5;
    private static final int PAGE = 100;

    private final Http http;
    private final RateLimiter limiter;
    private final Registry registry;
    private final Findings findings;

    public StorageProbe(MontoyaApi api, Http http, RateLimiter limiter, Registry registry, Findings findings) {
        this.http = http;
        this.limiter = limiter;
        this.registry = registry;
        this.findings = findings;
    }

    public void run(SupabaseInstance inst, List<String> customBuckets, Progress p) {
        Extract.Creds creds = Extract.credsFor(inst);
        if (!creds.usable()) {
            p.update("Storage: no usable credentials.");
            return;
        }
        // Captured once, up front — see ReadProbe for why.
        String testedAs = inst.activeIdentityLabel();
        PluginSettings s = registry.settings();

        Set<String> candidates = new LinkedHashSet<>(inst.buckets);
        if (customBuckets != null) {
            candidates.addAll(customBuckets);
        }
        if (s.discoveryEnabled) {
            candidates.addAll(Wordlists.BUCKETS);
        }

        boolean[] scopeAbort = {false};
        for (String bucket : candidates) {
            if (limiter.isStopped()) {
                p.update("Storage: stopped.");
                break;
            }
            p.update("Storage: listing " + bucket + "…");
            BucketState bs = enumerate(inst, bucket, creds, scopeAbort, p);
            if (scopeAbort[0]) {
                p.update("Storage: " + com.supascan.scope.Scope.OUT_OF_SCOPE_MESSAGE);
                return;
            }
            if (bs != null && !bs.files.isEmpty()) {
                bs.fileCount = bs.files.size();
                inst.bucketStates.put(bucket, bs);
                if (!inst.buckets.contains(bucket)) {
                    inst.buckets.add(bucket);
                }
                findings.publicBucket(inst, bucket, testedAs, bs.fileCount, lastEvidence);
                registry.save(inst);
                p.update("Storage: " + bucket + " → " + bs.fileCount + " file(s)");
            }
        }
        registry.fireChanged();
        p.update("Storage: done.");
    }

    private burp.api.montoya.http.message.HttpRequestResponse lastEvidence;

    private BucketState enumerate(SupabaseInstance inst, String bucket, Extract.Creds creds,
                                  boolean[] scopeAbort, Progress p) {
        BucketState bs = new BucketState(bucket);
        int requests = 0;
        Deque<Frame> stack = new ArrayDeque<>();
        stack.push(new Frame("", 0));

        while (!stack.isEmpty() && bs.files.size() < MAX_FILES && requests < MAX_REQUESTS) {
            if (limiter.isStopped()) {
                break;
            }
            Frame f = stack.pop();
            requests++;

            Http.Result r = listCall(inst, bucket, f.prefix, creds);
            if (r.kind == Http.Result.Kind.OUT_OF_SCOPE) {
                scopeAbort[0] = true;
                return null;
            }
            if (r.kind == Http.Result.Kind.STOPPED) {
                break;
            }
            if (!r.isOk() || r.status != 200) {
                continue;
            }
            lastEvidence = r.rr;

            JsonArray arr = asArray(r.body());
            if (arr == null) {
                continue;
            }
            for (JsonElement el : arr) {
                if (!el.isJsonObject()) {
                    continue;
                }
                JsonObject obj = el.getAsJsonObject();
                String name = str(obj, "name");
                if (name == null) {
                    continue;
                }
                boolean folder = !obj.has("id") || obj.get("id").isJsonNull();
                if (folder) {
                    if (f.depth < MAX_DEPTH) {
                        stack.push(new Frame(f.prefix + name + "/", f.depth + 1));
                    }
                } else {
                    Long size = null;
                    String mime = null;
                    if (obj.has("metadata") && obj.get("metadata").isJsonObject()) {
                        JsonObject md = obj.getAsJsonObject("metadata");
                        if (md.has("size") && md.get("size").isJsonPrimitive()) {
                            try {
                                size = md.get("size").getAsLong();
                            } catch (NumberFormatException ignored) {
                                size = null;
                            }
                        }
                        mime = str(md, "mimetype");
                    }
                    bs.files.add(new StorageObject(f.prefix + name, size, mime));
                    if (bs.files.size() >= MAX_FILES) {
                        break;
                    }
                }
            }
        }
        bs.fileCount = bs.files.size();
        return bs;
    }

    private Http.Result listCall(SupabaseInstance inst, String bucket, String prefix, Extract.Creds creds) {
        JsonObject body = new JsonObject();
        body.addProperty("prefix", prefix);
        body.addProperty("limit", PAGE);
        body.addProperty("offset", 0);
        JsonObject sortBy = new JsonObject();
        sortBy.addProperty("column", "name");
        sortBy.addProperty("order", "asc");
        body.add("sortBy", sortBy);
        String url = inst.projectUrl + "/storage/v1/object/list/" + enc(bucket);
        return http.request("POST", url, creds, java.util.Map.of("Content-Type", "application/json"),
                body.toString(), "storage list " + bucket + (prefix.isEmpty() ? "" : "/" + prefix));
    }

    // ---- operator-initiated helpers (Storage panel) ----

    public String publicUrl(SupabaseInstance inst, String bucket, String path) {
        return inst.projectUrl + "/storage/v1/object/public/" + enc(bucket) + "/" + encPath(path);
    }

    /** Build a download request (authenticated) for send-to-Repeater. */
    public HttpRequest downloadRequest(SupabaseInstance inst, String bucket, String path) {
        String url = inst.projectUrl + "/storage/v1/object/" + enc(bucket) + "/" + encPath(path);
        return http.build("GET", url, Extract.credsFor(inst), null, null);
    }

    /** Operator-initiated download (scope-gated + logged like any send). */
    public Http.Result download(SupabaseInstance inst, String bucket, String path) {
        String url = inst.projectUrl + "/storage/v1/object/" + enc(bucket) + "/" + encPath(path);
        return http.request("GET", url, Extract.credsFor(inst), null, null, "storage download " + bucket + "/" + path);
    }

    private static JsonArray asArray(String body) {
        try {
            JsonElement e = JsonParser.parseString(body);
            return e.isJsonArray() ? e.getAsJsonArray() : null;
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private static String str(JsonObject o, String key) {
        return o.has(key) && o.get(key).isJsonPrimitive() ? o.get(key).getAsString() : null;
    }

    private static String enc(String s) {
        return s.replace(" ", "%20");
    }

    private static String encPath(String path) {
        return path.replace(" ", "%20");
    }

    private static final class Frame {
        final String prefix;
        final int depth;

        Frame(String prefix, int depth) {
            this.prefix = prefix;
            this.depth = depth;
        }
    }
}
