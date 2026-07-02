package com.supascan.probes;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.supascan.extract.Extract;
import com.supascan.findings.Findings;
import com.supascan.model.IdorResult;
import com.supascan.model.PerUser;
import com.supascan.model.SessionUser;
import com.supascan.model.SupabaseInstance;
import com.supascan.net.Http;
import com.supascan.net.RateLimiter;
import com.supascan.registry.Registry;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * IDOR / broken-RLS differential (spec §6.7). Requires ≥2 identities. For each
 * known table, reads as each identity with a single count-only + first-id
 * request (no bulk data). If two different identities see identical rows (same
 * exact count and same first id), RLS isn't scoping per user.
 */
public final class IdorProbe {

    private static final int MAX_TABLES = 200;

    private final Http http;
    private final RateLimiter limiter;
    private final Registry registry;
    private final Findings findings;

    public IdorProbe(MontoyaApi api, Http http, RateLimiter limiter, Registry registry, Findings findings) {
        this.http = http;
        this.limiter = limiter;
        this.registry = registry;
        this.findings = findings;
    }

    public void run(SupabaseInstance inst, Progress p) {
        // Spec §6.7: the trigger is ≥2 *sessions*; anon is folded into the
        // comparison set as a bonus once that gate is met, not counted toward it.
        if (inst.sessions.size() < 2) {
            p.update("IDOR: need ≥2 sessions on this instance (anon is compared too, but doesn't count toward this).");
            return;
        }
        List<Identity> identities = buildIdentities(inst);
        if (inst.tables.isEmpty()) {
            p.update("IDOR: no known tables — run Read first.");
            return;
        }

        int tested = 0;
        for (String table : new ArrayList<>(inst.tables.keySet())) {
            if (limiter.isStopped()) {
                p.update("IDOR: stopped.");
                break;
            }
            if (tested >= MAX_TABLES) {
                break;
            }
            tested++;
            p.update("IDOR: " + table + " across " + identities.size() + " identities");

            IdorResult res = new IdorResult();
            HttpRequestResponse evidence = null;
            boolean aborted = false;

            for (Identity id : identities) {
                if (limiter.isStopped()) {
                    aborted = true;
                    break;
                }
                String url = inst.projectUrl + "/rest/v1/" + enc(table) + "?select=*&limit=1";
                Http.Result r = http.request("GET", url, id.creds,
                        Map.of("Prefer", "count=exact", "Range", "0-0"),
                        null, "idor " + table + " as " + id.label);
                if (r.kind == Http.Result.Kind.OUT_OF_SCOPE) {
                    p.update("IDOR: " + r.error);
                    return;
                }
                if (r.kind == Http.Result.Kind.STOPPED) {
                    aborted = true;
                    break;
                }
                if (!r.isOk()) {
                    res.perUser.add(new PerUser(id.label, null, null));
                    continue;
                }
                evidence = r.rr;
                Integer count = ReadProbe.parseCount(r.header("Content-Range"));
                String firstId = firstId(r.body());
                res.perUser.add(new PerUser(id.label, count, firstId));
            }
            if (aborted) {
                break;
            }

            String comparison = detectShared(res);
            if (comparison != null) {
                res.shared = true;
                findings.idorShared(inst, table, comparison, evidence);
            }
            inst.table(table).idor = res;
            registry.save(inst);
        }
        registry.fireChanged();
        p.update("IDOR: done (" + tested + " tables).");
    }

    /** Returns a human comparison string if two distinct identities share rows, else null. */
    private static String detectShared(IdorResult res) {
        Map<String, String> sigToLabel = new HashMap<>();
        for (PerUser pu : res.perUser) {
            if (pu.rowCount == null || pu.rowCount == 0 || pu.sampleId == null) {
                continue;
            }
            String sig = pu.rowCount + "|" + pu.sampleId;
            String prev = sigToLabel.get(sig);
            if (prev != null && !prev.equals(pu.label)) {
                return prev + " and " + pu.label + " both saw count=" + pu.rowCount
                        + " and first id=" + pu.sampleId;
            }
            sigToLabel.putIfAbsent(sig, pu.label);
        }
        return null;
    }

    private List<Identity> buildIdentities(SupabaseInstance inst) {
        List<Identity> out = new ArrayList<>();
        if (inst.anonKey != null && !inst.anonKey.isBlank()) {
            out.add(new Identity("anon", Extract.creds(inst.anonKey, inst.anonKey)));
        }
        for (SessionUser u : inst.sessions) {
            if (u.token == null || u.token.isBlank()) {
                continue;
            }
            String apikey = (inst.anonKey != null && !inst.anonKey.isBlank()) ? inst.anonKey : u.token;
            out.add(new Identity(u.label(), Extract.creds(apikey, u.token)));
        }
        return out;
    }

    private static String firstId(String body) {
        try {
            JsonElement e = JsonParser.parseString(body);
            if (!e.isJsonArray()) {
                return null;
            }
            JsonArray arr = e.getAsJsonArray();
            if (arr.isEmpty() || !arr.get(0).isJsonObject()) {
                return null;
            }
            JsonObject first = arr.get(0).getAsJsonObject();
            if (first.has("id") && first.get("id").isJsonPrimitive()) {
                return first.get("id").getAsString();
            }
            for (String k : first.keySet()) {
                if (first.get(k).isJsonPrimitive()) {
                    return k + "=" + first.get(k).getAsString();
                }
            }
            return null;
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private static String enc(String table) {
        return table.replace(" ", "%20");
    }

    private static final class Identity {
        final String label;
        final Extract.Creds creds;

        Identity(String label, Extract.Creds creds) {
            this.label = label;
            this.creds = creds;
        }
    }
}
