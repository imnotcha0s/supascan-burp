package com.supascan.probes;

import burp.api.montoya.MontoyaApi;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.supascan.extract.Extract;
import com.supascan.findings.Findings;
import com.supascan.model.PluginSettings;
import com.supascan.model.SupabaseInstance;
import com.supascan.model.TableState;
import com.supascan.net.Http;
import com.supascan.net.RateLimiter;
import com.supascan.registry.Registry;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Safe write probe (spec §6.2). Every request carries {@code Prefer: tx=rollback}
 * so nothing is ever persisted. Uses a contradiction filter that matches zero
 * rows without any value cast, and (when a sampled row exists) a type-safe body.
 */
public final class WriteProbe {

    private static final int MAX_TABLES = 400;
    /** MANDATORY — if this can't be set, no request is sent (spec §7.4). */
    private static final String ROLLBACK_PREFER = "tx=rollback,return=representation";

    private final Http http;
    private final RateLimiter limiter;
    private final Registry registry;
    private final Findings findings;

    public WriteProbe(MontoyaApi api, Http http, RateLimiter limiter, Registry registry, Findings findings) {
        this.http = http;
        this.limiter = limiter;
        this.registry = registry;
        this.findings = findings;
    }

    public void run(SupabaseInstance inst, Progress p) {
        Extract.Creds creds = Extract.credsFor(inst);
        if (!creds.usable()) {
            p.update("Write: no usable credentials.");
            return;
        }
        // Captured once, up front — see ReadProbe for why.
        String testedAs = inst.activeIdentityLabel();
        PluginSettings s = registry.settings();

        Deque<String> work = new ArrayDeque<>();
        Set<String> seen = new LinkedHashSet<>();
        for (String t : inst.tables.keySet()) {
            if (seen.add(t)) {
                work.add(t);
            }
        }
        if (s.discoveryEnabled) {
            for (String t : (s.useCustomWordlist && !Wordlists.parse(s.tableWordlist).isEmpty())
                    ? Wordlists.parse(s.tableWordlist) : Wordlists.TABLES) {
                if (seen.add(t)) {
                    work.add(t);
                }
            }
        }

        int tested = 0;
        while (!work.isEmpty() && tested < MAX_TABLES) {
            if (limiter.isStopped()) {
                p.update("Write: stopped.");
                break;
            }
            String table = work.poll();
            tested++;
            p.update("Write: " + table + " (" + tested + " tested)");

            TableState existing = inst.tables.get(table);
            String filterCol = pickFilterCol(existing);
            String body = buildBody(existing, filterCol);
            String url = inst.projectUrl + "/rest/v1/" + enc(table)
                    + "?and=(" + filterCol + ".is.null," + filterCol + ".not.is.null)";

            Map<String, String> headers = Map.of(
                    "Content-Type", "application/json",
                    "Prefer", ROLLBACK_PREFER);

            Http.Result r = http.request("PATCH", url, creds, headers, body, "write-probe " + table);
            if (r.kind == Http.Result.Kind.OUT_OF_SCOPE) {
                p.update("Write: " + r.error);
                return;
            }
            if (r.kind == Http.Result.Kind.STOPPED) {
                p.update("Write: stopped.");
                break;
            }
            if (!r.isOk()) {
                continue;
            }

            int code = r.status;
            String respBody = r.body();

            if (code == 404) {
                String hint = Extract.hintTable(respBody);
                if (hint != null && seen.add(hint)) {
                    work.add(hint);
                }
                continue;
            }

            TableState ts = inst.table(table);
            ts.observed = true;
            if (code == 200 || code == 204) {
                ts.anonWrite = "accepted";
                findings.writeAccepted(inst, table, testedAs, r.rr);
            } else if (code == 401 || code == 403) {
                ts.anonWrite = "rejected";
            }
            // 400 (schema/column/type error) is inconclusive — leave as-is, no finding.
            registry.save(inst);
        }
        registry.fireChanged();
        p.update("Write: done (" + tested + " tested).");
    }

    private static String pickFilterCol(TableState ts) {
        if (ts != null && ts.columns != null && !ts.columns.isEmpty()) {
            if (ts.columns.contains("id")) {
                return "id";
            }
            return ts.columns.get(0);
        }
        return "id";
    }

    /**
     * Type-safe no-op body. When a sampled row exists, reuse an existing column's
     * own value (guaranteed type-correct); otherwise fall back to the spec's
     * sentinel column. The filter matches 0 rows, so nothing is touched anyway.
     */
    private static String buildBody(TableState ts, String filterCol) {
        if (ts != null && ts.sampleRow != null) {
            try {
                JsonElement e = JsonParser.parseString(ts.sampleRow);
                if (e.isJsonObject()) {
                    JsonObject row = e.getAsJsonObject();
                    for (String k : row.keySet()) {
                        if (!k.equals(filterCol) && !k.equalsIgnoreCase("id")) {
                            JsonObject out = new JsonObject();
                            out.add(k, row.get(k));
                            return out.toString();
                        }
                    }
                }
            } catch (RuntimeException ignored) {
                // fall through
            }
        }
        return "{\"_supascan_probe\":\"test\"}";
    }

    private static String enc(String table) {
        return table.replace(" ", "%20");
    }
}
