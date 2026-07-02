package com.supascan.probes;

import burp.api.montoya.MontoyaApi;
import com.google.gson.JsonArray;
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
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Read test (spec §6.1). {@code limit=1} probe + count-only header for impact.
 * Uses a worklist so PostgREST 404 hints redirect to real table names. Never
 * requests more than one row of actual data.
 */
public final class ReadProbe {

    private static final int MAX_TABLES = 400;

    private final Http http;
    private final RateLimiter limiter;
    private final Registry registry;
    private final Findings findings;

    public ReadProbe(MontoyaApi api, Http http, RateLimiter limiter, Registry registry, Findings findings) {
        this.http = http;
        this.limiter = limiter;
        this.registry = registry;
        this.findings = findings;
    }

    public void run(SupabaseInstance inst, Progress p) {
        Extract.Creds creds = Extract.credsFor(inst);
        if (!creds.usable()) {
            p.update("Read: no usable credentials (add an anon key or a session).");
            return;
        }
        // Captured once, up front: attributes every finding from this run to the
        // identity that was actually active when it started, even if the operator
        // switches sessions in the UI while this background run is still going.
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
            for (String t : discoveryList(s)) {
                if (seen.add(t)) {
                    work.add(t);
                }
            }
        }

        int tested = 0;
        while (!work.isEmpty() && tested < MAX_TABLES) {
            if (limiter.isStopped()) {
                p.update("Read: stopped.");
                break;
            }
            String table = work.poll();
            tested++;
            p.update("Read: " + table + " (" + tested + " tested, " + work.size() + " queued)");

            String url = inst.projectUrl + "/rest/v1/" + enc(table) + "?select=*&limit=1";
            Http.Result r = http.request("GET", url, creds, null, null, "read " + table);
            if (r.kind == Http.Result.Kind.OUT_OF_SCOPE) {
                p.update("Read: " + r.error);
                return;
            }
            if (r.kind == Http.Result.Kind.STOPPED) {
                p.update("Read: stopped.");
                break;
            }
            if (!r.isOk()) {
                continue;
            }

            int code = r.status;
            String body = r.body();

            if (code == 404) {
                String hint = Extract.hintTable(body);
                if (hint != null && seen.add(hint)) {
                    work.add(hint);
                    p.update("Read: hint → " + hint);
                }
                continue; // do not persist a non-existent guess
            }

            TableState ts = inst.table(table);
            ts.observed = true;

            if (code == 401 || code == 403) {
                ts.anonRead = "denied";
            } else if (code == 200) {
                JsonArray rows = asArray(body);
                if (rows != null && rows.size() > 0 && rows.get(0).isJsonObject()) {
                    JsonObject first = rows.get(0).getAsJsonObject();
                    ts.anonRead = "rows";
                    ts.columns = keys(first);
                    ts.sampleRow = first.toString();
                    Integer count = countRows(inst, table, creds);
                    ts.rowCount = count;
                    if (Wordlists.isTokenTable(table)) {
                        findings.tokenTableReadable(inst, table, testedAs, count, r.rr);
                    } else {
                        findings.anonReadable(inst, table, Wordlists.isSensitiveTable(table), testedAs,
                                count, ts.sampleRow, r.rr);
                    }
                } else {
                    ts.anonRead = "empty";
                }
            }
            registry.save(inst);
        }
        registry.fireChanged();
        p.update("Read: done (" + tested + " tested).");
    }

    /** Count-only impact measurement — reads the Content-Range header, not the data. */
    private Integer countRows(SupabaseInstance inst, String table, Extract.Creds creds) {
        String url = inst.projectUrl + "/rest/v1/" + enc(table) + "?select=*";
        Http.Result r = http.request("GET", url, creds,
                java.util.Map.of("Prefer", "count=exact", "Range", "0-0"), null, "count " + table);
        if (!r.isOk()) {
            return null;
        }
        return parseCount(r.header("Content-Range"));
    }

    static Integer parseCount(String contentRange) {
        if (contentRange == null) {
            return null;
        }
        int slash = contentRange.lastIndexOf('/');
        if (slash < 0) {
            return null;
        }
        String total = contentRange.substring(slash + 1).trim();
        if (total.equals("*") || total.isEmpty()) {
            return null;
        }
        try {
            return Integer.parseInt(total);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private List<String> discoveryList(PluginSettings s) {
        if (s.useCustomWordlist) {
            List<String> custom = Wordlists.parse(s.tableWordlist);
            if (!custom.isEmpty()) {
                return custom;
            }
        }
        return Wordlists.TABLES;
    }

    private static JsonArray asArray(String body) {
        try {
            JsonElement e = JsonParser.parseString(body);
            return e.isJsonArray() ? e.getAsJsonArray() : null;
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private static List<String> keys(JsonObject o) {
        List<String> k = new ArrayList<>(o.keySet());
        return k;
    }

    private static String enc(String table) {
        return table.replace(" ", "%20");
    }
}
