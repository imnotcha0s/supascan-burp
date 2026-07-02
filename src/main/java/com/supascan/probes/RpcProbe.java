package com.supascan.probes;

import burp.api.montoya.MontoyaApi;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.supascan.extract.Extract;
import com.supascan.findings.Findings;
import com.supascan.model.RpcState;
import com.supascan.model.SupabaseInstance;
import com.supascan.net.Http;
import com.supascan.net.RateLimiter;
import com.supascan.registry.Registry;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * RPC checks (spec §6.4): enumerate functions via OpenAPI, merge with observed
 * names, optionally brute-force a built-in/custom list (with hint following),
 * and call each unauthenticated. Network/secret-capable names are flagged
 * elevated for manual review — SupaScan never auto-supplies attacker URLs.
 */
public final class RpcProbe {

    private static final int MAX_RPCS = 400;

    private final Http http;
    private final RateLimiter limiter;
    private final Registry registry;
    private final Findings findings;

    public RpcProbe(MontoyaApi api, Http http, RateLimiter limiter, Registry registry, Findings findings) {
        this.http = http;
        this.limiter = limiter;
        this.registry = registry;
        this.findings = findings;
    }

    public void run(SupabaseInstance inst, boolean bruteforce, List<String> customNames, Progress p) {
        Extract.Creds creds = Extract.credsFor(inst);
        if (!creds.usable()) {
            p.update("RPC: no usable credentials.");
            return;
        }
        // Captured once, up front — see ReadProbe for why.
        String testedAs = inst.activeIdentityLabel();

        Set<String> seen = new LinkedHashSet<>();
        Deque<String> work = new ArrayDeque<>();

        // OpenAPI enumeration.
        p.update("RPC: enumerating via OpenAPI…");
        Http.Result openapi = http.request("GET", inst.projectUrl + "/rest/v1/", creds,
                Map.of("Accept", "application/openapi+json"), null, "openapi");
        if (openapi.kind == Http.Result.Kind.OUT_OF_SCOPE) {
            p.update("RPC: " + openapi.error);
            return;
        }
        for (String fn : parseOpenApiRpcs(openapi)) {
            if (seen.add(fn)) {
                work.add(fn);
            }
        }
        // Observed RPCs.
        for (String fn : inst.rpcs) {
            if (seen.add(fn)) {
                work.add(fn);
            }
        }
        // Custom names.
        if (customNames != null) {
            for (String fn : customNames) {
                if (seen.add(fn)) {
                    work.add(fn);
                }
            }
        }
        // Opt-in brute-force.
        if (bruteforce) {
            for (String fn : Wordlists.RPCS) {
                if (seen.add(fn)) {
                    work.add(fn);
                }
            }
        }

        int tested = 0;
        while (!work.isEmpty() && tested < MAX_RPCS) {
            if (limiter.isStopped()) {
                p.update("RPC: stopped.");
                break;
            }
            String fn = work.poll();
            tested++;
            p.update("RPC: " + fn + " (" + tested + " tested)");

            String url = inst.projectUrl + "/rest/v1/rpc/" + enc(fn);
            Http.Result r = http.request("POST", url, creds,
                    Map.of("Content-Type", "application/json"), "{}", "rpc " + fn);
            if (r.kind == Http.Result.Kind.OUT_OF_SCOPE) {
                p.update("RPC: " + r.error);
                return;
            }
            if (r.kind == Http.Result.Kind.STOPPED) {
                p.update("RPC: stopped.");
                break;
            }
            if (!r.isOk()) {
                continue;
            }

            int code = r.status;
            String body = r.body();

            if (code == 404) {
                String hint = Extract.hintFunction(body);
                if (hint != null && seen.add(hint)) {
                    work.add(hint);
                    p.update("RPC: hint → " + hint);
                }
                continue;
            }

            RpcState st = inst.rpcStates.computeIfAbsent(fn, RpcState::new);
            st.status = code;
            if (!inst.rpcs.contains(fn)) {
                inst.rpcs.add(fn);
            }

            boolean reachable = (code >= 200 && code < 300) || code == 400; // 400 = exists, needs args
            st.exposed = reachable;
            st.elevated = Wordlists.isElevatedRpc(fn);

            if (code >= 200 && code < 300) {
                findings.unauthRpc(inst, fn, testedAs, code, r.rr);
            }
            if (st.elevated && reachable) {
                findings.elevatedRpc(inst, fn, r.rr);
            }
            registry.save(inst);
        }
        registry.fireChanged();
        p.update("RPC: done (" + tested + " tested).");
    }

    private static Set<String> parseOpenApiRpcs(Http.Result openapi) {
        Set<String> out = new LinkedHashSet<>();
        if (!openapi.isOk()) {
            return out;
        }
        try {
            JsonObject o = JsonParser.parseString(openapi.body()).getAsJsonObject();
            if (o.has("paths") && o.get("paths").isJsonObject()) {
                for (String key : o.getAsJsonObject("paths").keySet()) {
                    if (key.startsWith("/rpc/")) {
                        out.add(key.substring("/rpc/".length()));
                    }
                }
            }
        } catch (RuntimeException ignored) {
            // not OpenAPI JSON — nothing to enumerate
        }
        return out;
    }

    private static String enc(String fn) {
        return fn.replace(" ", "%20");
    }
}
