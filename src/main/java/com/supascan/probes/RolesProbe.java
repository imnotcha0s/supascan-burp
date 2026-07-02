package com.supascan.probes;

import burp.api.montoya.MontoyaApi;
import com.supascan.extract.Extract;
import com.supascan.findings.Findings;
import com.supascan.model.SchemaState;
import com.supascan.model.SupabaseInstance;
import com.supascan.net.Http;
import com.supascan.net.RateLimiter;
import com.supascan.registry.Registry;

import java.util.Map;

/**
 * Roles / schemas privilege-escalation check (spec §6.6). Brute-forces
 * privileged PostgREST schemas via the {@code Accept-Profile} header. Runs as
 * the active identity; {@code 200} means that role can reach the schema,
 * {@code 406} means it cannot.
 */
public final class RolesProbe {

    private final Http http;
    private final RateLimiter limiter;
    private final Registry registry;
    private final Findings findings;

    public RolesProbe(MontoyaApi api, Http http, RateLimiter limiter, Registry registry, Findings findings) {
        this.http = http;
        this.limiter = limiter;
        this.registry = registry;
        this.findings = findings;
    }

    public void run(SupabaseInstance inst, Progress p) {
        Extract.Creds creds = Extract.credsFor(inst);
        if (!creds.usable()) {
            p.update("Roles: no usable credentials.");
            return;
        }
        // Captured once, up front — see ReadProbe for why.
        String testedAs = inst.activeIdentityLabel();

        for (Map.Entry<String, String> e : Wordlists.SCHEMAS.entrySet()) {
            if (limiter.isStopped()) {
                p.update("Roles: stopped.");
                break;
            }
            String schema = e.getKey();
            String sensitivity = e.getValue();
            p.update("Roles: " + schema + " (as " + testedAs + ")");

            Http.Result r = http.request("GET", inst.projectUrl + "/rest/v1/", creds,
                    Map.of("Accept-Profile", schema), null, "schema " + schema);
            if (r.kind == Http.Result.Kind.OUT_OF_SCOPE) {
                p.update("Roles: " + r.error);
                return;
            }
            if (r.kind == Http.Result.Kind.STOPPED) {
                p.update("Roles: stopped.");
                break;
            }
            if (!r.isOk()) {
                continue;
            }

            SchemaState st = inst.schemaStates.computeIfAbsent(schema, k -> new SchemaState(schema, sensitivity));
            st.sensitivity = sensitivity;
            st.status = r.status;
            st.testedAs = testedAs;
            if (r.status == 200) {
                st.exposed = true;
                findings.schemaReachable(inst, schema, sensitivity, testedAs, r.rr);
            } else {
                st.exposed = false; // 406 = not exposed to this role
            }
            registry.save(inst);
        }
        registry.fireChanged();
        p.update("Roles: done.");
    }
}
