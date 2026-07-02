package com.supascan.findings;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.supascan.model.SupabaseInstance;
import com.supascan.registry.Registry;

import java.util.ArrayList;
import java.util.List;

/**
 * Builds Burp {@link AuditIssue}s and adds them to the site map (spec §9).
 * Burp has no "Critical" severity, so critical findings map to HIGH with a
 * {@code [CRITICAL]} name prefix. Issues are deduped per {@code projectRef +
 * name}; per-object names keep one issue per table/rpc/schema/bucket.
 */
public final class Findings {

    private static final String BACKGROUND =
            "Supabase exposes PostgREST, GoTrue (auth), and Storage directly to the browser using a public "
                    + "<code>anon</code> API key. Data safety depends entirely on Postgres Row Level Security (RLS) "
                    + "policies and correct auth/storage configuration. Missing or permissive policies expose data "
                    + "and operations to anonymous or any authenticated user.";
    private static final String REMEDIATION_BG =
            "Enable RLS on every table exposed through PostgREST and write policies that scope rows to the "
                    + "authenticated user. Constrain writes with <code>WITH CHECK</code>. Never ship a "
                    + "<code>service_role</code> key to the client. Restrict exposed schemas and storage buckets.";

    private final MontoyaApi api;
    private final Registry registry;

    public Findings(MontoyaApi api, Registry registry) {
        this.api = api;
        this.registry = registry;
    }

    // ----------------------------------------------------------- passive -----

    public void instanceDetected(SupabaseInstance inst, HttpRequestResponse ev) {
        if (inst.detectionIssueRaised) {
            return;
        }
        String detail = "<p>A Supabase backend was detected in proxied traffic.</p>"
                + "<ul>"
                + "<li>Project ref: <b>" + esc(inst.projectRef) + "</b></li>"
                + "<li>Project URL: <b>" + esc(inst.projectUrl) + "</b></li>"
                + "<li>anon key observed: <b>" + (inst.anonKey != null) + "</b></li>"
                + "</ul>"
                + "<p>This is informational. Run SupaScan's scope-gated active checks to test for "
                + "RLS / auth / storage / RPC misconfigurations.</p>";
        add(inst, "Supabase instance detected", detail,
                "No action required — informational.",
                AuditIssueSeverity.INFORMATION, AuditIssueConfidence.CERTAIN, ev);
        inst.detectionIssueRaised = true;
        registry.save(inst);
    }

    public void serviceRoleLeak(SupabaseInstance inst, String tokenPreview, String where, HttpRequestResponse ev) {
        String detail = "<p><b>A <code>service_role</code> key is reachable client-side.</b> This key bypasses "
                + "all Row Level Security and grants full read/write to the entire database, auth, and storage.</p>"
                + "<ul>"
                + "<li>Project: <b>" + esc(inst.projectRef) + "</b></li>"
                + "<li>Observed in: " + esc(where) + "</li>"
                + "<li>Token (truncated): <code>" + esc(tokenPreview) + "</code></li>"
                + "</ul>"
                + "<p>SupaScan reports this key but never sends a request authenticated with it (spec §7.5). "
                + "Treat it as fully compromised.</p>";
        String remediation = "<ol>"
                + "<li><b>Rotate the key immediately</b> in the Supabase dashboard (Settings → API → generate new "
                + "JWT secret / service key).</li>"
                + "<li>Remove it from all client bundles, environment variables shipped to the browser, and mobile "
                + "apps. The <code>service_role</code> key must live only in trusted server-side code.</li>"
                + "<li>Audit access logs for abuse while the key was exposed.</li>"
                + "</ol>";
        add(inst, "[CRITICAL] Exposed Supabase service_role key (full RLS bypass)", detail, remediation,
                AuditIssueSeverity.HIGH, AuditIssueConfidence.CERTAIN, ev);
    }

    // ------------------------------------------------------------- read ------

    public void anonReadable(SupabaseInstance inst, String table, boolean sensitive, String testedAs,
                             Integer rowCount, String sample, HttpRequestResponse ev) {
        String name = sensitive
                ? "Missing/permissive RLS — " + testedAs + " can read public." + table
                : "Table readable by " + testedAs + " — public." + table;
        AuditIssueSeverity sev = sensitive ? AuditIssueSeverity.HIGH : AuditIssueSeverity.MEDIUM;
        String detail = "<p>The table <code>public." + esc(table) + "</code> returns rows to <b>" + esc(testedAs)
                + "</b>" + impact(rowCount) + ". Either RLS is disabled or a policy is "
                + "permissive (e.g. <code>USING (true)</code>)."
                + ("anon".equals(testedAs) ? "" : " Note: this was tested as an <b>authenticated</b> identity, "
                        + "not anon — the exposure may be broader (any signed-up user) rather than fully public.")
                + "</p>"
                + sampleBlock(sample)
                + "<p><b>Reproduce (single row + exact count, no bulk data):</b></p>"
                + curlCount(inst, table);
        add(inst, name, detail, rlsRemediation(table), sev, AuditIssueConfidence.FIRM, ev);
    }

    public void tokenTableReadable(SupabaseInstance inst, String table, String testedAs,
                                   Integer rowCount, HttpRequestResponse ev) {
        String detail = "<p><b>An account-takeover primitive is readable.</b> The table "
                + "<code>public." + esc(table) + "</code> looks like it holds password-reset / verification / "
                + "session tokens and is readable as <b>" + esc(testedAs) + "</b>" + impact(rowCount)
                + ".</p><p>Reading these values can allow account takeover.</p>"
                + "<p><b>Reproduce:</b></p>" + curlCount(inst, table);
        add(inst, "[CRITICAL] Account-takeover primitive readable — public." + table, detail,
                rlsRemediation(table), AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM, ev);
    }

    // ------------------------------------------------------------ write ------

    public void writeAccepted(SupabaseInstance inst, String table, String testedAs, HttpRequestResponse ev) {
        String detail = "<p>A rollback-only write probe (<code>Prefer: tx=rollback</code>) against "
                + "<code>public." + esc(table) + "</code> was accepted as <b>" + esc(testedAs) + "</b>, indicating "
                + "writes would persist for that identity. A missing or permissive write policy (no "
                + "<code>WITH CHECK</code>) lets it insert or modify rows.</p>"
                + "<p><b>Note:</b> SupaScan used <code>Prefer: tx=rollback</code>, so nothing was persisted.</p>";
        String remediation = "<pre>-- Restrict writes to the owner\n"
                + "ALTER TABLE public." + esc(table) + " ENABLE ROW LEVEL SECURITY;\n"
                + "CREATE POLICY \"insert own\" ON public." + esc(table) + "\n"
                + "  FOR INSERT WITH CHECK ((select auth.uid()) = user_id);\n"
                + "CREATE POLICY \"update own\" ON public." + esc(table) + "\n"
                + "  FOR UPDATE USING ((select auth.uid()) = user_id)\n"
                + "  WITH CHECK ((select auth.uid()) = user_id);</pre>";
        add(inst, "Writable via " + testedAs + " (missing WITH CHECK) — public." + table, detail, remediation,
                AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM, ev);
    }

    // ------------------------------------------------------------- auth ------

    public void openSignup(SupabaseInstance inst, String email, HttpRequestResponse ev) {
        // Spec §9 gives this a MEDIUM–HIGH range: self-provisioning accounts is a
        // MEDIUM concern on its own; it's HIGH once we already have confirmed
        // read/write exposure that a freshly-signed-up identity could reach.
        boolean confirmedExposure = inst.tables.values().stream()
                .anyMatch(t -> "rows".equals(t.anonRead) || "accepted".equals(t.anonWrite));
        AuditIssueSeverity sev = confirmedExposure ? AuditIssueSeverity.HIGH : AuditIssueSeverity.MEDIUM;

        String detail = "<p>The GoTrue signup endpoint returned an immediately-valid session (access token) "
                + "for a newly-created account <code>" + esc(email) + "</code> with no email confirmation. "
                + "Anyone can self-provision authenticated accounts.</p>"
                + "<p>Combined with permissive RLS for the <code>authenticated</code> role, this can expose data "
                + "intended only for real users."
                + (confirmedExposure
                        ? " SupaScan has already confirmed readable/writable tables on this project, so a "
                                + "self-provisioned account can very likely reach that same data."
                        : "")
                + "</p>";
        String remediation = "<p>In the Supabase dashboard: Authentication → Providers → Email → enable "
                + "<b>Confirm email</b>. Review which tables/policies grant access to the "
                + "<code>authenticated</code> role and ensure they scope rows per user.</p>";
        add(inst, "Open signup without email confirmation", detail, remediation,
                sev, AuditIssueConfidence.FIRM, ev);
    }

    // ----------------------------------------------------------- storage -----

    public void publicBucket(SupabaseInstance inst, String bucket, String testedAs,
                             int fileCount, HttpRequestResponse ev) {
        String detail = "<p>The storage bucket <code>" + esc(bucket) + "</code> lists objects to <b>"
                + esc(testedAs) + "</b> (" + fileCount + " object(s) enumerated). A public or listable bucket "
                + "exposes stored files to that identity — and, if the bucket has no Storage RLS policy at all, "
                + "to anyone.</p>"
                + "<p>Public object URL pattern: <code>" + esc(inst.projectUrl)
                + "/storage/v1/object/public/" + esc(bucket) + "/&lt;path&gt;</code></p>";
        String remediation = "<p>Set the bucket to private and add Storage RLS policies on "
                + "<code>storage.objects</code> scoped per user, e.g.:</p>"
                + "<pre>CREATE POLICY \"read own files\" ON storage.objects\n"
                + "  FOR SELECT USING (\n"
                + "    bucket_id = '" + esc(bucket) + "'\n"
                + "    AND (select auth.uid())::text = (storage.foldername(name))[1]\n"
                + "  );</pre>";
        add(inst, "Storage bucket listable/downloadable by " + testedAs + " — " + bucket, detail, remediation,
                AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM, ev);
    }

    // -------------------------------------------------------------- rpc ------

    public void unauthRpc(SupabaseInstance inst, String fn, String testedAs, Integer status, HttpRequestResponse ev) {
        String detail = "<p>The PostgREST RPC <code>public." + esc(fn) + "</code> executed as <b>" + esc(testedAs)
                + "</b> without any function-level access check (HTTP " + status + "). Database functions "
                + "callable by low-privilege roles can leak data or perform privileged operations depending on "
                + "their body and <code>SECURITY DEFINER</code> status.</p>"
                + "<p><b>Reproduce:</b></p>" + curlRpc(inst, fn);
        String remediation = "<pre>-- Revoke execute from anon/authenticated as appropriate\n"
                + "REVOKE EXECUTE ON FUNCTION public." + esc(fn) + " FROM anon;\n"
                + "-- Prefer SECURITY INVOKER and explicit auth checks inside the function.</pre>";
        add(inst, "PostgREST RPC callable as " + testedAs + " without authorization — " + fn, detail, remediation,
                AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM, ev);
    }

    public void elevatedRpc(SupabaseInstance inst, String fn, HttpRequestResponse ev) {
        String detail = "<p>The RPC <code>public." + esc(fn) + "</code> is reachable and its name suggests "
                + "network or secret access (e.g. http/fetch/url/vault/secret/decrypt). This may enable "
                + "<b>SSRF</b> or <b>secret exposure</b>.</p>"
                + "<p><b>Manual review required.</b> SupaScan does <b>not</b> auto-supply attacker URLs or payloads. "
                + "Inspect the function definition and test carefully by hand.</p>";
        String remediation = "<p>Audit the function body. Restrict who can execute it, avoid outbound network "
                + "calls driven by caller input, and never expose secret material through return values.</p>";
        add(inst, "[CRITICAL] Potential SSRF / secret exposure via RPC — " + fn, detail, remediation,
                AuditIssueSeverity.HIGH, AuditIssueConfidence.TENTATIVE, ev);
    }

    // ------------------------------------------------------- roles/schema ----

    public void schemaReachable(SupabaseInstance inst, String schema, String sensitivity,
                                String testedAs, HttpRequestResponse ev) {
        AuditIssueSeverity sev = "medium".equalsIgnoreCase(sensitivity)
                ? AuditIssueSeverity.MEDIUM : AuditIssueSeverity.HIGH;
        String detail = "<p>The PostgREST schema <code>" + esc(schema) + "</code> (sensitivity: <b>"
                + esc(sensitivity) + "</b>) is reachable via the <code>Accept-Profile</code> header as "
                + "<b>" + esc(testedAs) + "</b>. By default only <code>public</code> should be exposed; another "
                + "reachable schema indicates a privilege-escalation / over-exposure issue.</p>"
                + "<p><b>Reproduce:</b></p><pre>curl -s -D - '" + esc(inst.projectUrl) + "/rest/v1/' \\\n"
                + "  -H 'apikey: " + apikeyForCurl(inst) + "' \\\n"
                + "  -H 'Authorization: Bearer " + apikeyForCurl(inst) + "' \\\n"
                + "  -H 'Accept-Profile: " + esc(schema) + "'</pre>";
        String remediation = "<p>Remove the schema from PostgREST's exposed schemas "
                + "(<code>db-schemas</code> / API settings). Ensure roles cannot reach internal schemas such as "
                + "<code>auth</code>, <code>vault</code>, <code>storage</code>.</p>";
        // testedAs is part of the name (not just the detail) so that re-running as
        // a second identity — the compare-roles workflow spec §6.6 recommends —
        // raises its own issue instead of being silently swallowed by dedupe
        // against the first role's already-raised finding for this schema.
        add(inst, "Privileged PostgREST schema reachable as " + testedAs + " — " + schema, detail, remediation,
                sev, AuditIssueConfidence.FIRM, ev);
    }

    // ------------------------------------------------------------- idor ------

    public void idorShared(SupabaseInstance inst, String table, String comparison, HttpRequestResponse ev) {
        String detail = "<p>Two different identities saw <b>identical rows</b> (same exact count and same first-row "
                + "id) for <code>public." + esc(table) + "</code>, which suggests RLS is not scoping rows per "
                + "user (potential IDOR / broken RLS).</p>"
                + "<p>" + esc(comparison) + "</p>"
                + "<p><b>Confirm manually</b> — shared/reference tables (lookups, public catalogs) can legitimately "
                + "match across users.</p>";
        add(inst, "Broken RLS / IDOR — identical rows across users — public." + table, detail,
                rlsRemediation(table), AuditIssueSeverity.HIGH, AuditIssueConfidence.TENTATIVE, ev);
    }

    // ------------------------------------------------------------- core ------

    private void add(SupabaseInstance inst, String name, String detail, String remediation,
                     AuditIssueSeverity sev, AuditIssueConfidence conf, HttpRequestResponse... evidence) {
        String key = inst.projectRef + "|" + name;
        if (registry.isIssueRaised(key)) {
            return;
        }
        List<HttpRequestResponse> ev = new ArrayList<>();
        for (HttpRequestResponse e : evidence) {
            if (e != null) {
                ev.add(e);
            }
        }
        String baseUrl = baseUrl(inst, ev);
        try {
            AuditIssue issue = AuditIssue.auditIssue(
                    name, detail, remediation, baseUrl, sev, conf, BACKGROUND, REMEDIATION_BG, sev, ev);
            api.siteMap().add(issue);
            registry.markIssueRaised(key);
            api.logging().logToOutput("[finding] (" + inst.projectRef + ") " + name);
        } catch (RuntimeException e) {
            api.logging().logToError("SupaScan: failed to add issue '" + name + "': " + e.getMessage());
        }
    }

    private static String baseUrl(SupabaseInstance inst, List<HttpRequestResponse> ev) {
        if (inst.projectUrl != null && !inst.projectUrl.isBlank()) {
            return inst.projectUrl;
        }
        if (!ev.isEmpty() && ev.get(0) != null && ev.get(0).request() != null) {
            return ev.get(0).request().url();
        }
        return "https://" + inst.projectRef + ".supabase.co";
    }

    // ---- detail helpers ----

    private static String impact(Integer rowCount) {
        if (rowCount == null) {
            return "";
        }
        return " (≈" + rowCount + " row" + (rowCount == 1 ? "" : "s") + " reachable)";
    }

    private static String sampleBlock(String sample) {
        if (sample == null || sample.isBlank()) {
            return "";
        }
        return "<p><b>Sample row:</b></p><pre>" + esc(sample) + "</pre>";
    }

    private String curlCount(SupabaseInstance inst, String table) {
        String key = apikeyForCurl(inst);
        return "<pre>curl -s -D - '" + esc(inst.projectUrl) + "/rest/v1/" + esc(table) + "?select=*' \\\n"
                + "  -H 'apikey: " + key + "' \\\n"
                + "  -H 'Authorization: Bearer " + key + "' \\\n"
                + "  -H 'Prefer: count=exact' -H 'Range: 0-0'</pre>";
    }

    private String curlRpc(SupabaseInstance inst, String fn) {
        String key = apikeyForCurl(inst);
        return "<pre>curl -s -D - -X POST '" + esc(inst.projectUrl) + "/rest/v1/rpc/" + esc(fn) + "' \\\n"
                + "  -H 'apikey: " + key + "' \\\n"
                + "  -H 'Authorization: Bearer " + key + "' \\\n"
                + "  -H 'Content-Type: application/json' \\\n"
                + "  -d '{}'</pre>";
    }

    /** Include the real anon key (public by design); use a placeholder for session-only creds. */
    private static String apikeyForCurl(SupabaseInstance inst) {
        if (inst.anonKey != null && !inst.anonKey.isBlank()) {
            return esc(inst.anonKey);
        }
        return "&lt;your-session-jwt&gt;";
    }

    private static String rlsRemediation(String table) {
        return "<pre>ALTER TABLE public." + esc(table) + " ENABLE ROW LEVEL SECURITY;\n"
                + "CREATE POLICY \"read own\" ON public." + esc(table) + "\n"
                + "  FOR SELECT USING ((select auth.uid()) = user_id);</pre>";
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
