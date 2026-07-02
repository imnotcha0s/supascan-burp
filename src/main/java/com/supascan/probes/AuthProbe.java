package com.supascan.probes;

import burp.api.montoya.MontoyaApi;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.supascan.extract.Extract;
import com.supascan.findings.Findings;
import com.supascan.model.SessionUser;
import com.supascan.model.SupabaseInstance;
import com.supascan.net.Http;
import com.supascan.registry.Registry;

import java.util.Map;
import java.util.UUID;

/**
 * Auth checks (spec §6.3): automated open-signup test plus signup / password
 * sign-in used by the Sessions and Custom-Signup panels. A successful signup
 * that returns an instant session is captured as a usable identity.
 */
public final class AuthProbe {

    private final Http http;
    private final Registry registry;
    private final Findings findings;

    public AuthProbe(MontoyaApi api, Http http, Registry registry, Findings findings) {
        this.http = http;
        this.registry = registry;
        this.findings = findings;
    }

    /** Automated open-signup check — at most one test account per run. */
    public void runSignupCheck(SupabaseInstance inst, Progress p) {
        Extract.Creds creds = Extract.credsFor(inst);
        if (!creds.usable()) {
            p.update("Auth: no anon key / creds to call the auth endpoint.");
            return;
        }
        String email = expandEmail(registry.settings().testEmail);
        String password = randomPassword();
        p.update("Auth: attempting signup as " + email);

        Http.Result r = signup(inst, email, password, null);
        if (r.kind == Http.Result.Kind.OUT_OF_SCOPE) {
            p.update("Auth: " + r.error);
            return;
        }
        if (r.kind == Http.Result.Kind.STOPPED) {
            p.update("Auth: stopped.");
            return;
        }
        if (!r.isOk()) {
            p.update("Auth: signup request failed.");
            return;
        }
        String token = extractAccessToken(r.body());
        if (token != null) {
            SessionUser u = captureSession(inst, r.body(), email, "signup");
            findings.openSignup(inst, email, r.rr);
            p.update("Auth: OPEN SIGNUP — instant session for " + email
                    + (u != null ? " (added as active identity)" : ""));
        } else {
            p.update("Auth: signup returned no instant session (email confirmation likely required).");
        }
    }

    /** Raw signup. {@code extraDataJson} (optional) becomes GoTrue user metadata. */
    public Http.Result signup(SupabaseInstance inst, String email, String password, String extraDataJson) {
        Extract.Creds creds = Extract.credsFor(inst);
        JsonObject body = new JsonObject();
        body.addProperty("email", email);
        body.addProperty("password", password);
        if (extraDataJson != null && !extraDataJson.isBlank()) {
            try {
                JsonElement data = JsonParser.parseString(extraDataJson);
                body.add("data", data);
            } catch (RuntimeException e) {
                // ignore invalid metadata JSON — send without it
            }
        }
        String url = inst.projectUrl + "/auth/v1/signup";
        return http.request("POST", url, creds, Map.of("Content-Type", "application/json"),
                body.toString(), "signup " + email);
    }

    /** Password grant sign-in. */
    public Http.Result signIn(SupabaseInstance inst, String email, String password) {
        Extract.Creds creds = Extract.credsFor(inst);
        JsonObject body = new JsonObject();
        body.addProperty("email", email);
        body.addProperty("password", password);
        String url = inst.projectUrl + "/auth/v1/token?grant_type=password";
        return http.request("POST", url, creds, Map.of("Content-Type", "application/json"),
                body.toString(), "signin " + email);
    }

    /** Parse a session out of an auth response, add it, and make it active. */
    public SessionUser captureSession(SupabaseInstance inst, String body, String fallbackEmail, String source) {
        String token = extractAccessToken(body);
        if (token == null) {
            return null;
        }
        String id = userId(body);
        String email = userEmail(body);
        SessionUser u = new SessionUser(
                id != null ? id : Registry.newId(),
                email != null ? email : fallbackEmail,
                token, source, Registry.now());
        inst.sessions.add(u);
        inst.activeSessionId = u.id;
        registry.save(inst);
        registry.fireChanged();
        return u;
    }

    // ---------------------------------------------------------------- utils --

    public static String extractAccessToken(String body) {
        JsonObject o = parse(body);
        if (o == null) {
            return null;
        }
        if (isStr(o, "access_token")) {
            return o.get("access_token").getAsString();
        }
        if (o.has("session") && o.get("session").isJsonObject()) {
            JsonObject sess = o.getAsJsonObject("session");
            if (isStr(sess, "access_token")) {
                return sess.get("access_token").getAsString();
            }
        }
        return null;
    }

    private static String userId(String body) {
        JsonObject o = parse(body);
        if (o == null) {
            return null;
        }
        if (o.has("user") && o.get("user").isJsonObject() && isStr(o.getAsJsonObject("user"), "id")) {
            return o.getAsJsonObject("user").get("id").getAsString();
        }
        return isStr(o, "id") ? o.get("id").getAsString() : null;
    }

    private static String userEmail(String body) {
        JsonObject o = parse(body);
        if (o == null) {
            return null;
        }
        if (o.has("user") && o.get("user").isJsonObject() && isStr(o.getAsJsonObject("user"), "email")) {
            return o.getAsJsonObject("user").get("email").getAsString();
        }
        return isStr(o, "email") ? o.get("email").getAsString() : null;
    }

    private static JsonObject parse(String body) {
        try {
            JsonElement e = JsonParser.parseString(body);
            return e.isJsonObject() ? e.getAsJsonObject() : null;
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private static boolean isStr(JsonObject o, String key) {
        return o.has(key) && o.get(key).isJsonPrimitive() && o.getAsJsonPrimitive(key).isString()
                && !o.get(key).getAsString().isBlank();
    }

    private static String expandEmail(String template) {
        String rand = UUID.randomUUID().toString().substring(0, 8);
        if (template.contains("{rand}")) {
            return template.replace("{rand}", rand);
        }
        return template;
    }

    private static String randomPassword() {
        return "Sup4!" + UUID.randomUUID().toString().replace("-", "");
    }
}
