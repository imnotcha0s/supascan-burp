package com.supascan.extract;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.supascan.model.SessionUser;
import com.supascan.model.SupabaseInstance;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure parsing helpers: JWT decode + role, project-ref / table / rpc / bucket
 * path parsing, PostgREST hint parsing, credential resolution, and body
 * scanning for refs / anon keys / service_role leaks. No I/O, no Burp types.
 */
public final class Extract {

    private Extract() {
    }

    /** {@code <ref>.supabase.co} — the 20-char project ref. */
    public static final Pattern HOST_REF = Pattern.compile("^([a-z0-9]{20})\\.supabase\\.co$");
    private static final Pattern REF_IN_TEXT = Pattern.compile("([a-z0-9]{20})\\.supabase\\.co");
    private static final Pattern JWT = Pattern.compile("eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{4,}");
    private static final Pattern HINT_TABLE =
            Pattern.compile("[Pp]erhaps you meant the table '(?:[A-Za-z0-9_]+\\.)?([A-Za-z0-9_]+)'");
    private static final Pattern HINT_FUNCTION =
            Pattern.compile("[Pp]erhaps you meant to call the function (?:[A-Za-z0-9_]+\\.)?([A-Za-z0-9_]+)");

    // ---------------------------------------------------------------- JWT ----

    /** Decoded JWT payload of interest. {@code role} is the key field for SupaScan. */
    public static final class Jwt {
        public final String token;
        public final String role;
        public final String ref;
        public final String sub;
        public final String email;
        public final Long exp;

        Jwt(String token, String role, String ref, String sub, String email, Long exp) {
            this.token = token;
            this.role = role;
            this.ref = ref;
            this.sub = sub;
            this.email = email;
            this.exp = exp;
        }

        public boolean isServiceRole() {
            return "service_role".equals(role);
        }

        public boolean isAnon() {
            return "anon".equals(role);
        }
    }

    /** Decode a JWT's payload segment. Returns null if the token is not a decodable JWT. */
    public static Jwt decodeJwt(String token) {
        if (token == null) {
            return null;
        }
        String t = token.trim();
        if (t.regionMatches(true, 0, "Bearer ", 0, 7)) {
            t = t.substring(7).trim();
        }
        String[] parts = t.split("\\.");
        if (parts.length < 2) {
            return null;
        }
        try {
            String json = new String(b64urlDecode(parts[1]), StandardCharsets.UTF_8);
            JsonObject o = JsonParser.parseString(json).getAsJsonObject();
            String role = optString(o, "role");
            String ref = optString(o, "ref");
            String sub = optString(o, "sub");
            String email = optString(o, "email");
            Long exp = o.has("exp") && o.get("exp").isJsonPrimitive() ? o.get("exp").getAsLong() : null;
            if (ref == null) {
                String iss = optString(o, "iss");
                if (iss != null) {
                    Matcher m = REF_IN_TEXT.matcher(iss);
                    if (m.find()) {
                        ref = m.group(1);
                    }
                }
            }
            return new Jwt(t, role, ref, sub, email, exp);
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** True if the string is a structurally-decodable JWT. */
    public static boolean isJwt(String s) {
        return decodeJwt(s) != null;
    }

    private static byte[] b64urlDecode(String s) {
        String t = s.replace('-', '+').replace('_', '/');
        int pad = t.length() % 4;
        if (pad == 2) {
            t += "==";
        } else if (pad == 3) {
            t += "=";
        } else if (pad == 1) {
            throw new IllegalArgumentException("bad base64url length");
        }
        return Base64.getDecoder().decode(t);
    }

    // --------------------------------------------------------------- hosts ---

    /** Project ref from a supabase.co host, or null (self-hosted / non-supabase). */
    public static String refFromHost(String host) {
        if (host == null) {
            return null;
        }
        Matcher m = HOST_REF.matcher(host);
        return m.matches() ? m.group(1) : null;
    }

    public static boolean isSupabaseApiPath(String path) {
        if (path == null) {
            return false;
        }
        String p = stripQuery(path);
        return p.startsWith("/rest/v1/") || p.startsWith("/auth/v1/")
                || p.startsWith("/storage/v1/") || p.startsWith("/realtime/v1/")
                || p.startsWith("/functions/v1/") || p.equals("/rest/v1");
    }

    // --------------------------------------------------------------- paths ---

    private static String afterRestV1(String path) {
        String p = stripQuery(path);
        int i = p.indexOf("/rest/v1/");
        if (i < 0) {
            return null;
        }
        return p.substring(i + "/rest/v1/".length());
    }

    /** Table name from {@code /rest/v1/<table>}; null for the OpenAPI root or {@code /rpc/}. */
    public static String tableFromPath(String path) {
        String rest = afterRestV1(path);
        if (rest == null || rest.isEmpty()) {
            return null;
        }
        String first = firstSegment(rest);
        if (first.isEmpty() || first.equals("rpc")) {
            return null;
        }
        return safeDecode(first);
    }

    /** Function name from {@code /rest/v1/rpc/<fn>}, else null. */
    public static String rpcFromPath(String path) {
        String rest = afterRestV1(path);
        if (rest == null || !rest.startsWith("rpc/")) {
            return null;
        }
        String fn = firstSegment(rest.substring("rpc/".length()));
        return fn.isEmpty() ? null : safeDecode(fn);
    }

    /** Bucket name out of any storage object/render path, skipping visibility/operation prefixes. */
    public static String bucketFromStoragePath(String path) {
        String p = stripQuery(path);
        int i = p.indexOf("/storage/v1/");
        if (i < 0) {
            return null;
        }
        List<String> parts = new ArrayList<>();
        for (String s : p.substring(i + "/storage/v1/".length()).split("/")) {
            if (!s.isEmpty()) {
                parts.add(s);
            }
        }
        if (parts.isEmpty()) {
            return null;
        }
        int idx = 0;
        String root = parts.get(0);
        if (root.equals("object")) {
            idx = 1;
        } else if (root.equals("render")) {
            idx = 1;
            if (idx < parts.size() && parts.get(idx).equals("image")) {
                idx++;
            }
        } else {
            return null;
        }
        while (idx < parts.size()) {
            String t = parts.get(idx);
            if (t.equals("public") || t.equals("sign") || t.equals("authenticated")
                    || t.equals("list") || t.equals("info") || t.equals("upload")) {
                idx++;
            } else {
                break;
            }
        }
        return idx < parts.size() ? safeDecode(parts.get(idx)) : null;
    }

    // --------------------------------------------------------------- hints ---

    /** PostgREST 404 table hint → real table name, else null. */
    public static String hintTable(String body) {
        if (body == null) {
            return null;
        }
        Matcher m = HINT_TABLE.matcher(body);
        return m.find() ? m.group(1) : null;
    }

    /** PostgREST function hint → real function name, else null. */
    public static String hintFunction(String body) {
        if (body == null) {
            return null;
        }
        Matcher m = HINT_FUNCTION.matcher(body);
        return m.find() ? m.group(1) : null;
    }

    // ------------------------------------------------------------- scanning --

    /** All distinct JWTs appearing in a blob of text (body / header value). */
    public static List<String> findJwts(String text) {
        Set<String> out = new LinkedHashSet<>();
        if (text != null) {
            Matcher m = JWT.matcher(text);
            while (m.find()) {
                out.add(m.group());
            }
        }
        return new ArrayList<>(out);
    }

    /** All distinct project refs appearing in a blob of text. */
    public static List<String> findRefs(String text) {
        Set<String> out = new LinkedHashSet<>();
        if (text != null) {
            Matcher m = REF_IN_TEXT.matcher(text);
            while (m.find()) {
                out.add(m.group(1));
            }
        }
        return new ArrayList<>(out);
    }

    // ---------------------------------------------------------- credentials --

    /** Resolved credentials for an active check. Either field may be null. */
    public static final class Creds {
        public final String apikey;
        public final String bearer;

        Creds(String apikey, String bearer) {
            this.apikey = apikey;
            this.bearer = bearer;
        }

        /** The extension can run with an anon key OR any session token (spec §5). */
        public boolean usable() {
            return notBlank(apikey) || notBlank(bearer);
        }

        /** Bearer to send, defaulting to the apikey when no explicit bearer exists. */
        public String effectiveBearer() {
            return notBlank(bearer) ? bearer : apikey;
        }

        /** Apikey to send, defaulting to the bearer when no anon/apikey exists. */
        public String effectiveApikey() {
            return notBlank(apikey) ? apikey : bearer;
        }
    }

    /** Build an explicit credential pair (e.g. per-identity for the IDOR probe). */
    public static Creds creds(String apikey, String bearer) {
        return new Creds(apikey, bearer);
    }

    /**
     * Credential resolution per spec §5. Supabase's gateway accepts any valid
     * project JWT as {@code apikey}, so the extension works with only a session.
     */
    public static Creds credsFor(SupabaseInstance inst) {
        String anon = blankToNull(inst.anonKey);
        SessionUser active = inst.activeSession();
        String activeTok = active != null ? blankToNull(active.token) : null;
        String anySession = null;
        for (SessionUser s : inst.sessions) {
            if (notBlank(s.token)) {
                anySession = s.token;
                break;
            }
        }
        String apikey = anon != null ? anon : (activeTok != null ? activeTok : anySession);
        String bearer = activeTok != null ? activeTok : (anon != null ? anon : anySession);
        return new Creds(apikey, bearer);
    }

    // --------------------------------------------------------------- utils ---

    private static String firstSegment(String s) {
        int slash = s.indexOf('/');
        String seg = slash < 0 ? s : s.substring(0, slash);
        int q = seg.indexOf('?');
        return q < 0 ? seg : seg.substring(0, q);
    }

    private static String stripQuery(String path) {
        int q = path.indexOf('?');
        return q < 0 ? path : path.substring(0, q);
    }

    private static String safeDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return s;
        }
    }

    private static String optString(JsonObject o, String key) {
        return o.has(key) && o.get(key).isJsonPrimitive() ? o.get(key).getAsString() : null;
    }

    private static String blankToNull(String s) {
        return notBlank(s) ? s : null;
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }
}
