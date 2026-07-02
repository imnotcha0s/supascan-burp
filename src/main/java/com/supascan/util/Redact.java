package com.supascan.util;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Evidence redaction (spec §7.6). Masks emails, truncates tokens/JWTs, and
 * drops obvious secret-named columns. Applied by default; the operator can
 * disable it only via an explicit, logged opt-in.
 */
public final class Redact {

    private Redact() {
    }

    private static final Gson GSON = new Gson();

    private static final Pattern EMAIL =
            Pattern.compile("([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");
    private static final Pattern JWT =
            Pattern.compile("eyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{4,}");

    private static final Set<String> SECRET_KEYS = Set.of(
            "password", "passwd", "pwd", "token", "access_token", "refresh_token",
            "secret", "client_secret", "api_key", "apikey", "authorization",
            "service_role", "service_role_key", "private_key", "encryption_key",
            "session", "otp", "hashed_password", "encrypted_password", "salt");

    /** Redact a free-text blob (issue detail, header values, etc.). */
    public static String text(String s) {
        if (s == null) {
            return null;
        }
        String out = EMAIL.matcher(s).replaceAll("$1***@***");
        out = JWT.matcher(out).replaceAll(m -> truncate(m.group()));
        return out;
    }

    /** Apply redaction to a JSON row only when {@code enabled}. */
    public static String maybeJson(String json, boolean enabled) {
        return enabled ? json(json) : json;
    }

    /** Redact a JSON value structurally: mask secret keys and email/token values. */
    public static String json(String json) {
        if (json == null) {
            return null;
        }
        try {
            JsonElement e = JsonParser.parseString(json);
            return GSON.toJson(redact(e));
        } catch (RuntimeException ex) {
            return text(json);
        }
    }

    private static JsonElement redact(JsonElement e) {
        if (e.isJsonObject()) {
            JsonObject in = e.getAsJsonObject();
            JsonObject out = new JsonObject();
            for (Map.Entry<String, JsonElement> entry : in.entrySet()) {
                String key = entry.getKey();
                if (SECRET_KEYS.contains(key.toLowerCase(Locale.ROOT))) {
                    out.addProperty(key, "***redacted***");
                } else {
                    out.add(key, redact(entry.getValue()));
                }
            }
            return out;
        }
        if (e.isJsonArray()) {
            JsonArray in = e.getAsJsonArray();
            JsonArray out = new JsonArray();
            for (JsonElement item : in) {
                out.add(redact(item));
            }
            return out;
        }
        if (e.isJsonPrimitive() && e.getAsJsonPrimitive().isString()) {
            return new JsonPrimitive(text(e.getAsString()));
        }
        return e;
    }

    private static String truncate(String token) {
        if (token.length() <= 12) {
            return "***";
        }
        return token.substring(0, 6) + "…[" + token.length() + " chars]";
    }
}
