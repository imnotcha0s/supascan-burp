package com.supascan.probes;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Built-in discovery wordlists and name classifiers (spec §6). */
public final class Wordlists {

    private Wordlists() {
    }

    /** ~65 common table names. */
    public static final List<String> TABLES = List.of(
            "users", "user", "profiles", "profile", "accounts", "account", "customers", "members",
            "orders", "order", "products", "product", "payments", "transactions", "invoices", "subscriptions",
            "messages", "chats", "conversations", "posts", "comments", "likes", "follows", "notifications",
            "sessions", "tokens", "api_keys", "secrets", "settings", "config", "logs", "audit_logs", "events",
            "files", "documents", "images", "uploads", "media", "attachments",
            "teams", "organizations", "orgs", "roles", "permissions", "groups",
            "contacts", "leads", "companies", "employees", "tasks", "projects", "boards", "cards", "todos",
            "categories", "tags", "reviews", "ratings", "favorites", "carts", "wishlists",
            "addresses", "emails", "credentials", "password_resets", "verification_tokens", "refresh_tokens",
            "admins", "admin");

    /** ~55 common/dangerous RPC names. */
    public static final List<String> RPCS = List.of(
            "get_user", "get_users", "current_user", "current_user_id", "whoami", "me", "get_current_user",
            "is_admin", "has_role", "get_role", "set_role", "make_admin", "promote_user", "grant_admin",
            "check_permission", "get_secret", "get_secrets", "get_api_key", "get_token", "get_config",
            "set_config", "get_env", "env", "version", "healthcheck", "ping", "test", "debug",
            "http", "http_get", "http_post", "fetch", "url_get", "exec_sql", "execute_sql", "run_sql",
            "pg_read_file", "pg_ls_dir", "read_file", "list_files", "decrypt", "encrypt", "vault_decrypt",
            "vault_read", "send_email", "send_sms", "reset_password", "create_user", "delete_user",
            "list_users", "get_all_users", "dump", "backup", "transfer", "charge", "get_balance");

    /** Common storage bucket names. */
    public static final List<String> BUCKETS = List.of(
            "avatars", "public", "uploads", "files", "images", "documents", "media", "photos", "videos",
            "attachments", "assets", "profile-pictures", "user-uploads", "backups", "private", "temp",
            "exports", "imports", "thumbnails", "banners");

    /** Privileged schemas with sensitivity (spec §6.6). Insertion order = probe order. */
    public static final Map<String, String> SCHEMAS = buildSchemas();

    private static Map<String, String> buildSchemas() {
        Map<String, String> m = new LinkedHashMap<>();
        for (String s : new String[] {"auth", "vault", "pgsodium", "secrets"}) {
            m.put(s, "critical");
        }
        for (String s : new String[] {"storage", "supabase_functions", "net", "realtime",
                "private", "internal", "admin", "pgbouncer"}) {
            m.put(s, "high");
        }
        for (String s : new String[] {"graphql", "extensions", "information_schema", "pg_catalog"}) {
            m.put(s, "medium");
        }
        return m;
    }

    // ---- classifiers ----

    /** Sensitive tables → HIGH severity for anon-read findings. */
    public static boolean isSensitiveTable(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        for (String k : new String[] {"user", "account", "customer", "member", "admin", "secret",
                "credential", "password", "payment", "card", "invoice", "billing", "profile", "email",
                "phone", "address", "auth", "private", "message", "order", "subscription", "api_key",
                "token", "ssn", "identity"}) {
            if (n.contains(k)) {
                return true;
            }
        }
        return false;
    }

    /** Token/secret tables → account-takeover primitive (critical-class). */
    public static boolean isTokenTable(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        for (String k : new String[] {"token", "otp", "password_reset", "reset_password", "verification",
                "verify", "magic", "confirmation", "one_time", "2fa", "mfa", "recovery"}) {
            if (n.contains(k)) {
                return true;
            }
        }
        return false;
    }

    /** RPCs whose names imply network/secret access → elevated manual review. */
    public static boolean isElevatedRpc(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        for (String k : new String[] {"http", "fetch", "url", "vault", "secret", "decrypt", "curl", "request"}) {
            if (n.contains(k)) {
                return true;
            }
        }
        return false;
    }

    /** Parse a custom wordlist textarea/file (newline- or comma-separated). */
    public static List<String> parse(String raw) {
        List<String> out = new ArrayList<>();
        if (raw == null) {
            return out;
        }
        for (String line : raw.split("[\\r\\n,]+")) {
            String t = line.trim();
            if (!t.isEmpty() && !out.contains(t)) {
                out.add(t);
            }
        }
        return out;
    }
}
