package com.supascan.net;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.supascan.extract.Extract;
import com.supascan.registry.Registry;
import com.supascan.scope.Scope;

import java.util.Map;

/**
 * The single choke point for every active request. Enforces rate limiting + the
 * kill switch (§7.7) and Activity-log auditability (§7.8) before delegating to
 * {@code api.http().sendRequest}. Probes never call {@code api.http()} directly.
 *
 * <p>NB: the Burp-scope gate (§7.2) was removed at operator request — active
 * checks now run against whatever host the selected instance points to. The
 * {@code OUT_OF_SCOPE} result kind is retained but no longer produced here.
 */
public final class Http {

    private final MontoyaApi api;
    private final RateLimiter limiter;
    private final Registry registry;

    public Http(MontoyaApi api, RateLimiter limiter, Registry registry) {
        this.api = api;
        this.limiter = limiter;
        this.registry = registry;
    }

    /** Build (but do not send) a request carrying the resolved credentials. */
    public HttpRequest build(String method, String url, Extract.Creds creds,
                             Map<String, String> headers, String body) {
        HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod(method);
        if (creds != null) {
            String apikey = creds.effectiveApikey();
            String bearer = creds.effectiveBearer();
            if (apikey != null && !apikey.isBlank()) {
                req = req.withAddedHeader("apikey", apikey);
            }
            if (bearer != null && !bearer.isBlank()) {
                req = req.withAddedHeader("Authorization", "Bearer " + bearer);
            }
        }
        boolean hasContentType = false;
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                req = req.withAddedHeader(e.getKey(), e.getValue());
                if (e.getKey().equalsIgnoreCase("Content-Type")) {
                    hasContentType = true;
                }
            }
        }
        if (!req.hasHeader("Accept")) {
            req = req.withAddedHeader("Accept", "application/json");
        }
        if (body != null) {
            if (!hasContentType) {
                req = req.withAddedHeader("Content-Type", "application/json");
            }
            req = req.withBody(body);
        }
        return req;
    }

    /** Convenience: build + send. */
    public Result request(String method, String url, Extract.Creds creds,
                          Map<String, String> headers, String body, String note) {
        return send(build(method, url, creds, headers, body), note);
    }

    /**
     * Send with all guards. Aborts if the kill switch is set. Every attempt is
     * written to the Activity log.
     */
    public Result send(HttpRequest req, String note) {
        String url = req.url();

        // §7.7 kill switch.
        if (limiter.isStopped()) {
            return Result.stopped();
        }

        RateLimiter.Slot slot;
        try {
            slot = limiter.acquire();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Result.stopped();
        }
        if (slot == null) {
            return Result.stopped();
        }

        try {
            HttpRequestResponse rr = api.http().sendRequest(req);
            Integer status = rr.hasResponse() ? (int) rr.response().statusCode() : null;
            registry.logActivity(req.method(), url, status, note);
            api.logging().logToOutput("[probe] " + req.method() + " " + url + " -> " + status);
            return Result.ok(rr, status);
        } catch (RuntimeException e) {
            registry.logActivity(req.method(), url, null, "error: " + e.getMessage());
            api.logging().logToError("[probe] " + req.method() + " " + url + " failed: " + e.getMessage());
            return Result.error(e.getMessage());
        } finally {
            slot.release();
        }
    }

    /** Outcome of a guarded send. */
    public static final class Result {
        public enum Kind { OK, OUT_OF_SCOPE, STOPPED, ERROR }

        public final Kind kind;
        public final HttpRequestResponse rr;
        public final Integer status;
        public final String error;
        private String cachedBody;

        private Result(Kind kind, HttpRequestResponse rr, Integer status, String error) {
            this.kind = kind;
            this.rr = rr;
            this.status = status;
            this.error = error;
        }

        static Result ok(HttpRequestResponse rr, Integer status) {
            return new Result(Kind.OK, rr, status, null);
        }

        static Result outOfScope(String url) {
            return new Result(Kind.OUT_OF_SCOPE, null, null, Scope.OUT_OF_SCOPE_MESSAGE);
        }

        static Result stopped() {
            return new Result(Kind.STOPPED, null, null, "stopped");
        }

        static Result error(String msg) {
            return new Result(Kind.ERROR, null, null, msg);
        }

        public boolean isOk() {
            return kind == Kind.OK;
        }

        public boolean is2xx() {
            return status != null && status >= 200 && status < 300;
        }

        public String body() {
            if (cachedBody == null) {
                cachedBody = (rr != null && rr.hasResponse()) ? rr.response().bodyToString() : "";
            }
            return cachedBody;
        }

        public String header(String name) {
            if (rr != null && rr.hasResponse()) {
                return rr.response().headerValue(name);
            }
            return null;
        }
    }
}
