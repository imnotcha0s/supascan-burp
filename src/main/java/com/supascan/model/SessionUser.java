package com.supascan.model;

/** An authenticated identity that active checks can run as. */
public class SessionUser {
    public String id;
    public String email;
    public String token;
    /** "signup" | "signin" | "manual" */
    public String source;
    public String createdAt;

    public SessionUser() {
    }

    public SessionUser(String id, String email, String token, String source, String createdAt) {
        this.id = id;
        this.email = email;
        this.token = token;
        this.source = source;
        this.createdAt = createdAt;
    }

    /** Short human label for UI / issue text. */
    public String label() {
        if (email != null && !email.isBlank()) {
            return email;
        }
        return id != null ? id : "user";
    }
}
