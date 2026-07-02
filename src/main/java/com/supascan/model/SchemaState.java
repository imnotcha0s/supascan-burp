package com.supascan.model;

/** Result of an Accept-Profile schema reachability probe. */
public class SchemaState {
    public String name;
    public boolean exposed;
    /** "critical" | "high" | "medium" */
    public String sensitivity;
    public Integer status;
    /** Identity the probe ran as (anon or a user label). */
    public String testedAs;

    public SchemaState() {
    }

    public SchemaState(String name, String sensitivity) {
        this.name = name;
        this.sensitivity = sensitivity;
    }
}
