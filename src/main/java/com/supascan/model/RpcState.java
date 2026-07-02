package com.supascan.model;

/** Per-RPC probe state. */
public class RpcState {
    public String name;
    public Integer status;
    public boolean exposed;
    /** Network/secret-capable names flagged for manual SSRF/secret review. */
    public boolean elevated;

    public RpcState() {
    }

    public RpcState(String name) {
        this.name = name;
    }
}
