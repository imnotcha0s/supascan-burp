package com.supascan;

import burp.api.montoya.MontoyaApi;
import com.supascan.findings.Findings;
import com.supascan.net.Http;
import com.supascan.net.RateLimiter;
import com.supascan.probes.AuthProbe;
import com.supascan.probes.IdorProbe;
import com.supascan.probes.ReadProbe;
import com.supascan.probes.RolesProbe;
import com.supascan.probes.RpcProbe;
import com.supascan.probes.StorageProbe;
import com.supascan.probes.WriteProbe;
import com.supascan.registry.Registry;
import com.supascan.scope.Scope;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Wires the whole extension together and owns the shared services. Created once
 * in {@link SupaScanExtension#initialize}. All active checks run on {@link
 * #executor}; Swing marshals to the EDT itself.
 */
public final class AppContext {

    public final MontoyaApi api;
    public final Registry registry;
    public final Scope scope;
    public final RateLimiter limiter;
    public final Http http;
    public final Findings findings;

    public final ReadProbe readProbe;
    public final WriteProbe writeProbe;
    public final AuthProbe authProbe;
    public final RpcProbe rpcProbe;
    public final StorageProbe storageProbe;
    public final RolesProbe rolesProbe;
    public final IdorProbe idorProbe;

    private final ThreadPoolExecutor executor;

    public AppContext(MontoyaApi api) {
        this.api = api;
        this.registry = new Registry(api);
        this.scope = new Scope(api);
        this.limiter = new RateLimiter(
                registry.settings().maxRequestsPerSecond, registry.settings().maxConcurrency);
        this.http = new Http(api, limiter, registry);
        this.findings = new Findings(api, registry);

        this.readProbe = new ReadProbe(api, http, limiter, registry, findings);
        this.writeProbe = new WriteProbe(api, http, limiter, registry, findings);
        this.authProbe = new AuthProbe(api, http, registry, findings);
        this.rpcProbe = new RpcProbe(api, http, limiter, registry, findings);
        this.storageProbe = new StorageProbe(api, http, limiter, registry, findings);
        this.rolesProbe = new RolesProbe(api, http, limiter, registry, findings);
        this.idorProbe = new IdorProbe(api, http, limiter, registry, findings);

        int pool = Math.max(1, registry.settings().maxConcurrency);
        // NB: with an unbounded queue, corePoolSize must be > 0 or no worker is
        // ever created. allowCoreThreadTimeOut lets idle workers be reaped.
        this.executor = new ThreadPoolExecutor(
                pool, pool, 30L, TimeUnit.SECONDS, new LinkedBlockingQueue<>(),
                r -> {
                    Thread t = new Thread(r, "supascan-probe");
                    t.setDaemon(true);
                    return t;
                });
        this.executor.allowCoreThreadTimeOut(true);
    }

    /** Submit an active-check task. Callers gate on scope/creds before calling. */
    public void submit(Runnable task) {
        executor.submit(task);
    }

    /** Kill switch: stop probes and drop queued work (spec §7.7). */
    public void stopAll() {
        limiter.stopAll();
        executor.getQueue().clear();
    }

    /** Re-arm before a new run. */
    public void armForRun() {
        limiter.reset();
    }

    /** Apply rate-limit / concurrency settings changes. */
    public void applyLimits() {
        limiter.configure(registry.settings().maxRequestsPerSecond, registry.settings().maxConcurrency);
        int n = Math.max(1, registry.settings().maxConcurrency);
        // Order matters: ThreadPoolExecutor rejects core > max at any instant.
        if (n >= executor.getMaximumPoolSize()) {
            executor.setMaximumPoolSize(n);
            executor.setCorePoolSize(n);
        } else {
            executor.setCorePoolSize(n);
            executor.setMaximumPoolSize(n);
        }
    }

    public void shutdown() {
        limiter.stopAll();
        executor.shutdownNow();
    }
}
