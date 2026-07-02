package com.supascan.net;

import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Token-bucket rate limiter + concurrency cap + global kill switch (spec §7.7).
 *
 * <p>{@link #acquire()} blocks until both a per-second token and a concurrency
 * permit are available, then returns a {@link Slot} the caller must release.
 * The slot remembers the exact semaphore it drew from, so changing the
 * concurrency cap mid-run never corrupts permits held by in-flight probes.
 */
public final class RateLimiter {

    private final Object bucketLock = new Object();
    private volatile int ratePerSec;
    private double tokens;
    private long lastRefillNanos;

    private volatile Semaphore concurrency;
    private volatile int maxConcurrency;

    private final AtomicBoolean stopped = new AtomicBoolean(false);

    public RateLimiter(int ratePerSec, int maxConcurrency) {
        this.ratePerSec = Math.max(1, ratePerSec);
        this.maxConcurrency = Math.max(1, maxConcurrency);
        this.concurrency = new Semaphore(this.maxConcurrency);
        this.tokens = this.ratePerSec;
        this.lastRefillNanos = System.nanoTime();
    }

    /** Apply new limits. A changed concurrency cap installs a fresh semaphore. */
    public synchronized void configure(int ratePerSec, int maxConcurrency) {
        this.ratePerSec = Math.max(1, ratePerSec);
        int mc = Math.max(1, maxConcurrency);
        if (mc != this.maxConcurrency) {
            this.maxConcurrency = mc;
            this.concurrency = new Semaphore(mc);
        }
        synchronized (bucketLock) {
            tokens = Math.min(tokens, this.ratePerSec);
        }
    }

    public boolean isStopped() {
        return stopped.get();
    }

    /** Trip the kill switch: in-flight {@link #acquire()} calls bail out. */
    public void stopAll() {
        stopped.set(true);
    }

    /** Re-arm after a stop, so a new run can proceed. */
    public void reset() {
        stopped.set(false);
    }

    /**
     * Blocks until a request may proceed. Returns {@code null} immediately if
     * the kill switch is set (caller must abort quietly).
     */
    public Slot acquire() throws InterruptedException {
        if (stopped.get()) {
            return null;
        }
        Semaphore sem = concurrency;
        sem.acquire();
        if (stopped.get()) {
            sem.release();
            return null;
        }
        try {
            while (true) {
                long sleepMs;
                synchronized (bucketLock) {
                    refill();
                    if (tokens >= 1d) {
                        tokens -= 1d;
                        return new Slot(sem);
                    }
                    double needed = 1d - tokens;
                    sleepMs = (long) Math.ceil(needed / ratePerSec * 1000d);
                }
                if (stopped.get()) {
                    sem.release();
                    return null;
                }
                Thread.sleep(Math.max(1, Math.min(sleepMs, 200)));
                if (stopped.get()) {
                    sem.release();
                    return null;
                }
            }
        } catch (InterruptedException e) {
            sem.release();
            throw e;
        }
    }

    private void refill() {
        long now = System.nanoTime();
        double elapsedSec = (now - lastRefillNanos) / 1_000_000_000d;
        lastRefillNanos = now;
        tokens = Math.min(ratePerSec, tokens + elapsedSec * ratePerSec);
    }

    /** A held concurrency permit. Idempotent {@link #release()}. */
    public static final class Slot {
        private final Semaphore sem;
        private final AtomicBoolean released = new AtomicBoolean(false);

        private Slot(Semaphore sem) {
            this.sem = sem;
        }

        public void release() {
            if (released.compareAndSet(false, true)) {
                sem.release();
            }
        }
    }
}
