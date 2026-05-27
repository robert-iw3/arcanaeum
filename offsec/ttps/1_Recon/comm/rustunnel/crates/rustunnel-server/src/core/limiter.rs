use std::time::{Duration, Instant};

use dashmap::DashMap;
use uuid::Uuid;

/// Per-tunnel token-bucket state.
struct Bucket {
    /// Tokens currently available (fractional accumulation tracked via last_refill).
    tokens: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new(max_rps: u32) -> Self {
        Self {
            tokens: max_rps as f64,
            last_refill: Instant::now(),
        }
    }

    /// Refill tokens proportional to elapsed time, then attempt to consume one token.
    /// Returns `true` when a token was successfully consumed (request is allowed).
    fn try_consume(&mut self, max_rps: u32) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);

        // Accumulate tokens since last check, capped at the burst ceiling (== max_rps).
        let new_tokens = elapsed.as_secs_f64() * max_rps as f64;
        self.tokens = (self.tokens + new_tokens).min(max_rps as f64);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Global rate-limiter that maintains one token bucket per tunnel.
pub struct RateLimiter {
    buckets: DashMap<Uuid, Bucket>,
    /// How long a bucket may sit idle before being evicted (avoids unbounded growth).
    evict_after: Duration,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: DashMap::new(),
            evict_after: Duration::from_secs(300), // 5 minutes idle eviction
        }
    }

    /// Returns `true` when the request for `tunnel_id` is within the `max_rps` budget.
    /// Returns `false` when the request should be rate-limited.
    pub fn check_rate_limit(&self, tunnel_id: &Uuid, max_rps: u32) -> bool {
        self.buckets
            .entry(*tunnel_id)
            .or_insert_with(|| Bucket::new(max_rps))
            .try_consume(max_rps)
    }

    /// Remove buckets that have been idle longer than `evict_after`.
    /// Call this periodically (e.g. every minute) to reclaim memory.
    pub fn evict_idle(&self) {
        let now = Instant::now();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < self.evict_after);
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_max_rps_in_burst() {
        let limiter = RateLimiter::new();
        let id = Uuid::new_v4();

        // A fresh bucket starts full, so the first `max_rps` calls must succeed.
        for _ in 0..10 {
            assert!(limiter.check_rate_limit(&id, 10));
        }
        // The 11th call within the same instant should be denied.
        assert!(!limiter.check_rate_limit(&id, 10));
    }

    #[test]
    fn refills_over_time() {
        use std::thread::sleep;

        let limiter = RateLimiter::new();
        let id = Uuid::new_v4();

        // Drain all tokens.
        for _ in 0..5 {
            limiter.check_rate_limit(&id, 5);
        }
        assert!(!limiter.check_rate_limit(&id, 5));

        // Wait long enough to accumulate at least one token (1s / 5 rps = 200 ms each).
        sleep(Duration::from_millis(250));

        assert!(limiter.check_rate_limit(&id, 5));
    }

    #[test]
    fn separate_tunnels_are_independent() {
        let limiter = RateLimiter::new();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        // Drain tunnel A.
        for _ in 0..2 {
            limiter.check_rate_limit(&a, 2);
        }
        assert!(!limiter.check_rate_limit(&a, 2));

        // Tunnel B should be completely unaffected.
        assert!(limiter.check_rate_limit(&b, 2));
    }

    #[test]
    fn evict_idle_removes_stale_buckets() {
        let limiter = RateLimiter::new();
        let id = Uuid::new_v4();
        limiter.check_rate_limit(&id, 10);
        assert_eq!(limiter.buckets.len(), 1);

        // Manually backdate the last_refill to simulate idleness.
        limiter
            .buckets
            .entry(id)
            .and_modify(|b| b.last_refill = Instant::now() - Duration::from_secs(600));

        limiter.evict_idle();
        assert_eq!(limiter.buckets.len(), 0);
    }
}
