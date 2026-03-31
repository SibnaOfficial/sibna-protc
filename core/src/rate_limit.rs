#![allow(missing_docs)]
//! Rate Limiting and DoS Protection - Hardened Edition
//!
//! Implements rate limiting for cryptographic operations to prevent
//! brute force attacks and resource exhaustion.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use std::sync::Arc;

/// Rate limiter for cryptographic operations
#[derive(Clone)]
pub struct RateLimiter {
    /// Operation limits configuration
    limits: Arc<RwLock<HashMap<String, OperationLimit>>>,
    /// Current counters per client
    counters: Arc<RwLock<HashMap<String, ClientCounter>>>,
    /// Global rate limit enabled
    global_enabled: bool,
    /// Global requests per second
    global_rps: u32,
    /// Global counter
    global_counter: Arc<RwLock<GlobalCounter>>,
}

/// Limit configuration for an operation type
#[derive(Clone, Debug)]
pub struct OperationLimit {
    /// Maximum operations per second
    pub max_per_second: u32,
    /// Maximum operations per minute
    pub max_per_minute: u32,
    /// Maximum operations per hour
    pub max_per_hour: u32,
    /// Maximum operations per day
    pub max_per_day: u32,
    /// Cooldown duration after limit exceeded
    pub cooldown: Duration,
    /// Burst size (allow short bursts)
    pub burst_size: u32,
}

impl Default for OperationLimit {
    fn default() -> Self {
        Self {
            max_per_second: 10,
            max_per_minute: 100,
            max_per_hour: 1000,
            max_per_day: 10000,
            cooldown: Duration::from_secs(60),
            burst_size: 5,
        }
    }
}

/// Counter for a specific client
#[derive(Clone, Debug)]
struct ClientCounter {
    /// Operations in current second
    second_count: u32,
    /// Operations in current minute
    minute_count: u32,
    /// Operations in current hour
    hour_count: u32,
    /// Operations in current day
    day_count: u32,
    /// Last second reset
    last_second: Instant,
    /// Last minute reset
    last_minute: Instant,
    /// Last hour reset
    last_hour: Instant,
    /// Last day reset
    last_day: Instant,
    /// Cooldown end time (if any)
    cooldown_until: Option<Instant>,
    /// Burst tokens available
    burst_tokens: u32,
    /// Last token refill
    last_refill: Instant,
}

impl Default for ClientCounter {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            second_count: 0,
            minute_count: 0,
            hour_count: 0,
            day_count: 0,
            last_second: now,
            last_minute: now,
            last_hour: now,
            last_day: now,
            cooldown_until: None,
            burst_tokens: 0, // Tokens are granted on first refill call
            last_refill: now.checked_sub(std::time::Duration::from_secs(60)).unwrap_or(now),
        }
    }
}

/// Global rate limit counter
#[derive(Clone, Debug)]
struct GlobalCounter {
    /// Request count in current second
    count: u32,
    /// Last reset time
    last_reset: Instant,
}

impl Default for GlobalCounter {
    fn default() -> Self {
        Self {
            count: 0,
            last_reset: Instant::now(),
        }
    }
}

/// Rate limit error
#[derive(Clone, Debug)]
pub enum RateLimitError {
    /// Rate limit exceeded
    RateExceeded {
        operation: String,
        limit_type: String,
        retry_after: Duration,
    },
    /// Client is in cooldown period
    CooldownActive(Duration),
    /// Unknown operation type
    UnknownOperation(String),
    /// Global rate limit exceeded
    GlobalRateExceeded,
    /// Burst limit exceeded
    BurstExceeded,
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateExceeded { operation, limit_type, retry_after } => {
                write!(f, "Rate limit exceeded for {} ({}). Retry after {:?}s", 
                       operation, limit_type, retry_after.as_secs())
            }
            Self::CooldownActive(remaining) => {
                write!(f, "Cooldown active. Retry after {:?}s", remaining.as_secs())
            }
            Self::UnknownOperation(op) => {
                write!(f, "Unknown operation: {}", op)
            }
            Self::GlobalRateExceeded => {
                write!(f, "Global rate limit exceeded")
            }
            Self::BurstExceeded => {
                write!(f, "Burst limit exceeded")
            }
        }
    }
}

impl std::error::Error for RateLimitError {}

/// Remaining quota information
#[derive(Clone, Debug)]
pub struct RemainingQuota {
    /// Remaining operations this second
    pub per_second: u32,
    /// Remaining operations this minute
    pub per_minute: u32,
    /// Remaining operations this hour
    pub per_hour: u32,
    /// Remaining operations this day
    pub per_day: u32,
    /// Remaining burst tokens
    pub burst_tokens: u32,
    /// Whether in cooldown
    pub in_cooldown: bool,
}

impl RateLimiter {
    /// Create a new rate limiter with default limits
    pub fn new() -> Self {
        let mut limits = HashMap::new();
        
        // Decryption operations (expensive)
        limits.insert("decrypt".to_string(), OperationLimit {
            max_per_second: 5,
            max_per_minute: 50,
            max_per_hour: 500,
            max_per_day: 5000,
            cooldown: Duration::from_secs(120),
            burst_size: 5,
        });
        
        // Handshake operations (very expensive)
        limits.insert("handshake".to_string(), OperationLimit {
            max_per_second: 1,
            max_per_minute: 10,
            max_per_hour: 100,
            max_per_day: 1000,
            cooldown: Duration::from_secs(300),
            burst_size: 2,
        });
        
        // Encryption operations (cheaper)
        limits.insert("encrypt".to_string(), OperationLimit {
            max_per_second: 20,
            max_per_minute: 200,
            max_per_hour: 2000,
            max_per_day: 20000,
            cooldown: Duration::from_secs(30),
            burst_size: 10,
        });
        
        // Key operations (very sensitive)
        limits.insert("key_gen".to_string(), OperationLimit {
            max_per_second: 2,
            max_per_minute: 20,
            max_per_hour: 100,
            max_per_day: 1000,
            cooldown: Duration::from_secs(600),
            burst_size: 2,
        });

        // Session creation
        limits.insert("create_session".to_string(), OperationLimit {
            max_per_second: 3,
            max_per_minute: 30,
            max_per_hour: 300,
            max_per_day: 3000,
            cooldown: Duration::from_secs(60),
            burst_size: 5,
        });

        Self {
            limits: Arc::new(RwLock::new(limits)),
            counters: Arc::new(RwLock::new(HashMap::new())),
            global_enabled: true,
            global_rps: 100,
            global_counter: Arc::new(RwLock::new(GlobalCounter::default())),
        }
    }

    /// Check if an operation is allowed
    ///
    /// # Arguments
    /// * `operation` - The operation type (decrypt, encrypt, handshake, etc.)
    /// * `client_id` - Unique identifier for the client
    ///
    /// # Returns
    /// `Ok(())` if allowed, `Err(RateLimitError)` if rate limited
    pub fn check(&self, operation: &str, client_id: &str) -> Result<(), RateLimitError> {
        // Check global rate limit first
        if self.global_enabled {
            self.check_global()?;
        }

        let limits = self.limits.read();
        let limit = limits.get(operation)
            .ok_or_else(|| RateLimitError::UnknownOperation(operation.to_string()))?;
        
        let mut counters = self.counters.write();
        let counter = counters.entry(client_id.to_string()).or_default();
        let now = Instant::now();
        
        // Check cooldown
        if let Some(cooldown_end) = counter.cooldown_until {
            if now < cooldown_end {
                let remaining = cooldown_end.duration_since(now);
                return Err(RateLimitError::CooldownActive(remaining));
            }
            counter.cooldown_until = None;
        }
        
        // Update counters
        self.update_counters(counter, limit, now);
        
        // Refill burst tokens
        self.refill_burst_tokens(counter, limit, now);
        
        // Check burst limit
        if counter.burst_tokens == 0 {
            counter.cooldown_until = Some(now + limit.cooldown);
            return Err(RateLimitError::BurstExceeded);
        }
        
        // Check rate limits
        if counter.second_count >= limit.max_per_second {
            counter.cooldown_until = Some(now + limit.cooldown);
            return Err(RateLimitError::RateExceeded {
                operation: operation.to_string(),
                limit_type: "per_second".to_string(),
                retry_after: limit.cooldown,
            });
        }
        
        if counter.minute_count >= limit.max_per_minute {
            counter.cooldown_until = Some(now + limit.cooldown);
            return Err(RateLimitError::RateExceeded {
                operation: operation.to_string(),
                limit_type: "per_minute".to_string(),
                retry_after: limit.cooldown,
            });
        }
        
        if counter.hour_count >= limit.max_per_hour {
            counter.cooldown_until = Some(now + limit.cooldown);
            return Err(RateLimitError::RateExceeded {
                operation: operation.to_string(),
                limit_type: "per_hour".to_string(),
                retry_after: limit.cooldown,
            });
        }
        
        if counter.day_count >= limit.max_per_day {
            counter.cooldown_until = Some(now + limit.cooldown);
            return Err(RateLimitError::RateExceeded {
                operation: operation.to_string(),
                limit_type: "per_day".to_string(),
                retry_after: limit.cooldown,
            });
        }
        
        // Increment counters and consume burst token
        counter.second_count += 1;
        counter.minute_count += 1;
        counter.hour_count += 1;
        counter.day_count += 1;
        counter.burst_tokens -= 1;
        
        Ok(())
    }

    /// Check global rate limit
    fn check_global(&self) -> Result<(), RateLimitError> {
        let mut counter = self.global_counter.write();
        let now = Instant::now();

        // Reset if second has passed
        if now.duration_since(counter.last_reset) >= Duration::from_secs(1) {
            counter.count = 0;
            counter.last_reset = now;
        }

        if counter.count >= self.global_rps {
            return Err(RateLimitError::GlobalRateExceeded);
        }

        counter.count += 1;
        Ok(())
    }

    /// Update counters based on time elapsed
    fn update_counters(&self, counter: &mut ClientCounter, _limit: &OperationLimit, now: Instant) {
        // Reset second counter
        if now.duration_since(counter.last_second) >= Duration::from_secs(1) {
            counter.second_count = 0;
            counter.last_second = now;
        }
        
        // Reset minute counter
        if now.duration_since(counter.last_minute) >= Duration::from_secs(60) {
            counter.minute_count = 0;
            counter.last_minute = now;
        }
        
        // Reset hour counter
        if now.duration_since(counter.last_hour) >= Duration::from_secs(3600) {
            counter.hour_count = 0;
            counter.last_hour = now;
        }

        // Reset day counter
        if now.duration_since(counter.last_day) >= Duration::from_secs(86400) {
            counter.day_count = 0;
            counter.last_day = now;
        }
    }

    /// Refill burst tokens
    fn refill_burst_tokens(&self, counter: &mut ClientCounter, limit: &OperationLimit, now: Instant) {
        let elapsed = now.duration_since(counter.last_refill);
        let tokens_to_add = (elapsed.as_millis() as u32 * limit.burst_size) / 1000;
        
        if tokens_to_add > 0 {
            counter.burst_tokens = (counter.burst_tokens + tokens_to_add).min(limit.burst_size);
            counter.last_refill = now;
        }
    }

    /// Reset all counters for a client
    pub fn reset(&self, client_id: &str) {
        let mut counters = self.counters.write();
        counters.remove(client_id);
    }

    /// Add a custom operation limit
    pub fn add_limit(&self, operation: String, limit: OperationLimit) {
        let mut limits = self.limits.write();
        limits.insert(operation, limit);
    }

    /// Get remaining quota for an operation
    pub fn remaining(&self, operation: &str, client_id: &str) -> Option<RemainingQuota> {
        let limits = self.limits.read();
        let limit = limits.get(operation)?;
        
        let mut counters = self.counters.write();
        let counter = counters.entry(client_id.to_string()).or_default();
        let now = Instant::now();
        
        self.update_counters(counter, limit, now);
        self.refill_burst_tokens(counter, limit, now);
        
        Some(RemainingQuota {
            per_second: limit.max_per_second.saturating_sub(counter.second_count),
            per_minute: limit.max_per_minute.saturating_sub(counter.minute_count),
            per_hour: limit.max_per_hour.saturating_sub(counter.hour_count),
            per_day: limit.max_per_day.saturating_sub(counter.day_count),
            burst_tokens: counter.burst_tokens,
            in_cooldown: counter.cooldown_until.map(|t| t > now).unwrap_or(false),
        })
    }

    /// Get rate limiter statistics
    pub fn stats(&self) -> RateLimiterStats {
        let counters = self.counters.read();
        RateLimiterStats {
            total_clients: counters.len(),
            in_cooldown: counters.values().filter(|c| c.cooldown_until.is_some()).count(),
        }
    }

    /// Enable/disable global rate limiting.
    /// Must be called before the limiter is shared across threads.
    /// Call via: `rate_limiter.write().set_global_enabled(false);`
    pub fn set_global_enabled(&mut self, enabled: bool) {
        self.global_enabled = enabled;
    }

    /// Set global requests-per-second limit.
    /// Must be called before the limiter is shared across threads.
    /// Call via: `rate_limiter.write().set_global_rps(200);`
    pub fn set_global_rps(&mut self, rps: u32) {
        self.global_rps = rps;
    }

    /// Prune inactive clients
    pub fn prune_inactive(&self, max_age: Duration) {
        let mut counters = self.counters.write();
        let now = Instant::now();
        counters.retain(|_, c| {
            now.duration_since(c.last_second) < max_age
        });
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Rate limiter statistics
#[derive(Clone, Debug)]
pub struct RateLimiterStats {
    /// Total number of tracked clients
    pub total_clients: usize,
    /// Number of clients in cooldown
    pub in_cooldown: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_basic() {
        let limiter = RateLimiter::new();
        
        // Should allow first request
        assert!(limiter.check("decrypt", "client1").is_ok());
    }

    #[test]
    fn test_rate_limiter_limit() {
        let limiter = RateLimiter::new();
        
        // Exhaust per-second limit (5 for decrypt)
        for _ in 0..5 {
            assert!(limiter.check("decrypt", "client1").is_ok());
        }
        
        // Should now be limited
        assert!(limiter.check("decrypt", "client1").is_err());
    }

    #[test]
    fn test_rate_limiter_different_clients() {
        let limiter = RateLimiter::new();
        
        // Exhaust limit for client1
        for _ in 0..5 {
            limiter.check("decrypt", "client1").unwrap();
        }
        
        // client1 should be limited
        assert!(limiter.check("decrypt", "client1").is_err());
        
        // client2 should still be allowed
        assert!(limiter.check("decrypt", "client2").is_ok());
    }

    #[test]
    fn test_remaining_quota() {
        let limiter = RateLimiter::new();
        
        limiter.check("decrypt", "client1").unwrap();
        
        let remaining = limiter.remaining("decrypt", "client1").unwrap();
        assert_eq!(remaining.per_second, 4);
        assert!(!remaining.in_cooldown);
    }

    #[test]
    fn test_unknown_operation() {
        let limiter = RateLimiter::new();
        
        let result = limiter.check("unknown_op", "client1");
        assert!(matches!(result, Err(RateLimitError::UnknownOperation(_))));
    }

    #[test]
    fn test_reset() {
        let limiter = RateLimiter::new();
        
        // Exhaust limit
        for _ in 0..5 {
            limiter.check("decrypt", "client1").unwrap();
        }
        
        // Should be limited
        assert!(limiter.check("decrypt", "client1").is_err());
        
        // Reset
        limiter.reset("client1");
        
        // Should be allowed again
        assert!(limiter.check("decrypt", "client1").is_ok());
    }

    #[test]
    fn test_global_rate_limit() {
        let mut limiter = RateLimiter::new();
        limiter.set_global_rps(20);
        
        // Should allow requests under limit
        for _ in 0..10 {
            assert!(limiter.check("encrypt", "client1").is_ok());
        }
    }

    #[test]
    fn test_stats() {
        let limiter = RateLimiter::new();
        
        limiter.check("decrypt", "client1").unwrap();
        limiter.check("decrypt", "client2").unwrap();
        
        let stats = limiter.stats();
        assert_eq!(stats.total_clients, 2);
    }
}
