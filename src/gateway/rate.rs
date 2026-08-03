use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use super::GatewayLimits;

const WINDOW: Duration = Duration::from_secs(60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
const MAX_RATE_KEYS: usize = 100_000;

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<State>>,
    limits: GatewayLimits,
}

struct State {
    connections: HashMap<IpAddr, usize>,
    event_ip: HashMap<IpAddr, Counter>,
    event_pubkey: HashMap<String, Counter>,
    req_ip: HashMap<IpAddr, Counter>,
    last_cleanup: Instant,
}

struct Counter {
    started: Instant,
    count: u32,
}

pub struct ConnectionPermit {
    limiter: RateLimiter,
    ip: IpAddr,
}

impl RateLimiter {
    pub fn new(limits: GatewayLimits) -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                connections: HashMap::new(),
                event_ip: HashMap::new(),
                event_pubkey: HashMap::new(),
                req_ip: HashMap::new(),
                last_cleanup: Instant::now(),
            })),
            limits,
        }
    }

    pub fn connect(&self, ip: IpAddr) -> Option<ConnectionPermit> {
        let mut state = self.inner.lock().ok()?;
        let count = state.connections.entry(ip).or_default();
        if *count >= self.limits.max_connections_per_ip {
            return None;
        }
        *count += 1;
        Some(ConnectionPermit {
            limiter: self.clone(),
            ip,
        })
    }

    pub fn event_from_ip(&self, ip: IpAddr) -> bool {
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };
        state.cleanup();
        allow_ip(&mut state.event_ip, ip, self.limits.events_per_minute_ip)
    }

    pub fn event_from_pubkey(&self, pubkey: &str) -> bool {
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };
        state.cleanup();
        allow_string(
            &mut state.event_pubkey,
            pubkey,
            self.limits.events_per_minute_pubkey,
        )
    }

    pub fn req_from_ip(&self, ip: IpAddr) -> bool {
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };
        state.cleanup();
        allow_ip(&mut state.req_ip, ip, self.limits.req_per_minute_ip)
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let Ok(mut state) = self.limiter.inner.lock() else {
            return;
        };
        if let Some(count) = state.connections.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.connections.remove(&self.ip);
            }
        }
    }
}

fn allow_ip(map: &mut HashMap<IpAddr, Counter>, key: IpAddr, limit: u32) -> bool {
    if !map.contains_key(&key) && map.len() >= MAX_RATE_KEYS {
        return false;
    }
    allow_counter(map.entry(key).or_insert_with(new_counter), limit)
}

fn allow_string(map: &mut HashMap<String, Counter>, key: &str, limit: u32) -> bool {
    if !map.contains_key(key) && map.len() >= MAX_RATE_KEYS {
        return false;
    }
    allow_counter(map.entry(key.to_owned()).or_insert_with(new_counter), limit)
}

impl State {
    fn cleanup(&mut self) {
        if self.last_cleanup.elapsed() < CLEANUP_INTERVAL {
            return;
        }
        let now = Instant::now();
        self.event_ip
            .retain(|_, counter| now.duration_since(counter.started) < WINDOW);
        self.event_pubkey
            .retain(|_, counter| now.duration_since(counter.started) < WINDOW);
        self.req_ip
            .retain(|_, counter| now.duration_since(counter.started) < WINDOW);
        self.last_cleanup = now;
    }
}

fn new_counter() -> Counter {
    Counter {
        started: Instant::now(),
        count: 0,
    }
}

fn allow_counter(counter: &mut Counter, limit: u32) -> bool {
    if counter.started.elapsed() >= WINDOW {
        *counter = new_counter();
    }
    if counter.count >= limit {
        return false;
    }
    counter.count += 1;
    true
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use crate::gateway::GatewayLimits;

    use super::RateLimiter;

    #[test]
    fn rate_and_connection_limits_fail_closed_and_permits_release() {
        let limits = GatewayLimits {
            max_connections_per_ip: 1,
            events_per_minute_ip: 1,
            events_per_minute_pubkey: 1,
            req_per_minute_ip: 1,
            ..GatewayLimits::default()
        };
        let limiter = RateLimiter::new(limits);
        let ip = "127.0.0.1".parse::<IpAddr>().unwrap();
        let permit = limiter.connect(ip).unwrap();
        assert!(limiter.connect(ip).is_none());
        drop(permit);
        assert!(limiter.connect(ip).is_some());
        assert!(limiter.event_from_ip(ip));
        assert!(!limiter.event_from_ip(ip));
        assert!(limiter.event_from_pubkey("a"));
        assert!(!limiter.event_from_pubkey("a"));
        assert!(limiter.req_from_ip(ip));
        assert!(!limiter.req_from_ip(ip));
    }
}
