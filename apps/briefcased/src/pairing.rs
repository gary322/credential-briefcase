use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use base64::Engine as _;
use rand::RngCore as _;
use tokio::sync::Mutex;
use uuid::Uuid;

pub const NOISE_PARAMS: &str = "Noise_NNpsk0_25519_ChaChaPoly_SHA256";

#[derive(Debug)]
struct PairingSession {
    psk: [u8; 32],
    expires_at: Instant,
}

#[derive(Debug)]
pub struct PairingManager {
    ttl: Duration,
    sessions: Mutex<HashMap<Uuid, PairingSession>>,
}

impl PairingManager {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub async fn start(&self) -> (Uuid, String, Instant) {
        let mut psk = [0u8; 32];
        rand::rng().fill_bytes(&mut psk);

        let id = Uuid::new_v4();
        let expires_at = Instant::now() + self.ttl;
        let code = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(psk);

        let mut guard = self.sessions.lock().await;
        guard.retain(|_, s| s.expires_at > Instant::now());
        guard.insert(id, PairingSession { psk, expires_at });

        (id, code, expires_at)
    }

    pub async fn get_psk(&self, id: Uuid) -> Option<[u8; 32]> {
        let guard = self.sessions.lock().await;
        let s = guard.get(&id)?;
        if s.expires_at <= Instant::now() {
            return None;
        }
        Some(s.psk)
    }

    pub async fn consume(&self, id: Uuid) {
        let mut guard = self.sessions.lock().await;
        guard.remove(&id);
    }
}

pub fn noise_responder(psk: &[u8; 32]) -> anyhow::Result<snow::HandshakeState> {
    let params: snow::params::NoiseParams = NOISE_PARAMS.parse().context("parse noise params")?;
    let builder = snow::Builder::new(params)
        .psk(0, psk)
        .context("set noise psk")?;
    builder.build_responder().context("build responder")
}

#[cfg(test)]
pub fn noise_initiator(psk: &[u8; 32]) -> anyhow::Result<snow::HandshakeState> {
    let params: snow::params::NoiseParams = NOISE_PARAMS.parse().context("parse noise params")?;
    let builder = snow::Builder::new(params)
        .psk(0, psk)
        .context("set noise psk")?;
    builder.build_initiator().context("build initiator")
}

#[derive(Debug)]
pub struct SignerReplayCache {
    ttl: Duration,
    seen: Mutex<HashMap<String, Instant>>,
}

impl SignerReplayCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            seen: Mutex::new(HashMap::new()),
        }
    }

    pub async fn check_and_insert(&self, key: String) -> bool {
        let now = Instant::now();
        let mut guard = self.seen.lock().await;
        guard.retain(|_, t| *t + self.ttl > now);

        if guard.contains_key(&key) {
            return false;
        }
        guard.insert(key, now);
        true
    }
}
