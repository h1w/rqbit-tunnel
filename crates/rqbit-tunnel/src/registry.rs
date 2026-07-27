use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering},
    },
};

use arc_swap::ArcSwap;
use librqbit::{
    TunnelPrivateKey, TunnelPublicKey, TunnelServerAuthorizer, TunnelServerSession,
    TunnelTrafficDirection, tunnel_generate_keypair,
};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    model::{TrafficTotals, UserRecord, UserSnapshot},
    store::{ServerStore, StoreError, current_unix_seconds},
};

/// The sole handoff of a newly generated client private key.
///
/// This deliberately has no serialization or debug implementation. Callers must
/// write the key to an explicit enrollment bundle immediately or drop it.
pub struct CreatedUser {
    pub user: UserRecord,
    pub client_private_key: TunnelPrivateKey,
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("user {0} does not exist")]
    UserNotFound(Uuid),
}

/// Durable users plus the dynamic, lock-free admission map used by the tunnel server.
pub struct UserRegistry {
    store: ServerStore,
    by_key: ArcSwap<HashMap<TunnelPublicKey, Arc<UserMeter>>>,
    users: RwLock<HashMap<Uuid, ManagedUser>>,
    mutations: Mutex<()>,
}

struct ManagedUser {
    record: UserRecord,
    counters: Arc<UserCounters>,
    meter: Arc<UserMeter>,
    retired_meters: Vec<Arc<UserMeter>>,
}


struct UserMeter {
    counters: Arc<UserCounters>,
    cancellation: CancellationToken,
    connected: AtomicUsize,
    last_seen: AtomicI64,
}

struct UserCounters {
    state: ArcSwap<MeterCounters>,
}

struct MeterCounters {
    total_upload: AtomicU64,
    total_download: AtomicU64,
    delta_upload: AtomicU64,
    delta_download: AtomicU64,
    dirty: AtomicBool,
}

impl UserRegistry {
    pub async fn open(store: ServerStore) -> Result<Self, RegistryError> {
        let stored_users = store.load_users().await?;
        let mut users = HashMap::with_capacity(stored_users.len());

        for stored in stored_users {
            let user_id = stored.record.id;
            let counters = Arc::new(UserCounters::new(stored.traffic));
            users.insert(
                user_id,
                ManagedUser {
                    record: stored.record,
                    counters: Arc::clone(&counters),
                    meter: Arc::new(UserMeter::new(counters)),
                    retired_meters: Vec::new(),
                },
            );
        }

        Ok(Self {
            store,
            by_key: ArcSwap::from_pointee(enabled_key_map(&users)),
            users: RwLock::new(users),
            mutations: Mutex::new(()),
        })
    }

    pub async fn create_user(
        &self,
        name: impl Into<String>,
    ) -> Result<CreatedUser, RegistryError> {
        let _mutation = self.mutations.lock().await;
        let (client_private_key, client_public_key) = tunnel_generate_keypair();
        let user = UserRecord {
            id: Uuid::new_v4(),
            name: name.into(),
            public_key: client_public_key.0,
            enabled: true,
            created_at: current_unix_seconds()?,
            reset_at: None,
        };

        self.store.create_user(&user).await?;
        let counters = Arc::new(UserCounters::new(TrafficTotals::default()));

        let mut users = self.users.write().await;
        users.insert(
            user.id,
            ManagedUser {
                record: user.clone(),
                counters: Arc::clone(&counters),
                meter: Arc::new(UserMeter::new(counters)),
                retired_meters: Vec::new(),
            },
        );
        self.publish_enabled_key_map(&users);

        Ok(CreatedUser {
            user,
            client_private_key,
        })
    }

    pub async fn delete_user(&self, user_id: Uuid) -> Result<(), RegistryError> {
        let _mutation = self.mutations.lock().await;
        {
            let users = self.users.read().await;
            if !users.contains_key(&user_id) {
                return Err(RegistryError::UserNotFound(user_id));
            }
        }

        self.store.delete_user(user_id).await?;

        let removed = {
            let mut users = self.users.write().await;
            let removed = users
                .remove(&user_id)
                .ok_or(RegistryError::UserNotFound(user_id))?;
            self.publish_enabled_key_map(&users);
            removed
        };

        for meter in removed.meters() {
            meter.cancel();
        }

        Ok(())
    }

    pub async fn flush(&self) -> Result<(), RegistryError> {
        let _mutation = self.mutations.lock().await;
        let counters = {
            let users = self.users.read().await;
            users
                .iter()
                .map(|(user_id, user)| (*user_id, Arc::clone(&user.counters)))
                .collect::<Vec<_>>()
        };

        for (user_id, counters) in counters {
            self.flush_counters(user_id, &counters).await?;
        }

        Ok(())
    }

    pub async fn reset_traffic(&self, user_id: Uuid) -> Result<(), RegistryError> {
        let _mutation = self.mutations.lock().await;
        let reset_at = current_unix_seconds()?;
        {
            let users = self.users.read().await;
            if !users.contains_key(&user_id) {
                return Err(RegistryError::UserNotFound(user_id));
            }
        }

        // The mutation gate prevents a flush from persisting the old counter
        // state after this transaction. Swapping counter state only after a
        // successful commit gives reset one linearization point: payloads that
        // acquired the old state are reset; later payloads use the new state.
        self.store.reset_traffic(user_id, reset_at).await?;

        let mut users = self.users.write().await;
        let user = users
            .get_mut(&user_id)
            .ok_or(RegistryError::UserNotFound(user_id))?;
        user.reset_counters();
        user.record.reset_at = Some(reset_at);
        Ok(())
    }

    pub async fn set_enabled(&self, user_id: Uuid, enabled: bool) -> Result<(), RegistryError> {
        let _mutation = self.mutations.lock().await;
        let counters = {
            let users = self.users.read().await;
            let user = users
                .get(&user_id)
                .ok_or(RegistryError::UserNotFound(user_id))?;
            if user.record.enabled == enabled {
                return Ok(());
            }
            Arc::clone(&user.counters)
        };

        self.flush_counters(user_id, &counters).await?;
        self.store.set_enabled(user_id, enabled).await?;

        let meter_to_cancel = {
            let mut users = self.users.write().await;
            let user = users
                .get_mut(&user_id)
                .ok_or(RegistryError::UserNotFound(user_id))?;
            user.record.enabled = enabled;
            if enabled {
                user.replace_active_meter();
                self.publish_enabled_key_map(&users);
                None
            } else {
                let meter = Arc::clone(&user.meter);
                self.publish_enabled_key_map(&users);
                Some(meter)
            }
        };

        if let Some(meter) = meter_to_cancel {
            meter.cancel();
        }

        Ok(())
    }

    pub async fn snapshot(&self, user_id: Uuid) -> Result<UserSnapshot, RegistryError> {
        let users = self.users.read().await;
        let user = users
            .get(&user_id)
            .ok_or(RegistryError::UserNotFound(user_id))?;

        Ok(user.snapshot())
    }

    fn publish_enabled_key_map(&self, users: &HashMap<Uuid, ManagedUser>) {
        self.by_key.store(Arc::new(enabled_key_map(users)));
    }

    async fn flush_counters(
        &self,
        user_id: Uuid,
        counters: &UserCounters,
    ) -> Result<(), RegistryError> {
        let (state, delta) = counters.detach_for_flush();
        if delta == TrafficTotals::default() {
            return Ok(());
        }

        if let Err(error) = self.store.increment_traffic(user_id, delta).await {
            state.restore_dirty_delta(delta);
            return Err(error.into());
        }

        Ok(())
    }
}

impl TunnelServerAuthorizer for UserRegistry {
    fn authorize(&self, key: &TunnelPublicKey) -> Option<Arc<dyn TunnelServerSession>> {
        self.by_key
            .load()
            .get(key)
            .cloned()
            .map(|meter| meter as Arc<dyn TunnelServerSession>)
    }
}

impl ManagedUser {
    fn meters(&self) -> Vec<Arc<UserMeter>> {
        let mut meters = Vec::with_capacity(self.retired_meters.len() + 1);
        meters.push(Arc::clone(&self.meter));
        meters.extend(self.retired_meters.iter().cloned());
        meters
    }

    fn replace_active_meter(&mut self) {
        self.retired_meters.push(Arc::clone(&self.meter));
        self.meter = Arc::new(UserMeter::new(Arc::clone(&self.counters)));
    }

    fn reset_counters(&mut self) {
        self.counters.reset();
    }

    fn snapshot(&self) -> UserSnapshot {
        let traffic = self.counters.traffic();
        let mut connected = self.meter.connected();
        let mut last_seen = self.meter.last_seen();

        for retired in &self.retired_meters {
            connected = connected.saturating_add(retired.connected());
            last_seen = last_seen.max(retired.last_seen());
        }

        UserSnapshot {
            id: self.record.id,
            name: self.record.name.clone(),
            enabled: self.record.enabled,
            connected,
            traffic,
            last_seen,
        }
    }
}

impl UserMeter {
    fn new(counters: Arc<UserCounters>) -> Self {
        Self {
            counters,
            cancellation: CancellationToken::new(),
            connected: AtomicUsize::new(0),
            last_seen: AtomicI64::new(0),
        }
    }

    fn cancel(&self) {
        self.cancellation.cancel();
    }

    fn connected(&self) -> usize {
        self.connected.load(Ordering::Relaxed)
    }

    fn last_seen(&self) -> Option<i64> {
        let timestamp = self.last_seen.load(Ordering::Relaxed);
        (timestamp > 0).then_some(timestamp)
    }

    fn traffic(&self) -> TrafficTotals {
        self.counters.traffic()
    }
}

impl UserCounters {
    fn new(traffic: TrafficTotals) -> Self {
        Self {
            state: ArcSwap::from_pointee(MeterCounters::new(traffic)),
        }
    }

    fn detach_for_flush(&self) -> (Arc<MeterCounters>, TrafficTotals) {
        let state = self.state.load_full();
        let delta = state.detach_dirty_delta();
        (state, delta)
    }

    fn record_payload(&self, direction: TunnelTrafficDirection, bytes: usize) {
        self.state.load().record_payload(direction, bytes);
    }

    fn reset(&self) {
        self.state
            .store(Arc::new(MeterCounters::new(TrafficTotals::default())));
    }

    fn traffic(&self) -> TrafficTotals {
        self.state.load().traffic()
    }
}

impl MeterCounters {
    fn new(traffic: TrafficTotals) -> Self {
        Self {
            total_upload: AtomicU64::new(traffic.upload),
            total_download: AtomicU64::new(traffic.download),
            delta_upload: AtomicU64::new(0),
            delta_download: AtomicU64::new(0),
            dirty: AtomicBool::new(false),
        }
    }

    fn detach_dirty_delta(&self) -> TrafficTotals {
        // `dirty` is a scheduling hint. A reset swaps the entire counter state,
        // so a clear flag can never decide whether the current state has data.
        self.dirty.store(false, Ordering::Relaxed);

        TrafficTotals {
            upload: self.delta_upload.swap(0, Ordering::AcqRel),
            download: self.delta_download.swap(0, Ordering::AcqRel),
        }
    }

    fn record_payload(&self, direction: TunnelTrafficDirection, bytes: usize) {
        let bytes = bytes as u64;

        match direction {
            TunnelTrafficDirection::Upload => {
                self.total_upload.fetch_add(bytes, Ordering::Relaxed);
                self.delta_upload.fetch_add(bytes, Ordering::Relaxed);
            }
            TunnelTrafficDirection::Download => {
                self.total_download.fetch_add(bytes, Ordering::Relaxed);
                self.delta_download.fetch_add(bytes, Ordering::Relaxed);
            }
        }
        self.dirty.store(true, Ordering::Relaxed);
    }

    fn restore_dirty_delta(&self, delta: TrafficTotals) {
        self.delta_upload.fetch_add(delta.upload, Ordering::Relaxed);
        self.delta_download
            .fetch_add(delta.download, Ordering::Relaxed);
        self.dirty.store(true, Ordering::Relaxed);
    }

    fn traffic(&self) -> TrafficTotals {
        TrafficTotals {
            upload: self.total_upload.load(Ordering::Relaxed),
            download: self.total_download.load(Ordering::Relaxed),
        }
    }
}

impl TunnelServerSession for UserMeter {
    fn record_payload(&self, direction: TunnelTrafficDirection, bytes: usize) {
        self.counters.record_payload(direction, bytes);
    }

    fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    fn connected(&self) {
        self.connected.fetch_add(1, Ordering::Relaxed);
        if let Ok(timestamp) = current_unix_seconds() {
            self.last_seen.store(timestamp, Ordering::Relaxed);
        }
    }

    fn disconnected(&self) {
        let _ = self
            .connected
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |connected| {
                connected.checked_sub(1)
            });
    }
}



fn enabled_key_map(users: &HashMap<Uuid, ManagedUser>) -> HashMap<TunnelPublicKey, Arc<UserMeter>> {
    users
        .values()
        .filter(|user| user.record.enabled)
        .map(|user| {
            (
                TunnelPublicKey(user.record.public_key),
                Arc::clone(&user.meter),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{ops::Deref, path::PathBuf};

    use librqbit::{
        TunnelPublicKey, TunnelServerAuthorizer, TunnelServerSession, TunnelTrafficDirection,
    };
    use rusqlite::{params, Connection};

    use crate::{
        model::TrafficTotals,
        paths::ServerPaths,
        store::ServerStore,
    };
    use super::{UserCounters, UserMeter, UserRegistry};

    struct TestRegistry {
        _directory: tempfile::TempDir,
        database_path: PathBuf,
        registry: UserRegistry,
    }

    impl Deref for TestRegistry {
        type Target = UserRegistry;

        fn deref(&self) -> &Self::Target {
            &self.registry
        }
    }

    async fn test_registry() -> TestRegistry {
        let directory = tempfile::tempdir().unwrap();
        let database_path = ServerPaths::under(directory.path()).database_path();
        let store = ServerStore::open(database_path.clone()).await.unwrap();
        let registry = UserRegistry::open(store).await.unwrap();

        TestRegistry {
            _directory: directory,
            database_path,
            registry,
        }
    }

    #[tokio::test]
    async fn disabling_a_user_rejects_new_admission_and_cancels_existing_sessions() {
        let registry = test_registry().await;
        let created = registry.create_user("alice").await.unwrap();
        let user = created.user;
        let session = registry.authorize(&TunnelPublicKey(user.public_key)).unwrap();
        registry.set_enabled(user.id, false).await.unwrap();
        assert!(registry.authorize(&TunnelPublicKey(user.public_key)).is_none());
        assert!(session.cancellation_token().is_cancelled());
        let reloaded = UserRegistry::open(
            ServerStore::open(registry.database_path.clone())
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        assert!(
            reloaded
                .authorize(&TunnelPublicKey(user.public_key))
                .is_none()
        );
    }


    #[tokio::test]
    async fn deleting_a_user_rejects_new_admission_and_cancels_existing_sessions() {
        let registry = test_registry().await;
        let created = registry.create_user("alice").await.unwrap();
        let user = created.user;
        let session = registry.authorize(&TunnelPublicKey(user.public_key)).unwrap();

        registry.delete_user(user.id).await.unwrap();

        assert!(registry.authorize(&TunnelPublicKey(user.public_key)).is_none());
        assert!(session.cancellation_token().is_cancelled());
        assert!(matches!(
            registry.snapshot(user.id).await,
            Err(super::RegistryError::UserNotFound(id)) if id == user.id
        ));
    }
    #[tokio::test]
    async fn flush_persists_both_direction_deltas() {
        let registry = test_registry().await;
        let created = registry.create_user("alice").await.unwrap();
        let user = created.user;
        let session = registry.authorize(&TunnelPublicKey(user.public_key)).unwrap();
        session.record_payload(TunnelTrafficDirection::Upload, 9);
        session.record_payload(TunnelTrafficDirection::Download, 14);
        registry.flush().await.unwrap();
        assert_eq!(
            registry.snapshot(user.id).await.unwrap().traffic,
            TrafficTotals {
                upload: 9,
                download: 14,
            }
        );
        let reloaded = UserRegistry::open(
            ServerStore::open(registry.database_path.clone())
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            reloaded.snapshot(user.id).await.unwrap().traffic,
            TrafficTotals {
                upload: 9,
                download: 14,
            }
        );
    }

    #[tokio::test]
    async fn failed_flush_keeps_deltas_for_later_retry() {
        let registry = test_registry().await;
        let created = registry.create_user("alice").await.unwrap();
        let user = created.user;
        let session = registry.authorize(&TunnelPublicKey(user.public_key)).unwrap();
        session.record_payload(TunnelTrafficDirection::Upload, 9);
        session.record_payload(TunnelTrafficDirection::Download, 14);

        let database_path = registry.database_path.clone();
        let restore_path = database_path.clone();
        tokio::task::spawn_blocking(move || {
            let connection = Connection::open(database_path)?;
            connection.execute(
                "DELETE FROM traffic_totals WHERE user_id = ?1",
                params![user.id.to_string()],
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
        .unwrap()
        .unwrap();

        assert!(registry.flush().await.is_err());
        assert_eq!(
            registry.snapshot(user.id).await.unwrap().traffic,
            TrafficTotals {
                upload: 9,
                download: 14,
            }
        );

        tokio::task::spawn_blocking(move || {
            let connection = Connection::open(restore_path)?;
            connection.execute(
                "INSERT INTO traffic_totals (user_id, updated_at) VALUES (?1, ?2)",
                params![user.id.to_string(), 0],
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
        .unwrap()
        .unwrap();

        registry.flush().await.unwrap();
        assert_eq!(
            registry.snapshot(user.id).await.unwrap().traffic,
            TrafficTotals {
                upload: 9,
                download: 14,
            }
        );
        let reloaded = UserRegistry::open(
            ServerStore::open(registry.database_path.clone())
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            reloaded.snapshot(user.id).await.unwrap().traffic,
            TrafficTotals {
                upload: 9,
                download: 14,
            }
        );
    }

    #[tokio::test]
    async fn re_enabling_a_user_uses_a_fresh_uncancelled_session() {
        let registry = test_registry().await;
        let created = registry.create_user("alice").await.unwrap();
        let user = created.user;
        let old_session = registry.authorize(&TunnelPublicKey(user.public_key)).unwrap();

        registry.set_enabled(user.id, false).await.unwrap();
        registry.set_enabled(user.id, true).await.unwrap();

        assert!(old_session.cancellation_token().is_cancelled());
        assert!(
            !registry
                .authorize(&TunnelPublicKey(user.public_key))
                .unwrap()
                .cancellation_token()
                .is_cancelled()
        );
    }

    #[tokio::test]
    async fn reset_traffic_clears_persisted_and_live_totals() {
        let registry = test_registry().await;
        let created = registry.create_user("alice").await.unwrap();
        let user = created.user;
        let session = registry.authorize(&TunnelPublicKey(user.public_key)).unwrap();
        session.record_payload(TunnelTrafficDirection::Upload, 4);
        session.record_payload(TunnelTrafficDirection::Download, 6);
        registry.flush().await.unwrap();
        session.record_payload(TunnelTrafficDirection::Upload, 3);
        session.record_payload(TunnelTrafficDirection::Download, 2);

        registry.reset_traffic(user.id).await.unwrap();
        registry.flush().await.unwrap();

        assert_eq!(
            registry.snapshot(user.id).await.unwrap().traffic,
            TrafficTotals::default()
        );
        let reloaded = UserRegistry::open(
            ServerStore::open(registry.database_path.clone())
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            reloaded.snapshot(user.id).await.unwrap().traffic,
            TrafficTotals::default()
        );
    }


    #[tokio::test]
    async fn reset_persists_post_reset_payloads_from_active_and_retired_sessions() {
        let registry = test_registry().await;
        let created = registry.create_user("alice").await.unwrap();
        let user = created.user;
        let retired = registry.authorize(&TunnelPublicKey(user.public_key)).unwrap();

        registry.set_enabled(user.id, false).await.unwrap();
        registry.set_enabled(user.id, true).await.unwrap();
        let active = registry.authorize(&TunnelPublicKey(user.public_key)).unwrap();

        registry.reset_traffic(user.id).await.unwrap();
        retired.record_payload(TunnelTrafficDirection::Upload, 3);
        active.record_payload(TunnelTrafficDirection::Download, 5);
        registry.flush().await.unwrap();

        let reloaded = UserRegistry::open(
            ServerStore::open(registry.database_path.clone())
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            reloaded.snapshot(user.id).await.unwrap().traffic,
            TrafficTotals {
                upload: 3,
                download: 5,
            }
        );
    }
    #[test]
    fn reset_handoff_applies_to_active_and_retired_meter_generations() {
        let counters = std::sync::Arc::new(UserCounters::new(TrafficTotals::default()));
        let active = UserMeter::new(std::sync::Arc::clone(&counters));
        let retired = UserMeter::new(std::sync::Arc::clone(&counters));
        let before_reset = counters.state.load_full();

        counters.reset();
        before_reset.record_payload(TunnelTrafficDirection::Upload, 9);
        retired.record_payload(TunnelTrafficDirection::Download, 5);

        assert_eq!(
            active.traffic(),
            TrafficTotals {
                upload: 0,
                download: 5,
            }
        );
        let (_, delta) = counters.detach_for_flush();
        assert_eq!(
            delta,
            TrafficTotals {
                upload: 0,
                download: 5,
            }
        );
    }
}
