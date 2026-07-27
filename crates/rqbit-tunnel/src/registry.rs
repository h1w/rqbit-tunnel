use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    ops::Bound::{Excluded, Unbounded},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use librqbit::{
    TunnelPrivateKey, TunnelPublicKey, TunnelServerAuthorizer, TunnelServerSession,
    TunnelTrafficDirection, tunnel_generate_keypair,
};
use thiserror::Error;
use tokio::{
    sync::{Mutex, RwLock, Semaphore, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    model::{
        MAX_USER_NAME_BYTES, MAX_USER_PAGE_SIZE, TrafficTotals, UserPage, UserRecord, UserSnapshot,
    },
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
    #[error("registry flush worker failed: {0}")]
    FlushWorker(#[from] tokio::task::JoinError),
    #[error("registry mutation gate is closed")]
    MutationGateClosed,
    #[error("registry operation task stopped before returning a result")]
    OperationTaskClosed,
    #[error("registry flush interval must not be zero")]
    ZeroFlushInterval,
    #[error("user name is {length} bytes, exceeding the {max} byte control-plane limit")]
    UserNameTooLong { length: usize, max: usize },
    #[error("user page size {requested} is outside 1..={max}")]
    InvalidPageSize { requested: usize, max: usize },
    #[error("the legacy user list response exceeds one bounded page")]
    PaginationRequired,
    #[error("user {0} does not exist")]
    UserNotFound(Uuid),
}

/// Durable users plus the dynamic, lock-free admission map used by the tunnel server.
pub struct UserRegistry {
    store: ServerStore,
    by_key: ArcSwap<HashMap<TunnelPublicKey, Arc<UserMeter>>>,
    users: RwLock<BTreeMap<Uuid, ManagedUser>>,
    flush_worker: FlushWorker,
    mutations: Semaphore,
}

struct ManagedUser {
    record: UserRecord,
    counters: Arc<UserCounters>,
    meter: Arc<UserMeter>,
    retired_meters: Vec<Weak<UserMeter>>,
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

struct FlushWorker {
    cancellation: CancellationToken,
    join: Mutex<Option<JoinHandle<()>>>,
    #[cfg(test)]
    flush_completed: Arc<tokio::sync::Notify>,
    #[cfg(test)]
    started: Arc<tokio::sync::Notify>,
}

impl UserRegistry {
    pub async fn open(store: ServerStore) -> Result<Arc<Self>, RegistryError> {
        Self::open_with_flush_interval(store, Duration::from_secs(1)).await
    }

    pub(crate) async fn open_with_flush_interval(
        store: ServerStore,
        interval: Duration,
    ) -> Result<Arc<Self>, RegistryError> {
        if interval.is_zero() {
            return Err(RegistryError::ZeroFlushInterval);
        }

        let stored_users = store.load_users().await?;
        let mut users = BTreeMap::new();

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

        let registry = Arc::new(Self {
            store,
            by_key: ArcSwap::from_pointee(enabled_key_map(&users)),
            users: RwLock::new(users),
            flush_worker: FlushWorker::new(),
            mutations: Semaphore::new(1),
        });
        registry
            .flush_worker
            .start(Arc::downgrade(&registry), interval)
            .await;

        Ok(registry)
    }

    async fn run_owned_operation<T, F, Fut>(
        self: &Arc<Self>,
        operation: F,
    ) -> Result<T, RegistryError>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Self>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, RegistryError>> + Send + 'static,
    {
        let (result_sender, result_receiver) = oneshot::channel();
        let registry = Arc::clone(self);
        let _ = tokio::spawn(async move {
            let result = operation(registry).await;
            let _ = result_sender.send(result);
        });

        result_receiver
            .await
            .map_err(|_| RegistryError::OperationTaskClosed)?
    }

    pub async fn create_user(
        self: &Arc<Self>,
        name: impl Into<String>,
    ) -> Result<CreatedUser, RegistryError> {
        let name = name.into();
        validate_user_name(&name)?;
        self.run_owned_operation(
            move |registry| async move { registry.create_user_inner(name).await },
        )
        .await
    }

    async fn create_user_inner(&self, name: String) -> Result<CreatedUser, RegistryError> {
        let _mutation = self
            .mutations
            .acquire()
            .await
            .map_err(|_| RegistryError::MutationGateClosed)?;
        let (client_private_key, client_public_key) = tunnel_generate_keypair();
        let user = UserRecord {
            id: Uuid::new_v4(),
            name,
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

    pub async fn delete_user(self: &Arc<Self>, user_id: Uuid) -> Result<(), RegistryError> {
        self.run_owned_operation(move |registry| async move {
            registry.delete_user_inner(user_id).await
        })
        .await
    }

    async fn delete_user_inner(&self, user_id: Uuid) -> Result<(), RegistryError> {
        let _mutation = self
            .mutations
            .acquire()
            .await
            .map_err(|_| RegistryError::MutationGateClosed)?;
        {
            let users = self.users.read().await;
            if !users.contains_key(&user_id) {
                return Err(RegistryError::UserNotFound(user_id));
            }
        }

        self.store.delete_user(user_id).await?;

        let mut removed = {
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

    pub async fn flush(self: &Arc<Self>) -> Result<(), RegistryError> {
        self.run_owned_operation(|registry| async move { registry.flush_inner().await })
            .await
    }

    async fn flush_inner(&self) -> Result<(), RegistryError> {
        let _mutation = self
            .mutations
            .acquire()
            .await
            .map_err(|_| RegistryError::MutationGateClosed)?;
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

    /// Stops periodic persistence, waits for the worker, then flushes once.
    pub async fn shutdown(self: &Arc<Self>) -> Result<(), RegistryError> {
        self.run_owned_operation(|registry| async move { registry.shutdown_inner().await })
            .await
    }

    async fn shutdown_inner(&self) -> Result<(), RegistryError> {
        self.flush_worker.stop().await?;
        self.flush_inner().await
    }

    pub async fn reset_traffic(self: &Arc<Self>, user_id: Uuid) -> Result<(), RegistryError> {
        self.run_owned_operation(move |registry| async move {
            registry.reset_traffic_inner(user_id).await
        })
        .await
    }

    async fn reset_traffic_inner(&self, user_id: Uuid) -> Result<(), RegistryError> {
        let _mutation = self
            .mutations
            .acquire()
            .await
            .map_err(|_| RegistryError::MutationGateClosed)?;
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

    pub async fn set_enabled(
        self: &Arc<Self>,
        user_id: Uuid,
        enabled: bool,
    ) -> Result<(), RegistryError> {
        self.run_owned_operation(move |registry| async move {
            registry.set_enabled_inner(user_id, enabled).await
        })
        .await
    }

    async fn set_enabled_inner(&self, user_id: Uuid, enabled: bool) -> Result<(), RegistryError> {
        let _mutation = self
            .mutations
            .acquire()
            .await
            .map_err(|_| RegistryError::MutationGateClosed)?;
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
                user.prune_retired_meters();
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
        let mut users = self.users.write().await;
        let user = users
            .get_mut(&user_id)
            .ok_or(RegistryError::UserNotFound(user_id))?;

        Ok(user.snapshot())
    }

    pub async fn snapshot_page(
        &self,
        after: Option<Uuid>,
        limit: usize,
    ) -> Result<UserPage, RegistryError> {
        if !(1..=MAX_USER_PAGE_SIZE).contains(&limit) {
            return Err(RegistryError::InvalidPageSize {
                requested: limit,
                max: MAX_USER_PAGE_SIZE,
            });
        }

        let mut users = self.users.write().await;
        let start: std::ops::Bound<Uuid> = after.map_or(Unbounded, Excluded);
        let mut entries = users.range_mut((start, Unbounded));
        let mut snapshots = Vec::with_capacity(limit);
        for _ in 0..limit {
            let Some((_user_id, user)) = entries.next() else {
                break;
            };
            snapshots.push(user.snapshot());
        }
        let next_page = entries
            .next()
            .is_some()
            .then(|| snapshots.last().map(|snapshot| snapshot.id))
            .flatten();

        Ok(UserPage {
            users: snapshots,
            next_page,
        })
    }

    fn publish_enabled_key_map(&self, users: &BTreeMap<Uuid, ManagedUser>) {
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

fn bounded_snapshot_name(name: &str) -> (String, Option<usize>) {
    if name.len() <= MAX_USER_NAME_BYTES {
        return (name.to_owned(), None);
    }

    let mut end = MAX_USER_NAME_BYTES;
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    (name[..end].to_owned(), Some(name.len()))
}

fn validate_user_name(name: &str) -> Result<(), RegistryError> {
    if name.len() > MAX_USER_NAME_BYTES {
        return Err(RegistryError::UserNameTooLong {
            length: name.len(),
            max: MAX_USER_NAME_BYTES,
        });
    }

    Ok(())
}

impl FlushWorker {
    fn new() -> Self {
        Self {
            cancellation: CancellationToken::new(),
            join: Mutex::new(None),
            #[cfg(test)]
            flush_completed: Arc::new(tokio::sync::Notify::new()),
            #[cfg(test)]
            started: Arc::new(tokio::sync::Notify::new()),
        }
    }

    async fn start(&self, registry: std::sync::Weak<UserRegistry>, interval: Duration) {
        let cancellation = self.cancellation.clone();
        #[cfg(test)]
        let flush_completed = Some(Arc::clone(&self.flush_completed));
        #[cfg(not(test))]
        let flush_completed = None;
        #[cfg(test)]
        let started = Some(Arc::clone(&self.started));
        #[cfg(not(test))]
        let started = None;
        let join = tokio::spawn(run_flush_worker(
            registry,
            cancellation,
            interval,
            flush_completed,
            started,
        ));

        let mut join_slot = self.join.lock().await;
        debug_assert!(join_slot.is_none());
        *join_slot = Some(join);
    }

    async fn stop(&self) -> Result<(), RegistryError> {
        self.cancellation.cancel();
        let join = { self.join.lock().await.take() };

        if let Some(join) = join {
            join.await?;
        }

        Ok(())
    }
}

impl Drop for FlushWorker {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

async fn run_flush_worker(
    registry: std::sync::Weak<UserRegistry>,
    cancellation: CancellationToken,
    interval: Duration,
    flush_completed: Option<Arc<tokio::sync::Notify>>,
    started: Option<Arc<tokio::sync::Notify>>,
) {
    let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    if let Some(started) = started {
        started.notify_one();
    }
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            _ = ticks.tick() => {
                let Some(registry) = registry.upgrade() else {
                    break;
                };

                match registry.flush().await {
                    Ok(()) => {
                        if let Some(flush_completed) = &flush_completed {
                            flush_completed.notify_one();
                        }
                    }
                    Err(error) => tracing::warn!(
                        error = %error,
                        "failed to flush rqbit tunnel traffic; will retry on the next interval"
                    ),
                }
            }
        }
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
    fn meters(&mut self) -> Vec<Arc<UserMeter>> {
        self.prune_retired_meters();

        let mut meters = Vec::with_capacity(self.retired_meters.len() + 1);
        meters.push(Arc::clone(&self.meter));
        meters.extend(self.retired_meters.iter().filter_map(Weak::upgrade));
        meters
    }

    fn replace_active_meter(&mut self) {
        let retired = Arc::downgrade(&self.meter);
        self.meter = Arc::new(UserMeter::new(Arc::clone(&self.counters)));
        self.retired_meters.push(retired);
        self.prune_retired_meters();
    }

    fn reset_counters(&mut self) {
        self.counters.reset();
    }

    fn snapshot(&mut self) -> UserSnapshot {
        self.prune_retired_meters();

        let traffic = self.counters.traffic();
        let mut connected = self.meter.connected();
        let mut last_seen = self.meter.last_seen();

        for retired in &self.retired_meters {
            if let Some(retired) = retired.upgrade() {
                connected = connected.saturating_add(retired.connected());
                last_seen = last_seen.max(retired.last_seen());
            }
        }

        let (name, name_truncated_bytes) = bounded_snapshot_name(&self.record.name);
        UserSnapshot {
            id: self.record.id,
            name,
            name_truncated_bytes,
            enabled: self.record.enabled,
            connected,
            traffic,
            last_seen,
        }
    }

    fn prune_retired_meters(&mut self) {
        self.retired_meters.retain(|meter| meter.strong_count() > 0);
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

fn enabled_key_map(
    users: &BTreeMap<Uuid, ManagedUser>,
) -> HashMap<TunnelPublicKey, Arc<UserMeter>> {
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
    use std::{ops::Deref, path::PathBuf, sync::Arc, time::Duration};

    use librqbit::{
        TunnelPublicKey, TunnelServerAuthorizer, TunnelServerSession, TunnelTrafficDirection,
    };
    use rusqlite::{Connection, params};

    use super::{UserCounters, UserMeter, UserRegistry};
    use crate::{
        ipc::protocol::{MAX_FRAME_BYTES, ServerResponse, encode_response},
        model::{MAX_USER_NAME_BYTES, TrafficTotals, UserRecord},
        paths::ServerPaths,
        store::ServerStore,
    };

    struct TestRegistry {
        _directory: tempfile::TempDir,
        database_path: PathBuf,
        registry: Arc<UserRegistry>,
    }

    impl Deref for TestRegistry {
        type Target = Arc<UserRegistry>;

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

    async fn test_registry_with_flush_interval(
        interval: Duration,
    ) -> (tempfile::TempDir, PathBuf, Arc<UserRegistry>) {
        let directory = tempfile::tempdir().unwrap();
        let database_path = ServerPaths::under(directory.path()).database_path();
        let store = ServerStore::open(database_path.clone()).await.unwrap();
        let registry = UserRegistry::open_with_flush_interval(store, interval)
            .await
            .unwrap();

        (directory, database_path, registry)
    }

    async fn persisted_traffic(registry: &UserRegistry, user_id: uuid::Uuid) -> TrafficTotals {
        registry
            .store
            .load_users()
            .await
            .unwrap()
            .into_iter()
            .find(|stored| stored.record.id == user_id)
            .unwrap()
            .traffic
    }

    #[tokio::test]
    async fn snapshot_page_returns_every_current_user_when_the_page_is_large_enough() {
        let registry = test_registry().await;
        let alice = registry.create_user("alice").await.unwrap().user;
        let bob = registry.create_user("bob").await.unwrap().user;

        let page = registry.snapshot_page(None, 2).await.unwrap();
        assert_eq!(page.users.len(), 2);
        assert!(page.users.iter().any(|snapshot| snapshot.id == alice.id));
        assert!(page.users.iter().any(|snapshot| snapshot.id == bob.id));
        assert!(page.next_page.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_flush_persists_dirty_traffic_without_an_admin_mutation() {
        let (_directory, _database_path, registry) =
            test_registry_with_flush_interval(Duration::from_secs(1)).await;
        registry.flush_worker.started.notified().await;

        let created = registry.create_user("alice").await.unwrap();
        let user = created.user;
        let session = registry
            .authorize(&TunnelPublicKey(user.public_key))
            .unwrap();
        session.record_payload(TunnelTrafficDirection::Upload, 9);
        session.record_payload(TunnelTrafficDirection::Download, 14);

        tokio::time::advance(Duration::from_secs(1)).await;
        registry.flush_worker.flush_completed.notified().await;

        assert_eq!(
            persisted_traffic(registry.as_ref(), user.id).await,
            TrafficTotals {
                upload: 9,
                download: 14,
            }
        );

        registry.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_joins_the_worker_then_flushes_remaining_traffic() {
        let (_directory, _database_path, registry) =
            test_registry_with_flush_interval(Duration::from_secs(60)).await;
        let created = registry.create_user("alice").await.unwrap();
        let user = created.user;
        let session = registry
            .authorize(&TunnelPublicKey(user.public_key))
            .unwrap();
        session.record_payload(TunnelTrafficDirection::Upload, 9);
        session.record_payload(TunnelTrafficDirection::Download, 14);

        registry.shutdown().await.unwrap();

        assert_eq!(
            persisted_traffic(registry.as_ref(), user.id).await,
            TrafficTotals {
                upload: 9,
                download: 14,
            }
        );
    }
    #[tokio::test]
    async fn disabling_a_user_rejects_new_admission_and_cancels_existing_sessions() {
        let registry = test_registry().await;
        let created = registry.create_user("alice").await.unwrap();
        let user = created.user;
        let session = registry
            .authorize(&TunnelPublicKey(user.public_key))
            .unwrap();
        registry.set_enabled(user.id, false).await.unwrap();
        assert!(
            registry
                .authorize(&TunnelPublicKey(user.public_key))
                .is_none()
        );
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
    async fn cancelling_set_enabled_after_its_store_write_keeps_live_and_durable_state_aligned() {
        let (_directory, database_path, registry) =
            test_registry_with_flush_interval(Duration::from_secs(60)).await;
        let created = registry.create_user("alice").await.unwrap();
        let user_id = created.user.id;
        let public_key = created.user.public_key;
        let pause = registry.store.pause_next_set_enabled();

        let caller_registry = Arc::clone(&registry);
        let caller = tokio::spawn(async move { caller_registry.set_enabled(user_id, false).await });
        pause.wait_started().await;
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());

        pause.release();
        registry.flush().await.unwrap();

        assert!(registry.authorize(&TunnelPublicKey(public_key)).is_none());
        let reloaded = UserRegistry::open(ServerStore::open(database_path).await.unwrap())
            .await
            .unwrap();
        assert!(reloaded.authorize(&TunnelPublicKey(public_key)).is_none());
        reloaded.shutdown().await.unwrap();
        registry.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn deleting_a_user_rejects_new_admission_and_cancels_existing_sessions() {
        let registry = test_registry().await;
        let created = registry.create_user("alice").await.unwrap();
        let user = created.user;
        let session = registry
            .authorize(&TunnelPublicKey(user.public_key))
            .unwrap();

        registry.delete_user(user.id).await.unwrap();

        assert!(
            registry
                .authorize(&TunnelPublicKey(user.public_key))
                .is_none()
        );
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
        let session = registry
            .authorize(&TunnelPublicKey(user.public_key))
            .unwrap();
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
        let (_directory, database_path, registry) =
            test_registry_with_flush_interval(Duration::from_secs(60)).await;
        let created = registry.create_user("alice").await.unwrap();
        let user = created.user;
        let session = registry
            .authorize(&TunnelPublicKey(user.public_key))
            .unwrap();
        session.record_payload(TunnelTrafficDirection::Upload, 9);
        session.record_payload(TunnelTrafficDirection::Download, 14);

        let delete_path = database_path.clone();
        let restore_path = database_path.clone();
        tokio::task::spawn_blocking(move || {
            let connection = Connection::open(delete_path)?;
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
        let reloaded = UserRegistry::open(ServerStore::open(database_path).await.unwrap())
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
        let old_session = registry
            .authorize(&TunnelPublicKey(user.public_key))
            .unwrap();

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
    async fn retired_session_authorized_before_reenable_remains_visible_after_connecting() {
        let (_directory, _database_path, registry) =
            test_registry_with_flush_interval(Duration::from_secs(60)).await;
        let created = registry.create_user("alice").await.unwrap();
        let user = created.user;
        let retired = registry
            .authorize(&TunnelPublicKey(user.public_key))
            .unwrap();

        registry.set_enabled(user.id, false).await.unwrap();
        registry.set_enabled(user.id, true).await.unwrap();
        retired.connected();

        assert_eq!(registry.snapshot(user.id).await.unwrap().connected, 1);
    }

    #[tokio::test]
    async fn inactive_reenable_cycles_do_not_retain_retired_meters() {
        let (_directory, _database_path, registry) =
            test_registry_with_flush_interval(Duration::from_secs(60)).await;
        let created = registry.create_user("alice").await.unwrap();
        let user = created.user;

        for _ in 0..64 {
            registry.set_enabled(user.id, false).await.unwrap();
            registry.set_enabled(user.id, true).await.unwrap();
        }

        let users = registry.users.read().await;
        assert!(users.get(&user.id).unwrap().retired_meters.is_empty());
    }

    #[tokio::test]
    async fn draining_retired_sessions_remain_visible_and_are_cancelled_on_delete() {
        let (_directory, _database_path, registry) =
            test_registry_with_flush_interval(Duration::from_secs(60)).await;
        let created = registry.create_user("alice").await.unwrap();
        let user = created.user;
        let retired = registry
            .authorize(&TunnelPublicKey(user.public_key))
            .unwrap();
        retired.connected();

        registry.set_enabled(user.id, false).await.unwrap();
        registry.set_enabled(user.id, true).await.unwrap();
        let active = registry
            .authorize(&TunnelPublicKey(user.public_key))
            .unwrap();
        active.connected();

        assert_eq!(registry.snapshot(user.id).await.unwrap().connected, 2);
        registry.delete_user(user.id).await.unwrap();
        assert!(retired.cancellation_token().is_cancelled());
        assert!(active.cancellation_token().is_cancelled());
    }

    #[tokio::test]
    async fn reset_traffic_clears_persisted_and_live_totals() {
        let registry = test_registry().await;
        let created = registry.create_user("alice").await.unwrap();
        let user = created.user;
        let session = registry
            .authorize(&TunnelPublicKey(user.public_key))
            .unwrap();
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
        let retired = registry
            .authorize(&TunnelPublicKey(user.public_key))
            .unwrap();

        registry.set_enabled(user.id, false).await.unwrap();
        registry.set_enabled(user.id, true).await.unwrap();
        let active = registry
            .authorize(&TunnelPublicKey(user.public_key))
            .unwrap();

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
            active.counters.traffic(),
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
    #[tokio::test]
    async fn legacy_overlong_name_reopens_and_lists_with_bounded_display_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = ServerPaths::under(directory.path()).database_path();
        let legacy_name = "é".repeat(MAX_FRAME_BYTES);
        assert!(legacy_name.len() > MAX_FRAME_BYTES);
        let user = UserRecord {
            id: uuid::Uuid::new_v4(),
            name: legacy_name.clone(),
            public_key: [7; 32],
            enabled: true,
            created_at: 0,
            reset_at: None,
        };

        let store = ServerStore::open(&database_path).await.unwrap();
        store.create_user(&user).await.unwrap();
        drop(store);

        let registry = UserRegistry::open(ServerStore::open(&database_path).await.unwrap())
            .await
            .unwrap();
        let page = registry.snapshot_page(None, 1).await.unwrap();
        assert_eq!(page.users.len(), 1);
        let snapshot = &page.users[0];
        assert_eq!(snapshot.id, user.id);
        assert!(snapshot.name.len() <= MAX_USER_NAME_BYTES);
        assert_ne!(snapshot.name, legacy_name);
        assert_eq!(
            serde_json::to_value(snapshot).unwrap()["name_truncated_bytes"],
            serde_json::json!(legacy_name.len())
        );

        registry.set_enabled(user.id, false).await.unwrap();
        let stored = registry.store.load_users().await.unwrap().pop().unwrap();
        assert_eq!(stored.record.name, legacy_name);
        let encoded = encode_response(&ServerResponse::UserPage(page)).unwrap();
        assert!(encoded.len() <= MAX_FRAME_BYTES);

        registry.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn create_user_rejects_a_name_over_the_control_plane_limit() {
        let registry = test_registry().await;

        assert!(registry.create_user("x".repeat(65)).await.is_err());
        assert!(
            registry
                .snapshot_page(None, 1)
                .await
                .unwrap()
                .users
                .is_empty()
        );

        registry.shutdown().await.unwrap();
    }
}
