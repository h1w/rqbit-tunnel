pub(crate) mod agent;
#[cfg(any(
    all(target_os = "linux", feature = "tray-linux"),
    all(windows, feature = "tray-windows")
))]
pub(crate) mod state;
pub(crate) use agent::{TrayRunOutcome, ensure_user_session, run, set_autostart};
