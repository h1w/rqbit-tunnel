use std::path::{Path, PathBuf};

#[cfg(windows)]
use std::{
    ffi::{OsString, c_void},
    os::windows::ffi::OsStringExt,
};

#[cfg(windows)]
#[link(name = "shell32")]
unsafe extern "system" {
    #[link_name = "SHGetKnownFolderPath"]
    fn sh_get_known_folder_path_raw(
        rfid: *const windows::core::GUID,
        flags: windows::Win32::UI::Shell::KNOWN_FOLDER_FLAG,
        token: windows::Win32::Foundation::HANDLE,
        path: *mut windows::core::PWSTR,
    ) -> windows::core::HRESULT;
}

/// Filesystem locations owned by the managed tunnel server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerPaths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub run_dir: PathBuf,
}

impl ServerPaths {
    /// Returns the root-owned paths used by an installed server.
    pub fn system() -> Self {
        Self {
            config_dir: PathBuf::from("/etc/rqbit-tunnel"),
            data_dir: PathBuf::from("/var/lib/rqbit-tunnel"),
            run_dir: PathBuf::from("/run/rqbit-tunnel"),
        }
    }

    /// Derives the installed layout below `root` for tests and install staging.
    pub fn under(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();

        Self {
            config_dir: root.join("etc/rqbit-tunnel"),
            data_dir: root.join("var/lib/rqbit-tunnel"),
            run_dir: root.join("run/rqbit-tunnel"),
        }
    }

    pub fn config_path(&self) -> PathBuf {
        self.config_dir.join("server.json")
    }

    pub fn server_key_path(&self) -> PathBuf {
        self.config_dir.join("server.key")
    }

    pub fn carrier_root(&self) -> PathBuf {
        self.data_dir.join("carrier")
    }

    pub fn control_socket_path(&self) -> PathBuf {
        self.run_dir.join("server.sock")
    }

    pub fn database_path(&self) -> PathBuf {
        self.data_dir.join("server-state.db")
    }
}

/// Filesystem locations owned by the managed tunnel client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientPaths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub run_dir: PathBuf,
}

impl ClientPaths {
    /// Returns the protected paths used by an installed client.
    pub fn system() -> Self {
        #[cfg(windows)]
        {
            let root = windows_program_data_root().join("rqbit-tunnel");
            return Self {
                config_dir: root.clone(),
                data_dir: root.clone(),
                run_dir: root.join("run"),
            };
        }

        #[cfg(not(windows))]
        Self {
            config_dir: PathBuf::from("/etc/rqbit-tunnel"),
            data_dir: PathBuf::from("/var/lib/rqbit-tunnel"),
            run_dir: PathBuf::from("/run/rqbit-tunnel-client"),
        }
    }

    /// Returns the stable executable root for the managed client bundle.
    pub fn install_root() -> PathBuf {
        #[cfg(windows)]
        {
            return windows_program_files_root().join("rqbit-tunnel");
        }

        #[cfg(not(windows))]
        PathBuf::from("/opt/rqbit-tunnel")
    }

    /// Derives the installed layout below `root` for tests and install staging.
    pub fn under(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();

        Self {
            config_dir: root.join("etc/rqbit-tunnel"),
            data_dir: root.join("var/lib/rqbit-tunnel"),
            run_dir: root.join("run/rqbit-tunnel-client"),
        }
    }

    pub fn config_path(&self) -> PathBuf {
        self.config_dir.join("client.json")
    }

    pub fn client_key_path(&self) -> PathBuf {
        self.config_dir.join("client.key")
    }

    pub fn carrier_root(&self) -> PathBuf {
        self.data_dir.join("client-carrier")
    }

    pub fn control_socket_path(&self) -> PathBuf {
        self.run_dir.join("client.sock")
    }
}

#[cfg(windows)]
fn windows_program_data_root() -> PathBuf {
    known_folder_path(&windows::Win32::UI::Shell::FOLDERID_ProgramData)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

#[cfg(windows)]
fn windows_program_files_root() -> PathBuf {
    known_folder_path(&windows::Win32::UI::Shell::FOLDERID_ProgramFiles)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
}

/// The projected Windows binding drops the out-pointer on HRESULT failure.
/// Keep it locally so every non-null allocation is released before fallback.
#[cfg(windows)]
fn known_folder_path(folder_id: &windows::core::GUID) -> Option<PathBuf> {
    use windows::{
        Win32::{Foundation::HANDLE, System::Com::CoTaskMemFree, UI::Shell::KNOWN_FOLDER_FLAG},
        core::PWSTR,
    };

    let mut allocated_path = PWSTR::null();
    let result = unsafe {
        sh_get_known_folder_path_raw(
            folder_id,
            KNOWN_FOLDER_FLAG(0),
            HANDLE::default(),
            &mut allocated_path,
        )
    };
    let path = if result.is_ok() && !allocated_path.is_null() {
        Some(unsafe { PathBuf::from(OsString::from_wide(allocated_path.as_wide())) })
    } else {
        None
    };
    unsafe {
        if !allocated_path.is_null() {
            CoTaskMemFree(Some(allocated_path.0 as *const c_void));
        }
    }
    path
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{ClientPaths, ServerPaths};

    #[test]
    fn system_paths_use_root_owned_locations() {
        let paths = ServerPaths::system();

        assert_eq!(paths.config_dir, Path::new("/etc/rqbit-tunnel"));
        assert_eq!(paths.data_dir, Path::new("/var/lib/rqbit-tunnel"));
        assert_eq!(paths.run_dir, Path::new("/run/rqbit-tunnel"));
    }

    #[test]
    fn staging_paths_remain_under_the_given_root() {
        let root = Path::new("/tmp/rqbit-tunnel-stage");
        let paths = ServerPaths::under(root);

        assert_eq!(paths.config_dir, root.join("etc/rqbit-tunnel"));
        assert_eq!(paths.data_dir, root.join("var/lib/rqbit-tunnel"));
        assert_eq!(paths.run_dir, root.join("run/rqbit-tunnel"));
    }

    #[cfg(not(windows))]
    #[test]
    fn client_runtime_paths_are_isolated_from_server_runtime_paths() {
        let client = ClientPaths::system();
        let server = ServerPaths::system();

        assert_eq!(client.run_dir, Path::new("/run/rqbit-tunnel-client"));
        assert_ne!(client.run_dir, server.run_dir);
    }

    #[cfg(windows)]
    #[test]
    fn windows_client_paths_are_absolute_and_share_one_programdata_root() {
        let paths = ClientPaths::system();

        assert!(paths.config_path().is_absolute());
        assert_eq!(paths.config_dir, paths.data_dir);
        assert_eq!(paths.run_dir, paths.config_dir.join("run"));
        assert!(paths.config_dir.ends_with("rqbit-tunnel"));
    }

    #[test]
    fn client_install_root_is_an_absolute_managed_directory() {
        let root = ClientPaths::install_root();

        assert!(root.is_absolute());
        assert_eq!(
            root.file_name().and_then(|component| component.to_str()),
            Some("rqbit-tunnel")
        );
    }
    #[test]
    fn server_artifact_paths_use_the_managed_layout() {
        let root = Path::new("/tmp/rqbit-tunnel-stage");
        let paths = ServerPaths::under(root);

        assert_eq!(
            paths.config_path(),
            root.join("etc/rqbit-tunnel/server.json")
        );
        assert_eq!(
            paths.server_key_path(),
            root.join("etc/rqbit-tunnel/server.key")
        );
        assert_eq!(
            paths.carrier_root(),
            root.join("var/lib/rqbit-tunnel/carrier")
        );
        assert_eq!(
            paths.control_socket_path(),
            root.join("run/rqbit-tunnel/server.sock")
        );
        assert_eq!(
            paths.database_path(),
            root.join("var/lib/rqbit-tunnel/server-state.db")
        );
    }

    #[test]
    fn client_artifact_paths_use_the_managed_layout() {
        let root = Path::new("/tmp/rqbit-tunnel-stage");
        let paths = ClientPaths::under(root);

        assert_eq!(
            paths.config_path(),
            root.join("etc/rqbit-tunnel/client.json")
        );
        assert_eq!(
            paths.client_key_path(),
            root.join("etc/rqbit-tunnel/client.key")
        );
        assert_eq!(
            paths.carrier_root(),
            root.join("var/lib/rqbit-tunnel/client-carrier")
        );
        assert_eq!(
            paths.control_socket_path(),
            root.join("run/rqbit-tunnel-client/client.sock")
        );
    }
}
