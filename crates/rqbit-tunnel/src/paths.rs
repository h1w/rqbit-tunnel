use std::path::{Path, PathBuf};

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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::ServerPaths;

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

    #[test]
    fn server_artifact_paths_use_the_managed_layout() {
        let root = Path::new("/tmp/rqbit-tunnel-stage");
        let paths = ServerPaths::under(root);

        assert_eq!(paths.config_path(), root.join("etc/rqbit-tunnel/server.json"));
        assert_eq!(paths.server_key_path(), root.join("etc/rqbit-tunnel/server.key"));
        assert_eq!(paths.carrier_root(), root.join("var/lib/rqbit-tunnel/carrier"));
        assert_eq!(paths.control_socket_path(), root.join("run/rqbit-tunnel/server.sock"));
        assert_eq!(paths.database_path(), root.join("var/lib/rqbit-tunnel/server-state.db"));
    }
}
