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

    pub fn database_path(&self) -> PathBuf {
        self.data_dir.join("server.sqlite3")
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
}
