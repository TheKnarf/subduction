//! Preparing the directory that holds a Veilid node's on-disk state.
//!
//! Veilid refuses to open its stores unless every directory and file it
//! uses is owned by the effective user **and** group of the process
//! (`veilid_tools::ensure_{file,directory}_private_owner`). On macOS/BSD,
//! new files and directories inherit the group of their _parent directory_
//! (e.g. `wheel` under `/tmp`), and on Linux the same happens under a setgid
//! directory, so a fresh data directory can fail with
//! `path has incorrect owner/group`. [`prepare_data_dir`] fixes that up
//! before Veilid starts.

use std::{io, path::Path};

/// Create `data_dir` (and missing parents) and make sure it and everything
/// already inside it that we own belongs to our effective group, so that
/// Veilid's ownership checks pass and files Veilid creates later inherit the
/// right group.
///
/// Entries owned by another user are left alone (Veilid will reject them
/// with a clear error). If `data_dir` itself is a symbolic link, its target
/// is fixed (Veilid's checks follow it too); symbolic links _inside_ the
/// tree are not followed. A no-op beyond creating the directory on non-Unix
/// platforms.
///
/// # Errors
///
/// Fails if the directory cannot be created or read, or a `chown` to our
/// own effective group fails.
pub fn prepare_data_dir(data_dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(data_dir)?;
    #[cfg(unix)]
    {
        // Veilid follows a symlinked data directory, so fix its target.
        let root = std::fs::canonicalize(data_dir)?;
        unix::fix_group_recursive(&root)?;
    }
    Ok(())
}

#[cfg(unix)]
mod unix {
    use std::{io, os::unix::fs::MetadataExt as _, path::Path};

    pub(super) fn fix_group_recursive(root: &Path) -> io::Result<()> {
        let uid = nix::unistd::geteuid().as_raw();
        let gid = nix::unistd::getegid().as_raw();
        let mut stack = vec![root.to_path_buf()];
        while let Some(path) = stack.pop() {
            // Do not follow symlinks inside the tree: a link could point
            // anywhere. (The root is already canonical.)
            let meta = std::fs::symlink_metadata(&path)?;
            if meta.file_type().is_symlink() || meta.uid() != uid {
                continue;
            }
            if meta.gid() != gid {
                tracing::debug!(path = %path.display(), from = meta.gid(), to = gid, "veilid: fixing data directory group");
                std::os::unix::fs::lchown(&path, None, Some(gid))?;
            }
            if meta.is_dir() {
                for entry in std::fs::read_dir(&path)? {
                    stack.push(entry?.path());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn creates_missing_directory_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("a").join("b");
        prepare_data_dir(&dir).unwrap();
        assert!(dir.is_dir());
        // Idempotent.
        prepare_data_dir(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn fixes_group_of_dir_and_existing_entries() {
        use std::os::unix::fs::MetadataExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("veilid");
        std::fs::create_dir_all(dir.join("table_store")).unwrap();
        std::fs::write(dir.join("table_store").join("db"), b"x").unwrap();
        std::fs::write(dir.join("top"), b"y").unwrap();

        let egid = nix::unistd::getegid().as_raw();
        // Simulate inheriting a foreign group (as under /tmp on macOS) when
        // we are a member of another group; otherwise only the invariant
        // can be checked.
        #[cfg(target_os = "linux")]
        let groups = nix::unistd::getgroups().unwrap_or_default();
        #[cfg(not(target_os = "linux"))]
        let groups: Vec<nix::unistd::Gid> = Vec::new();
        let other = groups
            .into_iter()
            .map(nix::unistd::Gid::as_raw)
            .find(|g| *g != egid);
        if let Some(other) = other {
            for p in [
                dir.clone(),
                dir.join("table_store"),
                dir.join("table_store").join("db"),
                dir.join("top"),
            ] {
                std::os::unix::fs::chown(&p, None, Some(other)).unwrap();
                assert_eq!(std::fs::metadata(&p).unwrap().gid(), other);
            }
        }

        prepare_data_dir(&dir).unwrap();

        for p in [
            dir.clone(),
            dir.join("table_store"),
            dir.join("table_store").join("db"),
            dir.join("top"),
        ] {
            assert_eq!(
                std::fs::metadata(&p).unwrap().gid(),
                egid,
                "{}",
                p.display()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn follows_a_symlinked_root() {
        use std::os::unix::fs::MetadataExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        std::fs::create_dir_all(target.join("table_store")).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let egid = nix::unistd::getegid().as_raw();
        #[cfg(target_os = "linux")]
        let groups = nix::unistd::getgroups().unwrap_or_default();
        #[cfg(not(target_os = "linux"))]
        let groups: Vec<nix::unistd::Gid> = Vec::new();
        if let Some(other) = groups
            .into_iter()
            .map(nix::unistd::Gid::as_raw)
            .find(|g| *g != egid)
        {
            for p in [target.clone(), target.join("table_store")] {
                std::os::unix::fs::chown(&p, None, Some(other)).unwrap();
            }
        }

        prepare_data_dir(&link).unwrap();

        for p in [target.clone(), target.join("table_store")] {
            assert_eq!(
                std::fs::metadata(&p).unwrap().gid(),
                egid,
                "{}",
                p.display()
            );
        }
    }
}
