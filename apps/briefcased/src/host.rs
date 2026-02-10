use std::net::SocketAddr;
use std::path::Path;

#[cfg(unix)]
use anyhow::Context as _;

pub fn validate_loopback_tcp_bind(addr: SocketAddr) -> anyhow::Result<()> {
    if !addr.ip().is_loopback() {
        anyhow::bail!("strict host mode requires loopback-only TCP bind");
    }
    Ok(())
}

#[cfg(unix)]
pub fn enforce_strict_host_fs(data_dir: &Path, auth_token_path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    // Ensure data dir is user-only (0700).
    std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 700 {}", data_dir.display()))?;
    let meta = std::fs::metadata(data_dir).context("stat data_dir")?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o700 {
        anyhow::bail!(
            "data_dir permissions must be 0700 in strict host mode (got {:o})",
            mode
        );
    }

    // Ensure auth token is user-only (0600).
    std::fs::set_permissions(auth_token_path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 600 {}", auth_token_path.display()))?;
    let meta = std::fs::metadata(auth_token_path).context("stat auth_token")?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        anyhow::bail!(
            "auth_token permissions must be 0600 in strict host mode (got {:o})",
            mode
        );
    }

    Ok(())
}

#[cfg(not(unix))]
pub fn enforce_strict_host_fs(_data_dir: &Path, _auth_token_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
pub fn validate_unix_socket_within_data_dir(
    data_dir: &Path,
    socket_path: &Path,
) -> anyhow::Result<()> {
    let dir = data_dir
        .canonicalize()
        .with_context(|| format!("canonicalize {}", data_dir.display()))?;

    let parent = socket_path
        .parent()
        .context("unix socket path has no parent")?;
    let parent = parent
        .canonicalize()
        .with_context(|| format!("canonicalize {}", parent.display()))?;

    if !parent.starts_with(&dir) {
        anyhow::bail!(
            "strict host mode requires unix socket path to be within data_dir (socket_path={})",
            socket_path.display()
        );
    }

    Ok(())
}
