use anyhow::Context as _;
use url::{Host, Url};

pub fn validate_https_or_loopback(u: &Url) -> anyhow::Result<()> {
    match u.scheme() {
        "https" => {}
        "http" => {
            let host = u.host().context("missing host")?;
            let is_loopback = match host {
                Host::Domain(d) => d.eq_ignore_ascii_case("localhost"),
                Host::Ipv4(ip) => ip.is_loopback(),
                Host::Ipv6(ip) => ip.is_loopback(),
            };
            if !is_loopback {
                anyhow::bail!("http is only allowed for localhost");
            }
        }
        _ => anyhow::bail!("unsupported scheme"),
    }

    if u.host_str().is_none() {
        anyhow::bail!("missing host");
    }
    if !u.username().is_empty() || u.password().is_some() {
        anyhow::bail!("userinfo not allowed");
    }
    if u.fragment().is_some() {
        anyhow::bail!("fragment not allowed");
    }
    Ok(())
}

pub fn validate_provider_base_url(u: &Url) -> anyhow::Result<()> {
    validate_https_or_loopback(u)?;

    if u.query().is_some() || u.fragment().is_some() {
        anyhow::bail!("query/fragment not allowed in base_url");
    }
    if u.path() != "" && u.path() != "/" {
        anyhow::bail!("path not allowed in base_url");
    }
    Ok(())
}

pub fn validate_mcp_endpoint_url(u: &Url) -> anyhow::Result<()> {
    validate_https_or_loopback(u)?;

    if u.query().is_some() || u.fragment().is_some() {
        anyhow::bail!("query/fragment not allowed in endpoint_url");
    }
    Ok(())
}
