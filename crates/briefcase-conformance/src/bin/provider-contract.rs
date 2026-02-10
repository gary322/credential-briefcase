use std::process::ExitCode;

use anyhow::Context as _;
use briefcase_conformance::provider_contract::{ProviderContractOptions, run_provider_contract};
use briefcase_core::Sensitive;
use clap::Parser;
use url::Url;

#[derive(Debug, Parser)]
#[command(
    name = "briefcase-provider-contract",
    about = "Provider gateway conformance harness"
)]
struct Args {
    #[arg(long, env = "PROVIDER_BASE_URL")]
    base_url: String,

    /// Admin secret for reference gateways that support `/api/revoke`.
    ///
    /// This is treated as sensitive and will not be printed.
    #[arg(long, env = "PROVIDER_ADMIN_SECRET")]
    admin_secret: Option<String>,

    #[arg(long, default_value_t = true)]
    run_oauth: bool,

    #[arg(long, default_value_t = false)]
    run_revocation: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let base_url = match Url::parse(&args.base_url).context("parse --base-url") {
        Ok(u) => u,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    let mut opts = ProviderContractOptions::new(base_url);
    opts.run_oauth = args.run_oauth;
    opts.run_revocation = args.run_revocation;
    opts.admin_secret = args.admin_secret.map(Sensitive);

    match run_provider_contract(opts).await {
        Ok(report) => {
            // Machine-readable output for evidence bundles.
            match serde_json::to_string_pretty(&report) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("failed to encode report json: {e}");
                    return ExitCode::from(2);
                }
            }

            if report.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            // Avoid multi-line errors; harness output should be easy to parse in CI logs.
            let msg = e.to_string().replace('\n', " ");
            eprintln!("provider contract harness failed: {msg}");
            ExitCode::from(1)
        }
    }
}
