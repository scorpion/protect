use anyhow::{Context, Result};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

/// Where the structured (JSON) audit trail is written, alongside — not
/// instead of — the human-readable stream on stdout. A fixed, well-known
/// path rather than a config option: this is the file a log shipper
/// (Filebeat, Fluentd, Promtail) is pointed at, or that `logrotate` is
/// configured against.
const LOG_DIR: &str = "logs";
const LOG_FILE: &str = "ldap.log";

#[tokio::main]
async fn main() -> Result<()> {
    std::fs::create_dir_all(LOG_DIR)
        .with_context(|| format!("creating log directory ./{LOG_DIR}"))?;
    // `_log_guard` flushes the background writer thread's buffer on drop;
    // holding it for the lifetime of `main` (rather than discarding it)
    // is what keeps the last few log lines from being lost on exit.
    let (file_writer, _log_guard) =
        tracing_appender::non_blocking(tracing_appender::rolling::never(LOG_DIR, LOG_FILE));

    // One filter drives both outputs, so RUST_LOG controls verbosity
    // everywhere at once rather than needing to be set twice.
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer())
        .with(
            fmt::layer()
                .json()
                .flatten_event(true)
                .with_writer(file_writer),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    ai_protect::run(&config_path).await?;
    Ok(())
}
