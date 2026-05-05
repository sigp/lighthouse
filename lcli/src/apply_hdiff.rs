use clap::ArgMatches;
use clap_utils::parse_required;
use eth2_network_config::Eth2NetworkConfig;
use ssz::Decode;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use store::config::StoreConfig;
use store::hdiff::{HDiff, HDiffBuffer};
use tracing::span::{Attributes, Id};
use tracing::{Subscriber, debug_span, info};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use types::{BeaconState, ChainSpec, EthSpec};

pub fn run<E: EthSpec>(
    network_config: Eth2NetworkConfig,
    matches: &ArgMatches,
) -> Result<(), String> {
    let spec = &network_config
        .chain_spec::<E>()
        .map_err(|e| format!("Unable to get chain spec: {:?}", e))?;

    let state_path: PathBuf = parse_required(matches, "state-path")?;
    let hdiff_path: PathBuf = parse_required(matches, "hdiff-path")?;

    let state_bytes = read_file(&state_path)?;
    let hdiff_bytes = read_file(&hdiff_path)?;

    let state = BeaconState::<E>::from_ssz_bytes(&state_bytes, spec)
        .map_err(|e| format!("Failed to decode BeaconState: {:?}", e))?;
    let hdiff = HDiff::from_ssz_bytes(&hdiff_bytes)
        .map_err(|e| format!("Failed to decode HDiff: {:?}", e))?;

    with_timing(|| run_inner::<E>(spec, state, hdiff))
}

fn run_inner<E: EthSpec>(
    spec: &ChainSpec,
    state: BeaconState<E>,
    hdiff: HDiff,
) -> Result<(), String> {
    let mut buffer =
        debug_span!("state_to_hdiff_buffer").in_scope(|| HDiffBuffer::from_state(state));

    let config = StoreConfig::default();
    debug_span!("hdiff_apply")
        .in_scope(|| hdiff.apply(&mut buffer, &config))
        .map_err(|e| format!("Failed to apply HDiff: {:?}", e))?;

    let _result_state: BeaconState<E> = debug_span!("hdiff_buffer_to_state").in_scope(|| {
        buffer
            .as_state(spec)
            .map_err(|e| format!("Failed to convert HDiffBuffer to BeaconState: {:?}", e))
    })?;

    log_hdiff_sizes(&hdiff);

    Ok(())
}

pub(crate) fn log_hdiff_sizes(hdiff: &HDiff) {
    let sizes = hdiff.sizes();
    let labels = [
        "state_diff",
        "balances_diff",
        "inactivity_scores_diff",
        "validators_diff",
        "historical_roots",
        "historical_summaries",
    ];
    info!("");
    info!("HDiff component sizes:");
    for (label, size) in labels.iter().zip(sizes.iter()) {
        info!("  {:<22}  {:>12}", label, format_bytes(*size));
    }
    info!("  {:<22}  {:>12}", "total", format_bytes(hdiff.size()));
}

pub(crate) fn read_file(path: &PathBuf) -> Result<Vec<u8>, String> {
    let mut file =
        File::open(path).map_err(|e| format!("Unable to open file {:?}: {:?}", path, e))?;
    let mut bytes = vec![];
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("Unable to read file {:?}: {:?}", path, e))?;
    Ok(bytes)
}

/// Install a scoped subscriber that:
/// - formats `info!` events as bare messages (no timestamps/levels)
/// - collects `debug_span!` durations via [`TimingCollector`] and prints a summary table
///   before returning
pub(crate) fn with_timing<R>(f: impl FnOnce() -> R) -> R {
    let collector = TimingCollector::default();
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_level(false)
        .without_time();
    let subscriber = tracing_subscriber::registry()
        .with(LevelFilter::DEBUG)
        .with(fmt_layer)
        .with(collector.clone());

    tracing::subscriber::with_default(subscriber, || {
        let result = f();
        collector.print_summary();
        result
    })
}

#[derive(Clone, Default)]
struct TimingCollector {
    entries: Arc<Mutex<Vec<TimingEntry>>>,
}

struct TimingEntry {
    name: &'static str,
    depth: usize,
    duration: Duration,
}

struct SpanStart {
    index: usize,
    start: Instant,
}

impl<S> Layer<S> for TimingCollector
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, _attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let depth = span.scope().skip(1).count();
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        let index = entries.len();
        entries.push(TimingEntry {
            name: span.name(),
            depth,
            duration: Duration::ZERO,
        });
        drop(entries);
        span.extensions_mut().insert(SpanStart {
            index,
            start: Instant::now(),
        });
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };
        let ext = span.extensions();
        let Some(s) = ext.get::<SpanStart>() else {
            return;
        };
        let elapsed = s.start.elapsed();
        let index = s.index;
        drop(ext);
        if let Ok(mut entries) = self.entries.lock()
            && let Some(entry) = entries.get_mut(index)
        {
            entry.duration = elapsed;
        }
    }
}

impl TimingCollector {
    fn print_summary(&self) {
        let Ok(entries) = self.entries.lock() else {
            return;
        };
        if entries.is_empty() {
            return;
        }

        const DUR_WIDTH: usize = 10;
        let name_width = entries
            .iter()
            .map(|e| e.name.len() + e.depth * 2)
            .max()
            .unwrap_or(0)
            .max("Phase".len());

        let total: Duration = entries
            .iter()
            .filter(|e| e.depth == 0)
            .map(|e| e.duration)
            .sum();

        let sep = format!("{}  {}", "-".repeat(name_width), "-".repeat(DUR_WIDTH));
        info!("");
        info!(
            "{:<nw$}  {:>dw$}",
            "Phase",
            "Duration",
            nw = name_width,
            dw = DUR_WIDTH
        );
        info!("{}", sep);
        for entry in entries.iter() {
            let name = format!("{}{}", "  ".repeat(entry.depth), entry.name);
            info!(
                "{:<nw$}  {:>dw$}",
                name,
                format_duration(entry.duration),
                nw = name_width,
                dw = DUR_WIDTH
            );
        }
        info!("{}", sep);
        info!(
            "{:<nw$}  {:>dw$}",
            "Total",
            format_duration(total),
            nw = name_width,
            dw = DUR_WIDTH
        );
    }
}

pub(crate) fn format_duration(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs >= 1.0 {
        format!("{:.2} s", secs)
    } else if secs * 1_000.0 >= 1.0 {
        format!("{:.2} ms", secs * 1_000.0)
    } else {
        format!("{:.2} µs", secs * 1_000_000.0)
    }
}

fn format_bytes(bytes: usize) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    let b = bytes as f64;
    if b >= MIB {
        format!("{:.2} MiB", b / MIB)
    } else if b >= KIB {
        format!("{:.2} KiB", b / KIB)
    } else {
        format!("{} B", bytes)
    }
}
