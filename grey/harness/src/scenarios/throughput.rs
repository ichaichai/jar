//! Scenario: measure sustained valid work-package throughput.
//!
//! The pixels service is stateful, so each work package must be built against
//! the latest service context. That makes a "fire 12 stale writes at once"
//! benchmark misleading: later submissions would be measuring stale-context
//! rejection or queueing artifacts rather than steady-state throughput.
//!
//! Instead, this scenario keeps the pipeline saturated with *valid* work:
//! submit immediately after each prior pixel is confirmed, then report the
//! sustained confirmed rate over a longer burst.
//!
//! This remains intentionally opt-in via `--scenario throughput` so that CI
//! keeps running the faster correctness-focused scenario set by default.

use std::time::{Duration, Instant};

use tracing::info;

use crate::poll::{pixel_matches, submit_pixel_work_package};
use crate::rpc::{NodeStatus, RpcClient, StorageResult};
use crate::scenarios::{LatencySample, ScenarioMetric, ScenarioResult};

const SERVICE_ID: u32 = 2000;
const BATCH_SIZE: usize = 12;
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(180);
const SETTLE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_FINALITY_LAG: u32 = 5;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PixelSpec {
    x: u8,
    y: u8,
    r: u8,
    g: u8,
    b: u8,
}

struct ThroughputStats {
    submitted: usize,
    total_window: Duration,
    submit_rpc_avg: Duration,
    confirm_avg: Duration,
    confirm_max: Duration,
    slots_elapsed: u32,
}

pub async fn run(client: &RpcClient) -> ScenarioResult {
    let start = Instant::now();

    match run_inner(client).await {
        Ok((latencies, metrics)) => ScenarioResult {
            name: "throughput",
            pass: true,
            duration: start.elapsed(),
            error: None,
            latencies,
            metrics,
        },
        Err(e) => ScenarioResult {
            name: "throughput",
            pass: false,
            duration: start.elapsed(),
            error: Some(e),
            latencies: vec![],
            metrics: vec![],
        },
    }
}

async fn run_inner(
    client: &RpcClient,
) -> Result<(Vec<LatencySample>, Vec<ScenarioMetric>), String> {
    let start_status = wait_for_finality_settle(client).await?;
    let measurement_start = Instant::now();
    let pixels = throughput_pixels();
    let mut latencies = Vec::with_capacity(pixels.len());
    let mut submit_rpcs = Vec::with_capacity(pixels.len());

    for spec in pixels {
        let submit_start = Instant::now();
        submit_pixel_work_package(client, SERVICE_ID, spec.x, spec.y, spec.r, spec.g, spec.b)
            .await
            .map_err(|e| format!("submit pixel({},{}): {e}", spec.x, spec.y))?;
        submit_rpcs.push(submit_start.elapsed());
        let storage = wait_for_pixel_storage(client, spec).await?;
        let confirm_latency = submit_start.elapsed();
        latencies.push(LatencySample {
            label: format!("pixel({},{})", spec.x, spec.y),
            duration: confirm_latency,
        });
        info!(
            "confirmed pixel ({},{}) at slot {} in {:.2}s",
            spec.x,
            spec.y,
            storage.slot,
            confirm_latency.as_secs_f64()
        );
    }

    let end_status = client
        .get_status()
        .await
        .map_err(|e| format!("failed to fetch status after throughput scenario: {e}"))?;
    let confirm_durations: Vec<Duration> = latencies.iter().map(|sample| sample.duration).collect();
    let stats = ThroughputStats {
        submitted: latencies.len(),
        total_window: measurement_start.elapsed(),
        submit_rpc_avg: average_duration(&submit_rpcs),
        confirm_avg: average_duration(&confirm_durations),
        confirm_max: confirm_durations
            .iter()
            .copied()
            .max()
            .unwrap_or(Duration::ZERO),
        slots_elapsed: end_status.head_slot.saturating_sub(start_status.head_slot),
    };

    info!(
        "throughput complete: submitted={} totalWindow={:.2}s slotsElapsed={}",
        stats.submitted,
        stats.total_window.as_secs_f64(),
        stats.slots_elapsed
    );

    Ok((latencies, build_metrics(&stats)))
}

async fn wait_for_finality_settle(client: &RpcClient) -> Result<NodeStatus, String> {
    let settle_deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        let status = client
            .get_status()
            .await
            .map_err(|e| format!("RPC error: {e}"))?;
        let lag = status.head_slot.saturating_sub(status.finalized_slot);
        if lag <= MAX_FINALITY_LAG {
            return Ok(status);
        }
        if Instant::now() > settle_deadline {
            return Err(format!(
                "finality did not settle within {:?} (head={}, finalized={}, lag={lag})",
                SETTLE_TIMEOUT, status.head_slot, status.finalized_slot
            ));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_pixel_storage(
    client: &RpcClient,
    spec: PixelSpec,
) -> Result<StorageResult, String> {
    let deadline = Instant::now() + CONFIRM_TIMEOUT;
    loop {
        if Instant::now() > deadline {
            return Err(format!(
                "pixel ({},{}) did not appear in storage within {:?}",
                spec.x, spec.y, CONFIRM_TIMEOUT
            ));
        }

        let storage = client
            .read_storage(SERVICE_ID, "00")
            .await
            .map_err(|e| format!("failed to read pixels storage: {e}"))?;
        if let Some(value) = storage.value.as_deref()
            && pixel_matches(value, spec.x, spec.y, spec.r, spec.g, spec.b)
        {
            return Ok(storage);
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn throughput_pixels() -> Vec<PixelSpec> {
    (0..BATCH_SIZE)
        .map(|i| {
            let i = i as u8;
            PixelSpec {
                x: 5 + i,
                y: 80 + (i / 6),
                r: 16u8.wrapping_add(i.wrapping_mul(17)),
                g: 32u8.wrapping_add(i.wrapping_mul(29)),
                b: 48u8.wrapping_add(i.wrapping_mul(43)),
            }
        })
        .collect()
}

fn average_duration(samples: &[Duration]) -> Duration {
    if samples.is_empty() {
        return Duration::ZERO;
    }
    let total: Duration = samples.iter().copied().sum();
    total / samples.len() as u32
}

fn build_metrics(stats: &ThroughputStats) -> Vec<ScenarioMetric> {
    let submitted = stats.submitted as f64;
    let total_secs = stats.total_window.as_secs_f64().max(f64::EPSILON);
    let slots = f64::from(stats.slots_elapsed.max(1));

    vec![
        ScenarioMetric {
            label: "submitted_wp".into(),
            value: submitted,
            unit: "count",
        },
        ScenarioMetric {
            label: "total_window_ms".into(),
            value: stats.total_window.as_secs_f64() * 1000.0,
            unit: "ms",
        },
        ScenarioMetric {
            label: "submit_rpc_avg_ms".into(),
            value: stats.submit_rpc_avg.as_secs_f64() * 1000.0,
            unit: "ms",
        },
        ScenarioMetric {
            label: "confirm_avg_ms".into(),
            value: stats.confirm_avg.as_secs_f64() * 1000.0,
            unit: "ms",
        },
        ScenarioMetric {
            label: "confirm_max_ms".into(),
            value: stats.confirm_max.as_secs_f64() * 1000.0,
            unit: "ms",
        },
        ScenarioMetric {
            label: "sustained_confirm_wp_per_sec".into(),
            value: submitted / total_secs,
            unit: "wps/s",
        },
        ScenarioMetric {
            label: "sustained_confirm_wp_per_slot".into(),
            value: submitted / slots,
            unit: "count",
        },
        ScenarioMetric {
            label: "head_slots_elapsed".into(),
            value: stats.slots_elapsed as f64,
            unit: "slots",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn assert_metric(metrics: &[ScenarioMetric], label: &str, expected: f64) {
        let actual = metrics
            .iter()
            .find(|metric| metric.label == label)
            .unwrap_or_else(|| panic!("missing metric {label}"))
            .value;
        assert!(
            (actual - expected).abs() < 0.01,
            "metric {label}: expected {expected}, got {actual}"
        );
    }

    #[test]
    fn throughput_pixels_are_unique() {
        let pixels = throughput_pixels();
        assert_eq!(pixels.len(), BATCH_SIZE);

        let unique_positions: HashSet<(u8, u8)> = pixels.iter().map(|p| (p.x, p.y)).collect();
        assert_eq!(unique_positions.len(), pixels.len());
        assert!(pixels.iter().all(|p| (80..=81).contains(&p.y)));
    }

    #[test]
    fn build_metrics_reports_expected_rates() {
        let metrics = build_metrics(&ThroughputStats {
            submitted: 12,
            total_window: Duration::from_secs(12),
            submit_rpc_avg: Duration::from_millis(250),
            confirm_avg: Duration::from_secs(1),
            confirm_max: Duration::from_secs(2),
            slots_elapsed: 4,
        });

        assert_metric(&metrics, "submitted_wp", 12.0);
        assert_metric(&metrics, "confirm_avg_ms", 1000.0);
        assert_metric(&metrics, "confirm_max_ms", 2000.0);
        assert_metric(&metrics, "sustained_confirm_wp_per_sec", 1.0);
        assert_metric(&metrics, "sustained_confirm_wp_per_slot", 3.0);
    }
}
