use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
struct MetricInfo {
    name: String,
    description: String,
    metric_type: MetricType,
    crate_name: String,
}

#[derive(Debug, Clone)]
enum MetricType {
    Counter,
    Gauge,
    Histogram,
    GaugeVec,
    CounterVec,
}

impl MetricType {
    fn grafana_unit(&self) -> &'static str {
        match self {
            MetricType::Counter | MetricType::CounterVec => "short",
            MetricType::Gauge | MetricType::GaugeVec => "short",
            MetricType::Histogram => "s", // seconds for most histograms
        }
    }
}

fn find_metrics_files(root_dir: &Path) -> Vec<PathBuf> {
    let mut metrics_files = Vec::new();

    fn visit_dirs(dir: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    // Skip certain directories
                    let dir_name = path.file_name().unwrap().to_str().unwrap();
                    if !["target", ".git", "node_modules"].contains(&dir_name) {
                        visit_dirs(&path, files)?;
                    }
                } else if path.file_name().unwrap() == "metrics.rs" {
                    files.push(path);
                }
            }
        }
        Ok(())
    }

    visit_dirs(root_dir, &mut metrics_files).ok();
    metrics_files
}

fn parse_metrics_file(file_path: &Path) -> Vec<MetricInfo> {
    let content = match fs::read_to_string(file_path) {
        Ok(content) => content,
        Err(_) => return Vec::new(),
    };

    let crate_name = extract_crate_name(file_path);
    let mut metrics = Vec::new();

    // Regex patterns for different metric types
    let patterns = vec![
        (
            r#"pub static\s+(\w+):\s*LazyLock<Result<IntCounter>>\s*=\s*LazyLock::new\(\|\|\s*\{\s*try_create_int_counter\(\s*"([^"]+)",\s*"([^"]+)""#,
            MetricType::Counter,
        ),
        (
            r#"pub static\s+(\w+):\s*LazyLock<Result<IntGauge>>\s*=\s*LazyLock::new\(\|\|\s*\{\s*try_create_int_gauge\(\s*"([^"]+)",\s*"([^"]+)""#,
            MetricType::Gauge,
        ),
        (
            r#"pub static\s+(\w+):\s*LazyLock<Result<Histogram>>\s*=\s*LazyLock::new\(\|\|\s*\{\s*try_create_histogram[^(]*\(\s*"([^"]+)",\s*"([^"]+)""#,
            MetricType::Histogram,
        ),
        (
            r#"pub static\s+(\w+):\s*LazyLock<Result<IntGaugeVec>>\s*=\s*LazyLock::new\(\|\|\s*\{\s*try_create_int_gauge_vec\(\s*"([^"]+)",\s*"([^"]+)""#,
            MetricType::GaugeVec,
        ),
        (
            r#"pub static\s+(\w+):\s*LazyLock<Result<IntCounterVec>>\s*=\s*LazyLock::new\(\|\|\s*\{\s*try_create_int_counter_vec\(\s*"([^"]+)",\s*"([^"]+)""#,
            MetricType::CounterVec,
        ),
    ];

    for (pattern, metric_type) in patterns {
        let re = Regex::new(pattern).unwrap();
        for captures in re.captures_iter(&content) {
            let metric_name = captures.get(2).unwrap().as_str().to_string();
            let description = captures.get(3).unwrap().as_str().to_string();

            metrics.push(MetricInfo {
                name: metric_name,
                description,
                metric_type: metric_type.clone(),
                crate_name: crate_name.clone(),
            });
        }
    }

    metrics
}

fn extract_crate_name(file_path: &Path) -> String {
    let path_str = file_path.to_string_lossy();

    if path_str.contains("beacon_node/beacon_chain") {
        "beacon_chain".to_string()
    } else if path_str.contains("beacon_node/http_api") {
        "http_api".to_string()
    } else if path_str.contains("beacon_node/network") {
        "network".to_string()
    } else if path_str.contains("beacon_node/execution_layer") {
        "execution_layer".to_string()
    } else if path_str.contains("beacon_node/lighthouse_network") {
        "lighthouse_network".to_string()
    } else if path_str.contains("validator_client") {
        "validator_client".to_string()
    } else if path_str.contains("slasher") {
        "slasher".to_string()
    } else if path_str.contains("lighthouse/src") {
        "lighthouse".to_string()
    } else {
        // Extract from path components
        let components: Vec<&str> = path_str.split('/').collect();
        for (i, component) in components.iter().enumerate() {
            if *component == "src" && i > 0 {
                return components[i - 1].to_string();
            }
        }
        "unknown".to_string()
    }
}

fn generate_grafana_dashboard(metrics_by_crate: HashMap<String, Vec<MetricInfo>>) -> Value {
    let mut rows = Vec::new();
    let mut panel_id = 1;

    for (crate_name, metrics) in metrics_by_crate {
        // Create a row for each crate
        let row = json!({
            "collapsed": false,
            "datasource": null,
            "gridPos": {
                "h": 1,
                "w": 24,
                "x": 0,
                "y": (rows.len() * 10) as i32
            },
            "id": panel_id,
            "panels": [],
            "title": format!("{} Metrics", crate_name.replace("_", " ").to_uppercase()),
            "type": "row"
        });
        rows.push(row);
        panel_id += 1;

        // Create panels for metrics in this crate
        let mut panels = Vec::new();
        let mut x_pos = 0;
        let mut y_pos = (rows.len() * 10) as i32;

        for (i, metric) in metrics.iter().enumerate() {
            if i % 4 == 0 && i > 0 {
                y_pos += 8;
                x_pos = 0;
            }

            let panel = create_panel(&metric, panel_id, x_pos, y_pos);
            panels.push(panel);
            panel_id += 1;
            x_pos += 6;
        }

        rows.extend(panels);
    }

    json!({
        "annotations": {
            "list": [
                {
                    "builtIn": 1,
                    "datasource": {
                        "type": "grafana",
                        "uid": "-- Grafana --"
                    },
                    "enable": true,
                    "hide": true,
                    "iconColor": "rgba(0, 211, 255, 1)",
                    "name": "Annotations & Alerts",
                    "target": {
                        "limit": 100,
                        "matchAny": false,
                        "tags": [],
                        "type": "dashboard"
                    },
                    "type": "dashboard"
                }
            ]
        },
        "editable": true,
        "fiscalYearStartMonth": 0,
        "graphTooltip": 0,
        "id": null,
        "links": [],
        "liveNow": false,
        "panels": rows,
        "refresh": "30s",
        "schemaVersion": 37,
        "style": "dark",
        "tags": ["lighthouse", "ethereum", "beacon-chain"],
        "templating": {
            "list": [
                {
                    "current": {
                        "selected": false,
                        "text": ".*",
                        "value": ".*"
                    },
                    "hide": 0,
                    "includeAll": false,
                    "label": "Instance",
                    "multi": false,
                    "name": "Instance",
                    "options": [],
                    "query": ".*",
                    "queryType": "",
                    "skipUrlSync": false,
                    "type": "textbox"
                }
            ]
        },
        "time": {
            "from": "now-1h",
            "to": "now"
        },
        "timepicker": {},
        "timezone": "",
        "title": "Lighthouse Metrics Dashboard",
        "uid": "lighthouse-metrics",
        "version": 1,
        "weekStart": ""
    })
}

fn create_panel(metric: &MetricInfo, id: i32, x: i32, y: i32) -> Value {
    let query = format!("{}{{instance=~\"$Instance\"}}", metric.name);

    json!({
        "datasource": {
            "type": "prometheus",
            "uid": null
        },
        "fieldConfig": {
            "defaults": {
                "color": {
                    "mode": "palette-classic"
                },
                "custom": {
                    "axisLabel": "",
                    "axisPlacement": "auto",
                    "barAlignment": 0,
                    "drawStyle": "line",
                    "fillOpacity": 10,
                    "gradientMode": "none",
                    "hideFrom": {
                        "legend": false,
                        "tooltip": false,
                        "vis": false
                    },
                    "lineInterpolation": "linear",
                    "lineWidth": 1,
                    "pointSize": 5,
                    "scaleDistribution": {
                        "type": "linear"
                    },
                    "showPoints": "never",
                    "spanNulls": false,
                    "stacking": {
                        "group": "A",
                        "mode": "none"
                    },
                    "thresholdsStyle": {
                        "mode": "off"
                    }
                },
                "mappings": [],
                "thresholds": {
                    "mode": "absolute",
                    "steps": [
                        {
                            "color": "green",
                            "value": null
                        },
                        {
                            "color": "red",
                            "value": 80
                        }
                    ]
                },
                "unit": metric.metric_type.grafana_unit()
            },
            "overrides": []
        },
        "gridPos": {
            "h": 8,
            "w": 6,
            "x": x,
            "y": y
        },
        "id": id,
        "options": {
            "legend": {
                "calcs": [],
                "displayMode": "list",
                "placement": "bottom"
            },
            "tooltip": {
                "mode": "single",
                "sort": "none"
            }
        },
        "targets": [
            {
                "datasource": {
                    "type": "prometheus",
                    "uid": "prometheus"
                },
                "expr": query,
                "interval": "",
                "legendFormat": "",
                "refId": "A"
            }
        ],
        "title": metric.name,
        "description": metric.description,
        "type": "timeseries"
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let lighthouse_path = std::env::args().nth(1).unwrap_or_else(|| ".".to_string());

    let root_path = Path::new(&lighthouse_path);

    println!("Scanning for metrics.rs files in: {}", root_path.display());

    let metrics_files = find_metrics_files(root_path);
    println!("Found {} metrics.rs files", metrics_files.len());

    let mut all_metrics: HashMap<String, Vec<MetricInfo>> = HashMap::new();

    for file in &metrics_files {
        println!("Parsing: {}", file.display());
        let metrics = parse_metrics_file(file);

        for metric in metrics {
            all_metrics
                .entry(metric.crate_name.clone())
                .or_insert_with(Vec::new)
                .push(metric);
        }
    }

    println!("Found metrics in {} crates:", all_metrics.len());
    for (crate_name, metrics) in &all_metrics {
        println!("  {}: {} metrics", crate_name, metrics.len());
    }

    let dashboard = generate_grafana_dashboard(all_metrics);

    let output_file = "lighthouse_metrics_dashboard.json";
    fs::write(output_file, serde_json::to_string_pretty(&dashboard)?)?;

    println!("Dashboard generated: {}", output_file);

    Ok(())
}
