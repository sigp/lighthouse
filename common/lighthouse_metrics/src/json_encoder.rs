use prometheus::{Encoder, Result};

use prometheus::proto::{MetricFamily, MetricType};
use std::io::Write;

/// An encoder that encodes all `Count` and `Gauge` metrics to a flat json
/// without any labels.
pub struct JsonEncoder {
    required_metrics: Vec<String>,
}

impl JsonEncoder {
    pub fn new(required_metrics: Vec<String>) -> Self {
        JsonEncoder { required_metrics }
    }
}

impl Encoder for JsonEncoder {
    fn encode<W: Write>(&self, metric_families: &[MetricFamily], writer: &mut W) -> Result<()> {
        writer.write_all(b"{\n")?;
        for (i, mf) in metric_families
            .iter()
            .filter(|mf| {
                self.required_metrics
                    .iter()
                    .any(|name| mf.get_name() == *name)
            })
            .enumerate()
        {
            let name = mf.get_name();
            if i != 0 {
                writer.write_all(b",")?;
            }

            for metric in mf.get_metric() {
                let value = match mf.get_field_type() {
                    MetricType::COUNTER => metric.get_counter().get_value().to_string(),
                    MetricType::GAUGE => metric.get_gauge().get_value().to_string(),
                    _ => {
                        // TODO: have a better error message
                        return Err(prometheus::Error::Msg(
                            "Cannot encode this metric".to_string(),
                        ));
                    }
                };
                writer.write_all(b"\"")?;
                writer.write_all(name.as_bytes())?;
                writer.write_all(b"\":")?;
                writer.write_all(value.as_bytes())?;
            }
        }
        writer.write_all(b"}")?;

        Ok(())
    }

    fn format_type(&self) -> &str {
        "json"
    }
}
