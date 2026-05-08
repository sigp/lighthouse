//! OpenTelemetry samplers for filtering traces.

use opentelemetry::Context;
use opentelemetry::trace::{Link, SamplingDecision, SamplingResult, SpanKind, TraceState};
use opentelemetry_sdk::trace::ShouldSample;

/// A sampler that only samples spans whose names start with a given prefix.
///
/// This sampler is designed to be used with `Sampler::ParentBased`, which will:
/// - Use this sampler's decision for root spans (no parent)
/// - Automatically inherit the parent's sampling decision for child spans
///
/// This ensures that only traces starting from known instrumented code paths are exported,
/// reducing noise from partially instrumented code paths.
#[derive(Debug, Clone)]
pub struct PrefixBasedSampler {
    prefix: &'static str,
}

impl PrefixBasedSampler {
    pub fn new(prefix: &'static str) -> Self {
        Self { prefix }
    }
}

impl ShouldSample for PrefixBasedSampler {
    fn should_sample(
        &self,
        _parent_context: Option<&Context>,
        _trace_id: opentelemetry::trace::TraceId,
        name: &str,
        _span_kind: &SpanKind,
        _attributes: &[opentelemetry::KeyValue],
        _links: &[Link],
    ) -> SamplingResult {
        if name.starts_with(self.prefix) {
            SamplingResult {
                decision: SamplingDecision::RecordAndSample,
                attributes: Vec::new(),
                trace_state: TraceState::default(),
            }
        } else {
            SamplingResult {
                decision: SamplingDecision::Drop,
                attributes: Vec::new(),
                trace_state: TraceState::default(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::TraceId;

    #[test]
    fn prefix_based_sampler_filters_by_prefix() {
        let sampler = PrefixBasedSampler::new("test_");
        let trace_id = TraceId::from_hex("0123456789abcdef0123456789abcdef").unwrap();

        // Spans with prefix should be sampled
        let result = sampler.should_sample(
            None,
            trace_id,
            "test_my_span",
            &SpanKind::Internal,
            &[],
            &[],
        );
        assert!(matches!(result.decision, SamplingDecision::RecordAndSample));

        // Spans without prefix should be dropped
        let result =
            sampler.should_sample(None, trace_id, "other_span", &SpanKind::Internal, &[], &[]);
        assert!(matches!(result.decision, SamplingDecision::Drop));
    }
}
