use crate::{
    ConsumerError, LightClientData, LightClientDataSource, RequestLimits, SourceError,
    SourceErrorKind, SourceResult, SyncBudget, SyncError, SyncPolicy, SyncUsage, UpdateRange,
    sync::checked_current_slot,
};
use slot_clock::SlotClock;
use std::{future::Future, pin::Pin, time::Duration};
use tokio::time::Instant;
use types::{
    EthSpec, Hash256, LightClientBootstrap, LightClientFinalityUpdate, LightClientUpdate, Slot,
};

/// Per-task accounting and transient retries around the unchanged verification steps.
pub(crate) struct ManagedSource<'a, S, C> {
    source: &'a mut S,
    clock: &'a C,
    policy: &'a SyncPolicy,
    deadline: Instant,
    last_slot: Slot,
    no_progress: u64,
    stopped: Option<SyncError>,
    pub(crate) usage: SyncUsage,
}

impl<'a, S: Send, C: SlotClock> ManagedSource<'a, S, C> {
    pub(crate) fn new(
        source: &'a mut S,
        clock: &'a C,
        policy: &'a SyncPolicy,
        deadline: Instant,
    ) -> Result<Self, SyncError> {
        let last_slot = clock.now().ok_or(ConsumerError::ClockUnavailable)?;
        let source = Self {
            source,
            clock,
            policy,
            deadline,
            last_slot,
            no_progress: 0,
            stopped: None,
            usage: SyncUsage::default(),
        };
        source.check_deadline()?;
        Ok(source)
    }

    pub(crate) fn check_deadline(&self) -> Result<(), SyncError> {
        if Instant::now() >= self.deadline {
            return Err(SyncError::DeadlineExceeded);
        }
        Ok(())
    }

    pub(crate) fn observe_clock(&mut self) -> Result<Slot, SyncError> {
        self.check_deadline()?;
        let current = checked_current_slot(self.clock, self.last_slot)?;
        self.observe_slot(current)?;
        Ok(current)
    }

    pub(crate) fn observe_slot(&mut self, current: Slot) -> Result<(), SyncError> {
        if current < self.last_slot {
            return Err(ConsumerError::ClockWentBackwards {
                previous: self.last_slot,
                current,
            }
            .into());
        }
        self.last_slot = current;
        Ok(())
    }

    pub(crate) fn finish_step<T>(
        &mut self,
        result: Result<T, ConsumerError>,
    ) -> Result<T, SyncError> {
        if let Some(error) = self.stopped.take() {
            return Err(error);
        }
        result.map_err(SyncError::from)
    }

    pub(crate) fn reset_progress(&mut self) {
        self.no_progress = 0;
    }

    pub(crate) fn check_no_progress(&self) -> Result<(), SyncError> {
        if self.no_progress >= self.policy.max_no_progress_requests {
            return Err(SyncError::NoProgress {
                requests: self.no_progress,
            });
        }
        Ok(())
    }

    fn budget(&self, resource: SyncBudget) -> SyncError {
        let limit = match resource {
            SyncBudget::Requests => self.policy.max_requests,
            SyncBudget::Updates => self.policy.max_updates,
            SyncBudget::ResponseBytes => self.policy.max_total_response_bytes,
        };
        SyncError::BudgetExceeded { resource, limit }
    }

    fn check_capacity(&self, needs_updates: bool) -> Result<(), SyncError> {
        self.check_deadline()?;
        if self.usage.requests >= self.policy.max_requests {
            return Err(self.budget(SyncBudget::Requests));
        }
        if needs_updates && self.usage.updates >= self.policy.max_updates {
            return Err(self.budget(SyncBudget::Updates));
        }
        if self.usage.response_bytes >= self.policy.max_total_response_bytes {
            return Err(self.budget(SyncBudget::ResponseBytes));
        }
        self.check_no_progress()
    }

    pub(crate) async fn sleep(&mut self, delay: Duration) -> Result<(), SyncError> {
        self.observe_clock()?;
        self.check_capacity(true)?;
        let wake_at = Instant::now()
            .checked_add(delay)
            .filter(|wake_at| *wake_at < self.deadline)
            .ok_or(SyncError::DeadlineExceeded)?;
        tokio::time::sleep_until(wake_at).await;
        self.observe_clock()?;
        Ok(())
    }

    fn attempt_limits(
        &mut self,
        requested: RequestLimits,
        needs_updates: bool,
    ) -> Result<RequestLimits, SyncError> {
        self.observe_clock()?;
        self.check_capacity(needs_updates)?;
        let remaining_time = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(SyncError::DeadlineExceeded)?;
        let remaining_bytes = self
            .policy
            .max_total_response_bytes
            .saturating_sub(self.usage.response_bytes);
        let limits = RequestLimits::new(
            requested.timeout().min(remaining_time),
            requested.max_response_bytes().min(remaining_bytes),
        )
        .map_err(ConsumerError::from)?;
        self.usage.requests = self
            .usage
            .requests
            .checked_add(1)
            .ok_or_else(|| self.budget(SyncBudget::Requests))?;
        self.no_progress = self.no_progress.saturating_add(1);
        Ok(limits)
    }

    fn account_bytes(&mut self, received: u64) -> Result<(), SyncError> {
        self.usage.response_bytes = self
            .usage
            .response_bytes
            .checked_add(received)
            .ok_or_else(|| self.budget(SyncBudget::ResponseBytes))?;
        if self.usage.response_bytes > self.policy.max_total_response_bytes {
            return Err(self.budget(SyncBudget::ResponseBytes));
        }
        Ok(())
    }

    fn account_updates(&mut self, received: usize) -> Result<(), SyncError> {
        let received = u64::try_from(received).map_err(|_| self.budget(SyncBudget::Updates))?;
        self.usage.updates = self
            .usage
            .updates
            .checked_add(received)
            .ok_or_else(|| self.budget(SyncBudget::Updates))?;
        if self.usage.updates > self.policy.max_updates {
            return Err(self.budget(SyncBudget::Updates));
        }
        Ok(())
    }

    fn stop(&mut self, error: SyncError) -> SourceError {
        self.stopped = Some(error);
        // The private adapter must fit the source trait. The driver always calls finish_step,
        // which restores the typed error before this sentinel could cross its public boundary.
        // A genuine Configuration source error is never stored here and remains unchanged.
        SourceError {
            kind: SourceErrorKind::Configuration,
            bytes_received: 0,
            source: None,
        }
    }

    async fn request<T: Send + 'static>(
        &mut self,
        requested: RequestLimits,
        needs_updates: bool,
        count_updates: fn(&T) -> usize,
        mut send: impl for<'b> FnMut(
            &'b mut S,
            RequestLimits,
        )
            -> Pin<Box<dyn Future<Output = SourceResult<T>> + Send + 'b>>
        + Send,
    ) -> SourceResult<T> {
        let mut retries = 0u64;
        let mut retry_delay = self.policy.initial_retry_delay;
        loop {
            let limits = self
                .attempt_limits(requested, needs_updates)
                .map_err(|error| self.stop(error))?;
            let request_deadline = Instant::now()
                .checked_add(limits.timeout())
                .ok_or_else(|| self.stop(SyncError::DeadlineExceeded))?;
            let response =
                match tokio::time::timeout_at(request_deadline, send(self.source, limits)).await {
                    Ok(response) => response,
                    Err(elapsed) => Err(SourceError {
                        kind: SourceErrorKind::Transient { retry_after: None },
                        // Cancellation cannot recover the source's partial-body accounting. Charge
                        // the entire allowance, so repeated timeouts cannot evade the byte budget.
                        bytes_received: limits.max_response_bytes(),
                        source: Some(Box::new(elapsed)),
                    }),
                };
            let completed_in_time = Instant::now() < request_deadline;
            let bytes = match &response {
                Ok(response) => response.bytes_received,
                Err(error) => error.bytes_received,
            };
            self.account_bytes(bytes)
                .map_err(|error| self.stop(error))?;
            self.observe_clock().map_err(|error| self.stop(error))?;
            crate::sync::check_response_size(bytes, limits)?;
            let error = match response {
                Ok(response) => {
                    self.account_updates(count_updates(&response.data))
                        .map_err(|error| self.stop(error))?;
                    if completed_in_time {
                        return Ok(response);
                    }
                    // A source may return Ready after a long poll before Tokio checks its timer.
                    // Reject a late success but retain its measured bytes and decoded update count.
                    SourceError {
                        kind: SourceErrorKind::Transient { retry_after: None },
                        bytes_received: response.bytes_received,
                        source: Some(Box::new(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "light-client source returned after the request deadline",
                        ))),
                    }
                }
                // A late terminal source error must not become a retryable timeout.
                Err(error) => error,
            };
            let retry_after = match error.kind {
                SourceErrorKind::Transient { retry_after } => retry_after,
                _ => return Err(error),
            };
            if retries >= self.policy.max_retries {
                return Err(self.stop(SyncError::RetriesExhausted {
                    attempts: retries.saturating_add(1),
                    source: error,
                }));
            }
            let delay = retry_after.map_or(retry_delay, |hint| retry_delay.max(hint));
            if delay > self.policy.max_retry_delay {
                return Err(self.stop(SyncError::RetryDelayExceeded {
                    requested: delay,
                    maximum: self.policy.max_retry_delay,
                }));
            }
            self.sleep(delay).await.map_err(|error| self.stop(error))?;
            retries = retries.saturating_add(1);
            retry_delay = retry_delay
                .saturating_mul(2)
                .min(self.policy.max_retry_delay);
        }
    }
}

impl<E: EthSpec, S: LightClientDataSource<E>, C: SlotClock> LightClientDataSource<E>
    for ManagedSource<'_, S, C>
{
    async fn get_bootstrap(
        &mut self,
        block_root: Hash256,
        limits: RequestLimits,
    ) -> SourceResult<LightClientData<LightClientBootstrap<E>>> {
        self.request(
            limits,
            false,
            |_| 0,
            move |source, limits| Box::pin(source.get_bootstrap(block_root, limits)),
        )
        .await
    }

    async fn get_updates(
        &mut self,
        range: UpdateRange,
        limits: RequestLimits,
    ) -> SourceResult<Vec<LightClientData<LightClientUpdate<E>>>> {
        self.request(limits, true, Vec::len, move |source, limits| {
            Box::pin(source.get_updates(range, limits))
        })
        .await
    }

    async fn get_finality_update(
        &mut self,
        limits: RequestLimits,
    ) -> SourceResult<LightClientData<LightClientFinalityUpdate<E>>> {
        self.request(
            limits,
            true,
            |_| 1,
            |source, limits| Box::pin(source.get_finality_update(limits)),
        )
        .await
    }
}
