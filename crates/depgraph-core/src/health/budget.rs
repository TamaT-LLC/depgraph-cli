#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HealthAnalysisError {
    #[error("health analysis was cancelled")]
    Cancelled,
    #[error("health analysis exhausted its bounded work budget")]
    ResourceExhausted,
    #[error("health analysis detected an invalid graph result")]
    Integrity,
}

pub(crate) struct HealthAnalysisBudget {
    used: usize,
    maximum: usize,
}

impl HealthAnalysisBudget {
    pub(crate) const fn new(maximum: usize) -> Self {
        Self { used: 0, maximum }
    }

    pub(crate) fn step(
        &mut self,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<(), HealthAnalysisError> {
        if is_cancelled() {
            return Err(HealthAnalysisError::Cancelled);
        }
        if self.used >= self.maximum {
            return Err(HealthAnalysisError::ResourceExhausted);
        }
        self.used += 1;
        Ok(())
    }
}
