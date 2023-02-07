use crate::machine::StepCommitment;

const MAX_STEP_CHUNKS: usize = 40;

pub struct StepDiffFinder {
    step_commitments: Vec<StepCommitment>,
}

impl StepDiffFinder {
    pub fn new(step_commitments: Vec<StepCommitment>) -> Self {
        Self { step_commitments }
    }

    pub fn diff_step_range<'a, 'b: 'a>(
        &'a self,
        step_commitments: &'b [StepCommitment],
    ) -> (&'a StepCommitment, &'a StepCommitment) {
        let (idx, last_diff_step) = step_commitments
            .iter()
            .enumerate()
            .find(|(_idx, sc)| self.step_commitments.binary_search(sc).is_err())
            .unwrap();
        if step_commitments.len() < MAX_STEP_CHUNKS {
            return (last_diff_step, last_diff_step);
        }

        (&step_commitments[idx - 1], last_diff_step)
    }

    pub fn step_range(&self, start: usize, end: usize) -> Vec<StepCommitment> {
        assert!((start < end) && (end < self.step_commitments.len()));

        let chunks = if end - start + 1 < MAX_STEP_CHUNKS {
            end - start + 1
        } else {
            MAX_STEP_CHUNKS
        };

        let mut position = start;
        let chunk_len = (end - start) / chunks + 1;
        let mut range = Vec::with_capacity(chunks);
        for idx in 0..chunks {
            if idx == chunks - 1 {
                position = end;
            }
            range.push(self.step_commitments[position]);
            position += chunk_len;
        }

        range
    }
}
