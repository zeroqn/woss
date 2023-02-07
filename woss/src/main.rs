use std::{fs, ops::Deref};

use ckb_vm::RISCV_MAX_MEMORY;
use machine::StepCommitment;
use rand::Rng;

pub mod common;
pub mod dissection;
pub mod machine;
pub mod memory;
pub mod prover;
pub mod types;
pub mod verifier;

use crate::{dissection::StepDiffFinder, prover::Prover, verifier::Verifier};

fn forge_steps(mut steps: Vec<StepCommitment>, start_at: u64) -> Vec<StepCommitment> {
    let mut rng = rand::rngs::OsRng::default();
    let (_same, diff) = steps.split_at_mut(start_at as usize);
    diff.iter_mut()
        .for_each(|sc| sc.commitment = (rng.gen::<[u8; 32]>()).into());
    steps.to_vec()
}

enum Finder {
    Challenger(StepDiffFinder),
    Producer(StepDiffFinder),
}

impl Deref for Finder {
    type Target = StepDiffFinder;

    fn deref(&self) -> &Self::Target {
        match self {
            Finder::Challenger(ref f) => f,
            Finder::Producer(ref f) => f,
        }
    }
}

fn main() {
    let mut prover = Prover::<u32>::new(RISCV_MAX_MEMORY);
    // https://github.com/nervosnetwork/ckb-vm/blob/develop/tests/programs/simple
    let buffer = fs::read("./simple").unwrap().into();
    prover.load_program(&buffer).unwrap();

    let result = prover.run().unwrap();
    println!("step count: {}", result.step_count);

    prover.reset();
    prover.load_program(&buffer).unwrap();

    // Step 0 should not be challenged
    let random_diff_step = rand::rngs::OsRng::default().gen::<u64>() % (result.step_count - 1) + 1;
    let forged_steps = forge_steps(result.step_commitments.clone(), random_diff_step);
    let diff_step = forged_steps[random_diff_step as usize];
    let correct_step = result.step_commitments[random_diff_step as usize];
    assert_ne!(diff_step, correct_step);
    println!("random diff step {}", random_diff_step);

    let producer = Finder::Producer(StepDiffFinder::new(forged_steps));
    let challenger = Finder::Challenger(StepDiffFinder::new(result.step_commitments.clone()));

    let mut steps_to_diff = producer.step_range(0, result.step_count as usize);
    let mut next = &challenger;

    while steps_to_diff.len() > 1 {
        let (start, end) = next.diff_step_range(&steps_to_diff);
        steps_to_diff = if start == end {
            vec![*start]
        } else {
            next.step_range(start.step_num as usize, end.step_num as usize)
        };
        next = if matches!(next, Finder::Challenger(_)) {
            &producer
        } else {
            &challenger
        }
    }
    assert_eq!(diff_step.step_num, steps_to_diff.first().unwrap().step_num);

    let last_same_step = *result
        .step_commitments
        .get((diff_step.step_num - 1) as usize)
        .unwrap();
    let result = prover.run_until_step(last_same_step.step_num).unwrap();
    assert_eq!(result.step_count, last_same_step.step_num);

    let proof = prover.prove_next_step().unwrap();
    let mut verifier = Verifier::<u32>::from_proof(proof).unwrap();
    assert_eq!(last_same_step, verifier.commit_step().unwrap());

    verifier.execute_next_step().unwrap();
    assert_ne!(diff_step, verifier.commit_step().unwrap());
    assert_eq!(correct_step, verifier.commit_step().unwrap());
    println!("challenge diff step {} success", diff_step.step_num);
}
