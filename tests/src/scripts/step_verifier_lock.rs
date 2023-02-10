use std::{fs, io::Read, path::PathBuf};

use ckb_script::TransactionScriptsVerifier;
use ckb_types::{
    bytes::Bytes,
    core::ScriptHashType,
    packed::{
        CellDep, CellInput, CellOutput, OutPoint, RawTransaction, Script, Transaction, Uint64,
        WitnessArgs,
    },
    prelude::{Builder, Entity, Pack, PackVec},
};
use once_cell::sync::Lazy;
use rand::Rng;
use woss::{prover::Prover, types::conversion::Pack as WossPack, verifier::Verifier};

use crate::scripts::tx_dataloader::TxDataLoader;

use super::tx_dataloader::{CellInfo, InputCellInfo};

const SCRIPT_DIR: &str = "../challenge/build/release";
const STEP_VERIFIER_LOCK: &str = "step-verifier-lock";

static STEP_VERIFIER_LOCK_PROGRAM: Lazy<Bytes> = Lazy::new(|| {
    let mut buf = Vec::new();
    let mut path = PathBuf::new();
    path.push(&SCRIPT_DIR);
    path.push(&STEP_VERIFIER_LOCK);
    let mut f = fs::File::open(&path).expect("load program");
    f.read_to_end(&mut buf).expect("read program");
    Bytes::from(buf.to_vec())
});

static STEP_VERIFIER_LOCK_CODE_HASH: Lazy<[u8; 32]> = Lazy::new(|| {
    const CKB_PERSONALIZATION: &[u8] = b"ckb-default-hash";

    let mut buf = [0u8; 32];
    let mut hasher = blake2b_ref::Blake2bBuilder::new(32)
        .personal(CKB_PERSONALIZATION)
        .build();
    hasher.update(&STEP_VERIFIER_LOCK_PROGRAM);
    hasher.finalize(&mut buf);
    buf
});

#[test]
fn test_step_verifier_lock() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut prover = Prover::<u32>::new(4 << 20);
    // https://github.com/nervosnetwork/ckb-vm/blob/develop/tests/programs/simple
    let buffer = fs::read("../simple").unwrap().into();
    prover.load_program(&buffer).unwrap();

    let result = prover.run().unwrap();
    println!("step count: {}", result.step_count);

    prover.reset();
    prover.load_program(&buffer).unwrap();

    let random_step_num = rand::rngs::OsRng::default().gen::<u64>() % (result.step_count - 1) + 1;
    println!("random step {}", random_step_num);

    let random_step = result.step_commitments[random_step_num as usize];
    let prev_step = result.step_commitments[(random_step.step_num - 1) as usize];
    let result = prover.run_until_step(prev_step.step_num).unwrap();
    assert_eq!(result.step_count, prev_step.step_num);

    let proof = prover.prove_next_step().unwrap();
    let mut verifier = Verifier::<u32>::from_proof(proof.clone()).unwrap();
    assert_eq!(prev_step, verifier.commit_step().unwrap());

    verifier.execute_next_step().unwrap();
    assert_eq!(random_step, verifier.commit_step().unwrap());

    // Test verifier in lock contract
    let verifier_lock_cell = {
        let cell = CellInfo {
            output: CellOutput::new_builder()
                .capacity(Pack::pack(&u64::MAX))
                .build(),
            data: STEP_VERIFIER_LOCK_PROGRAM.clone(),
            data_hash: STEP_VERIFIER_LOCK_CODE_HASH.pack(),
        };
        let out_point = OutPoint::new_builder()
            .tx_hash(rand::random::<[u8; 32]>().pack())
            .build();
        InputCellInfo {
            input: CellInput::new_builder().previous_output(out_point).build(),
            cell,
        }
    };

    let test_input_cell = {
        let args = {
            let mut com = prev_step.commitment.to_vec();
            com.extend_from_slice(&random_step.commitment);
            Pack::pack(com.as_slice())
        };
        // Enable vm version1
        let lock = Script::new_builder()
            .code_hash(STEP_VERIFIER_LOCK_CODE_HASH.pack())
            .args(args)
            .build();

        let cell = CellInfo {
            output: CellOutput::new_builder()
                .capacity(Pack::<Uint64>::pack(&u64::MAX))
                .lock(lock)
                .build(),
            ..Default::default()
        };
        let out_point = OutPoint::new_builder()
            .tx_hash(rand::random::<[u8; 32]>().pack())
            .build();
        InputCellInfo {
            input: CellInput::new_builder().previous_output(out_point).build(),
            cell,
        }
    };

    let raw_tx = RawTransaction::new_builder()
        .cell_deps(vec![CellDep::from(&verifier_lock_cell)].pack())
        .inputs(vec![test_input_cell.input.clone()].pack())
        .build();
    let witness = WitnessArgs::new_builder()
        .lock(Some(proof.pack().as_bytes()).pack())
        .build();
    let tx = Transaction::new_builder()
        .raw(raw_tx)
        .witnesses(vec![witness.as_bytes()].pack())
        .build();

    let mut tx_dataloader = TxDataLoader::default();
    tx_dataloader.extend_cell_deps(vec![verifier_lock_cell]);
    tx_dataloader.extend_inputs(vec![test_input_cell]);

    let resolved_tx = tx_dataloader.resolve_tx(&tx);
    let cycles = TransactionScriptsVerifier::new(&resolved_tx, &tx_dataloader)
        .verify(u64::MAX)
        .unwrap();

    println!("cycles {}", cycles);
}
