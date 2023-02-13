# Summary

In this document, we discuss how to commit ckb-vm and later open a commitment in a ckb contract.

## What to commit?

Basic two parts
  - properties, which are readonly, for example, version, max cycles
  - state, which are updatable during instruction execution, for example, memory and registers

We use the definition from ckb-vm code [here](https://github.com/nervosnetwork/ckb-vm/blob/develop/src/machine/mod.rs#L283)

```rust
#[derive(Default)]
pub struct DefaultCoreMachine<R, M> {
    registers: [R; RISCV_GENERAL_REGISTER_NUMBER],
    pc: R,
    next_pc: R,
    memory: M,
    cycles: u64,
    max_cycles: u64,
    running: bool,
    isa: u8,
    version: u32,
}
```

## How to commit?

We hash all the elements list in the above two parts to get a single hash, that's the vm commitment.

```pseudocode
let mut hasher = blake2b_hasher();

hasher.update("Machine");
hasher.update("Registers" | vm.registers);
hasher.update("PC" | vm.pc);
hasher.update("Next_PC" | vm.next_pc);
hasher.update("Memory" | vm.memory.commit);
hasher.update("Cycles" | vm.cycles);
hasher.update("Max_Cycles" | vm.max_cycles);
hasher.update("Running" | vm.running);
hasher.update("ISA" | vm.isa);
hasher.update("Version" | vm.version);
```

### How to commit memory?

We use sparse merkle tree for our memory, and the `size` and `smt.root` is our commitment to a memory.

Thanks to well designed ckb-vm code, we're only needed to implement `Memory` trait.

Similary to flat memory implementation in ckb-vm code [here](https://github.com/nervosnetwork/ckb-vm/blob/develop/src/memory/flat.rs)

Flat memory has two parts
  - flags for page
  - data

We can store both of two parts in smt. Using following methods to generate key
  - flag key: hash("Flag" | page)
  - data key: hash("Data" | address / 32)

Detail in code [here](https://github.com/zeroqn/woss/blob/rice-pudding/challenge/crates/woss/src/memory/prover.rs)

## How to open in contract?

We can generate smt proof for all updated key-values in memory smt. For rest of elements in the vm definition, 
provide pre-images and we're done.

```pseudocode
let machine = restore_from(pre_images);
machine.memory = restore_from(smt_proof);
assert_eq!(machine.commit(), expected_commit);
```

With all pre-images and smt proof, we're able to execute vm instruction in contract.

Detail memory code [here](https://github.com/zeroqn/woss/blob/rice-pudding/challenge/crates/woss/src/memory/verifier.rs)

Detail machine restore code [here](https://github.com/zeroqn/woss/blob/rice-pudding/challenge/crates/woss/src/machine.rs#L241)

## How to execute an instruction (step) in contract?

Again, thanks to well designed ckb-vm code. We ported it to `no_std` environment with small modifications, then simpily execute it.

Detail code [here](https://github.com/zeroqn/woss/blob/rice-pudding/challenge/crates/woss/src/machine.rs#L99)

Execution code in contract [here](https://github.com/zeroqn/woss/blob/rice-pudding/challenge/contracts/step-verifier-lock/src/entry.rs#L75)
