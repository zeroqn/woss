macro_rules! impl_conversion_for_entity_unpack {
    ($original:ty, $entity:ident) => {
        impl Unpack<$original> for packed::$entity {
            fn unpack(&self) -> $original {
                self.as_reader().unpack()
            }
        }
    };
}

macro_rules! impl_conversion_for_vector_pack {
    ($original:ty, $entity:ident) => {
        impl Pack<packed::$entity> for [$original] {
            fn pack(&self) -> packed::$entity {
                packed::$entity::new_builder()
                    .set(self.iter().map(|v| v.pack()).collect())
                    .build()
            }
        }
    };
}

macro_rules! impl_conversion_for_vector_unpack {
    ($original:ty, $entity:ident, $reader:ident) => {
        impl<'r> Unpack<Vec<$original>> for packed::$reader<'r> {
            fn unpack(&self) -> Vec<$original> {
                self.iter().map(|x| x.unpack()).collect()
            }
        }
        impl_conversion_for_entity_unpack!(Vec<$original>, $entity);
    };
}

macro_rules! impl_conversion_for_vector {
    ($original:ty, $entity:ident, $reader:ident) => {
        impl_conversion_for_vector_pack!($original, $entity);
        impl_conversion_for_vector_unpack!($original, $entity, $reader);
    };
}

macro_rules! impl_conversion_for_packed_iterator_pack {
    ($item:ident, $vec:ident) => {
        impl<T> PackVec<packed::$vec, packed::$item> for T
        where
            T: IntoIterator<Item = packed::$item>,
        {
            fn pack(self) -> packed::$vec {
                packed::$vec::new_builder().extend(self).build()
            }
        }
    };
}

macro_rules! impl_conversion_for_registers_pack {
    ($reg:ty, $entity:ident) => {
        impl Pack<packed::$entity> for [$reg; RISCV_GENERAL_REGISTER_NUMBER] {
            fn pack(&self) -> packed::$entity {
                let mut registers: [_; RISCV_GENERAL_REGISTER_NUMBER] = Default::default();
                for idx in 0..RISCV_GENERAL_REGISTER_NUMBER {
                    registers[idx] = self[idx].pack();
                }

                packed::$entity::new_builder().set(registers).build()
            }
        }
    };
}

macro_rules! impl_conversion_for_registers_unpack {
    ($reg:ty, $regreader:ident, $entity:ident, $reader:ident) => {
        impl<'r> Unpack<[$reg; RISCV_GENERAL_REGISTER_NUMBER]> for packed::$reader<'r> {
            fn unpack(&self) -> [$reg; RISCV_GENERAL_REGISTER_NUMBER] {
                let mut registers: [$reg; RISCV_GENERAL_REGISTER_NUMBER] = Default::default();

                for idx in 0..RISCV_GENERAL_REGISTER_NUMBER {
                    let start = idx * 4;
                    let end = idx * 4 + 4;
                    registers[idx] =
                        packed::$regreader::new_unchecked(&self.as_slice()[start..end]).unpack();
                }

                registers
            }
        }
        impl_conversion_for_entity_unpack!([$reg; RISCV_GENERAL_REGISTER_NUMBER], $entity);
    };
}

macro_rules! impl_conversion_for_registers {
    ($reg:ty, $regreader:ident, $entity:ident, $reader:ident) => {
        impl_conversion_for_registers_pack!($reg, $entity);
        impl_conversion_for_registers_unpack!($reg, $regreader, $entity, $reader);
    };
}

macro_rules! impl_conversion_for_step_proof_pack {
    ($original:ty, $entity:ident) => {
        impl Pack<packed::$entity> for $original {
            fn pack(&self) -> packed::$entity {
                assert!(u8::from(true) == 1);

                packed::$entity::new_builder()
                    .step_num(self.step_num.pack())
                    .registers(self.registers.pack())
                    .pc(self.pc.pack())
                    .next_pc(self.next_pc.pack())
                    .memory(self.memory.pack())
                    .cycles(self.cycles.pack())
                    .max_cycles(self.max_cycles.pack())
                    .running(u8::from(self.running).into())
                    .isa(self.isa.into())
                    .version(self.version.pack())
                    .build()
            }
        }
    };
}

macro_rules! impl_conversion_for_step_proof_unpack {
    ($original:ty, $entity:ident, $reader:ident) => {
        impl<'r> Unpack<$original> for packed::$reader<'r> {
            #[inline]
            fn unpack(&self) -> $original {
                StepProof {
                    step_num: self.step_num().unpack(),
                    registers: self.registers().unpack(),
                    pc: self.pc().unpack(),
                    next_pc: self.next_pc().unpack(),
                    memory: self.memory().unpack(),
                    cycles: self.cycles().unpack(),
                    max_cycles: self.max_cycles().unpack(),
                    running: (Into::<u8>::into(self.running()) == 1),
                    isa: self.isa().into(),
                    version: self.version().unpack(),
                }
            }
        }
        impl_conversion_for_entity_unpack!($original, $entity);
    };
}

macro_rules! impl_conversion_for_step_proof {
    ($original:ty, $entity:ident, $reader:ident) => {
        impl_conversion_for_step_proof_pack!($original, $entity);
        impl_conversion_for_step_proof_unpack!($original, $entity, $reader);
    };
}
