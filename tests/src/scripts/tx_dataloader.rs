use std::collections::HashMap;

use ckb_traits::{CellDataProvider, HeaderProvider};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellMetaBuilder, ResolvedTransaction},
        DepType, HeaderView,
    },
    packed::{Byte32, CellDep, CellInput, CellOutput, OutPoint, OutPointVec, Transaction},
    prelude::{Builder, Entity},
};

#[derive(Clone, Default)]
pub struct CellInfo {
    pub output: CellOutput,
    pub data: Bytes,
    pub data_hash: Byte32,
}

#[derive(Clone)]
pub struct InputCellInfo {
    pub input: CellInput,
    pub cell: CellInfo,
}

impl From<&InputCellInfo> for CellDep {
    fn from(value: &InputCellInfo) -> Self {
        CellDep::new_builder()
            .out_point(value.input.previous_output())
            .build()
    }
}

pub struct TxDataLoader {
    headers: HashMap<Byte32, HeaderView>,
    cell_deps: HashMap<OutPoint, CellInfo>,
    inputs: HashMap<OutPoint, CellInfo>,
}

impl Default for TxDataLoader {
    fn default() -> Self {
        Self {
            headers: Default::default(),
            cell_deps: Default::default(),
            inputs: Default::default(),
        }
    }
}

impl TxDataLoader {
    pub fn extend_inputs(&mut self, inputs: impl IntoIterator<Item = InputCellInfo>) {
        self.inputs.extend(
            inputs
                .into_iter()
                .map(|ic| (ic.input.previous_output(), ic.cell)),
        )
    }

    pub fn extend_cell_deps(&mut self, deps: impl IntoIterator<Item = InputCellInfo>) {
        self.cell_deps.extend(
            deps.into_iter()
                .map(|ic| (ic.input.previous_output(), ic.cell)),
        )
    }

    pub fn resolve_tx(&self, tx: &Transaction) -> ResolvedTransaction {
        let to_meta = |out_point: OutPoint| -> CellMeta {
            self.get_cell_meta(&out_point)
                .expect(&format!("resolve tx outpoint {}", out_point))
        };

        let mut resolved_dep_groups = vec![];
        let mut resolved_cell_deps = vec![];

        for cell_dep in tx.raw().cell_deps().into_iter() {
            let cell_meta = to_meta(cell_dep.out_point());

            match DepType::try_from(cell_dep.dep_type()).expect("valid dep type") {
                DepType::DepGroup => {
                    let data = cell_meta.mem_cell_data.as_ref().expect("valid dep group");
                    let out_points = OutPointVec::from_slice(data).expect("valid dep group");
                    let cell_deps = out_points.into_iter().map(to_meta);

                    resolved_cell_deps.extend(cell_deps);
                    resolved_dep_groups.push(cell_meta)
                }
                DepType::Code => resolved_cell_deps.push(cell_meta),
            }
        }

        let resolved_inputs: Vec<CellMeta> = {
            let to_out_point = tx.raw().inputs().into_iter().map(|d| d.previous_output());
            to_out_point.map(to_meta).collect()
        };

        ResolvedTransaction {
            transaction: tx.to_owned().into_view(),
            resolved_cell_deps,
            resolved_inputs,
            resolved_dep_groups,
        }
    }

    fn get_cell_info(&self, out_point: &OutPoint) -> Option<&CellInfo> {
        match self.cell_deps.get(out_point) {
            Some(c) => Some(c),
            None => self.inputs.get(out_point),
        }
    }

    fn get_cell_meta(&self, out_point: &OutPoint) -> Option<CellMeta> {
        self.get_cell_info(out_point).map(|ci| {
            CellMetaBuilder::from_cell_output(ci.output.to_owned(), ci.data.to_owned())
                .out_point(out_point.clone())
                .build()
        })
    }
}

impl CellDataProvider for TxDataLoader {
    fn get_cell_data(&self, out_point: &OutPoint) -> Option<Bytes> {
        self.get_cell_info(out_point).map(|ci| ci.data.to_owned())
    }

    fn get_cell_data_hash(&self, out_point: &OutPoint) -> Option<Byte32> {
        self.get_cell_info(out_point)
            .map(|ci| ci.data_hash.to_owned())
    }
}

impl HeaderProvider for TxDataLoader {
    fn get_header(&self, block_hash: &Byte32) -> Option<HeaderView> {
        self.headers.get(block_hash).cloned()
    }
}
