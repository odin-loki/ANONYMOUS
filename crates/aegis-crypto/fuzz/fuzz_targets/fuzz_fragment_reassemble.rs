#![no_main]

use aegis_crypto::cell::{Cell, CELL_LEN};
use aegis_crypto::fragment::{reassemble, SphinxReassembler, SPHINX_FRAGMENT_COUNT};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut ras = SphinxReassembler::new();
    let max_cells = data.len() / CELL_LEN;
    for i in 0..max_cells.min(64) {
        let start = i * CELL_LEN;
        let mut buf = [0u8; CELL_LEN];
        buf.copy_from_slice(&data[start..start + CELL_LEN]);
        let cell = Cell::from_bytes(buf);
        let _ = ras.push(&cell);
    }

    if !data.is_empty() {
        let batch_len = (data.len() / CELL_LEN).min(SPHINX_FRAGMENT_COUNT + 4);
        let cells: Vec<Cell> = (0..batch_len)
            .map(|i| {
                let start = i * CELL_LEN;
                let mut buf = [0u8; CELL_LEN];
                if start + CELL_LEN <= data.len() {
                    buf.copy_from_slice(&data[start..start + CELL_LEN]);
                } else if start < data.len() {
                    let n = data.len() - start;
                    buf[..n].copy_from_slice(&data[start..]);
                }
                Cell::from_bytes(buf)
            })
            .collect();
        let _ = reassemble(&cells);
    }
});
