use crate::blockchain::db::kv::Datastore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;

use crate::blockchain::proto::tx::TxOutpoint;

use rkv::StoreError;
use std::{thread, time};
/// Tarjan's Union-Find data structure.
//#[derive(RustcDecodable, RustcEncodable)]
pub struct DisjointSet {
    pub set_size: usize,
    pub parent: Vec<usize>,
    pub rank: Vec<usize>,
    pub map: Datastore, //HashMap<T, usize>, // Each T entry is mapped onto a usize tag.
}

impl DisjointSet {
    pub fn new(file_name: &str, db_name: &str) -> Result<Self, StoreError> {
        const CAPACITY: usize = 1000000;
        Ok(DisjointSet {
            set_size: 0,
            parent: Vec::with_capacity(CAPACITY),
            rank: Vec::with_capacity(CAPACITY),
            map: Datastore::new(file_name, db_name)?, //HashMap::with_capacity(CAPACITY),
        })
    }

    pub fn make_set(&mut self, x: String) {
        if self.map.contains_key_address(&x) {
            return;
        }

        let len = &mut self.set_size;
        match self.map.insert_length(&x, *len) {
            Err(_) => {
                let ten_millis = time::Duration::from_millis(30);
                thread::sleep(ten_millis);
                self.map.insert_length(&x, *len).unwrap();
                self.map.increment_size();
            }
            Ok(_) => {
                self.map.increment_size();
            }
        };
        self.parent.push(*len);
        self.rank.push(0);

        *len += 1;
    }

    /// Returns Some(num), num is the tag of subset in which x is.
    /// If x is not in the data structure, it returns None.
    pub fn find(&mut self, x: &str) -> Option<usize> {
        let pos: usize;
        match self.map.get_length(&x) {
            Some(p) => {
                pos = p;
            }
            None => return None,
        }

        let ret = DisjointSet::find_internal(&mut self.parent, pos);
        Some(ret)
    }

    /// Implements path compression.
    fn find_internal(p: &mut Vec<usize>, n: usize) -> usize {
        if p[n] != n {
            let parent = p[n];
            p[n] = DisjointSet::find_internal(p, parent);
            p[n]
        } else {
            n
        }
    }

    /// Union the subsets to which x and y belong.
    /// If it returns Ok<u32>, it is the tag for unified subset.
    /// If it returns Err(), at least one of x and y is not in the disjoint-set.
    pub fn union(&mut self, x: String, y: String) -> Result<usize, ()> {
        let x_root;
        let y_root;
        let x_rank;
        let y_rank;
        match self.find(&x) {
            Some(x_r) => {
                x_root = x_r;
                x_rank = self.rank[x_root];
            }
            None => {
                return Err(());
            }
        }

        match self.find(&y) {
            Some(y_r) => {
                y_root = y_r;
                y_rank = self.rank[y_root];
            }
            None => {
                return Err(());
            }
        }

        // Implements union-by-rank optimization.
        if x_root == y_root {
            return Ok(x_root);
        }

        if x_rank > y_rank {
            self.parent[y_root] = x_root;
            return Ok(x_root);
        } else {
            self.parent[x_root] = y_root;
            if x_rank == y_rank {
                self.rank[y_root] += 1;
            }
            return Ok(y_root);
        }
    }

    /// Forces all laziness, updating every tag.
    pub fn finalize(&mut self) {
        debug!(target: "Clusterizer [finalize]", "Finalizing clusters.");
        for i in 0..self.set_size {
            DisjointSet::find_internal(&mut self.parent, i);
        }
        debug!(target: "Clusterizer [finalize]", "Clusters finalized.");
    }
}
