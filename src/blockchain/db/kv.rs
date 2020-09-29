use crate::blockchain::proto::tx::TxOutpoint;
use rkv::{Manager, Rkv, SingleStore, StoreError, StoreOptions, Value};
//use rkv::backend::{Lmdb, LmdbEnvironment};

use bincode;
use rkv::backend::{
    Lmdb, LmdbDatabase, LmdbEnvironment, SafeMode, SafeModeDatabase, SafeModeEnvironment,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub struct Datastore {
    pub store: SingleStore<LmdbDatabase>,
    pub env: Rkv<LmdbEnvironment>,
    database_size: usize,
}

impl Datastore {
    pub fn new(file_name: &str, db_name: &str) -> Result<Self, StoreError>
    where
        Self: Sized,
    {
        let path_file = format!("./blockparser/{}", file_name);
        let path = Path::new(&path_file);
        match fs::create_dir_all(path) {
            Ok(_) => {
                println!("Database folder created or reuse");
            }
            Err(e) => {
                println!("Error message: {:?}", e);
                panic!("Failed to access or create database folder");
            }
        }

        let k = Rkv::new::<Lmdb>(path)?;
        let store = k.open_single(db_name, StoreOptions::create())?;

        Ok(Datastore {
            store,
            env: k,
            database_size: 0,
        })
    }

    pub fn insert(&mut self, x: TxOutpoint, address: String) -> Result<(), StoreError> {
        let mut writer = self.env.write().unwrap();

        let tx = bincode::serialize(&x).unwrap();
        self.store
            .put(&mut writer, &tx, &Value::Str(&address))
            .unwrap();
        writer.commit()
    }

    pub fn insert_length(&mut self, x: &str, length: usize) -> Result<(), StoreError> {
        let mut writer = self.env.write().unwrap();

        self.store
            .put(&mut writer, &x, &Value::U64(length as u64))
            .unwrap();
        writer.commit()
    }

    pub fn remove(&mut self, x: &TxOutpoint) {
        let mut writer = self.env.write().unwrap();

        let tx = bincode::serialize(&x).unwrap();
        self.store.delete(&mut writer, tx).unwrap();
        writer.commit().unwrap();
        self.decrease_size();
    }

    pub fn contains_key(&mut self, x: &TxOutpoint) -> bool {
        let tx = bincode::serialize(&x).unwrap();
        let reader = self.env.read().expect("reader");

        match self.store.get(&reader, &tx).expect("fetch value") {
            Some(_val) => {
                return true;
            }
            None => {
                return false;
            }
        };
    }

    pub fn contains_key_address(&mut self, x: &str) -> bool {
        let reader = self.env.read().expect("reader");

        match self.store.get(&reader, &x).expect("fetch value") {
            Some(_val) => {
                return true;
            }
            None => {
                return false;
            }
        };
    }

    pub fn get(&mut self, x: &TxOutpoint) -> Option<String> {
        let tx = bincode::serialize(&x).unwrap();
        let reader = self.env.read().expect("reader");

        match self.store.get(&reader, &tx).expect("fetch address") {
            Some(val) => match val {
                Value::Str(ee) => Some(String::from(ee)),
                _ => panic!("Nothing Import"),
            },
            None => None,
        };
        None
    }

    pub fn get_length(&mut self, x: &str) -> Option<usize> {
        let reader = self.env.read().expect("reader");

        match self.store.get(&reader, &x).expect("fetch address") {
            Some(val) => match val {
                Value::U64(ee) => Some(ee as usize),
                _ => panic!("Nothing Import"),
            },
            None => None,
        };
        None
    }

    pub fn len(&self) -> usize {
        self.database_size
    }

    pub fn increment_size(&mut self) {
        let len = &mut self.database_size;
        *len += 1;
    }

    pub fn decrease_size(&mut self) {
        let len = &mut self.database_size;
        *len -= 1;
    }
}
