use rkv::{Manager, Rkv, SingleStore, Value, StoreOptions};
use rkv::backend::{SafeMode, SafeModeEnvironment};
use std::fs;
use tempfile::Builder;
use bincode;
use serde::{Serialize, Deserialize};

use crate::blockchain::proto::tx::TxOutpoint;


pub struct Datastore<T: Clone + Hash + Eq + Serialize + Deserialize> {
    pub store: SingleStore<SafeModeDatabase>
    pub env: RwLockReadGuard<'_, Rkv<SafeModeEnvironment>>
}


impl<T> Datastore <T>{

    pub fn name(file_name: &str, db_name: &str) -> Datastore {
        let root = Builder::new().prefix(file_name.to_own()).tempdir().unwrap();
        fs::create_dir_all(root.path()).unwrap();
        let path = root.path();

        let mut manager = Manager::<SafeModeEnvironment>::singleton().write().unwrap();
        let shared_rkv = manager.get_or_create(path, Rkv::new::<SafeMode>).unwrap();
        //let created_arc = manager.get_or_create(path, Rkv::new::<Lmdb>).unwrap();
        let env = created_arc.read().unwrap();

        let store = env.open_single(db_name, StoreOptions::create()).unwrap();

        Datastore{store, env}

       // unimplemented!();
    }

    pub fn insert(&mut self, x: T, address: &str) {
        let mut writer = self.env.write().unwrap();

        let tx = bincode::serialize(&x).unwrap();
        self.store.put(&mut writer, &tx, &Value::Str(address)).unwrap();
        writer.commit().unwrap();
    }

    pub fn insert_length(&mut self, x: T, length: usize) {
        let mut writer = self.env.write().unwrap();

        let tx = bincode::serialize(&x).unwrap();
        self.store.put(&mut writer, &tx, &Value::U64(length)).unwrap();
        writer.commit().unwrap();
    }

    pub fn remove(&mut self, x: T) {
        let mut writer = self.env.write().unwrap();

        let tx = bincode::serialize(&x).unwrap();
        self.store.delete(&mut writer, tx).unwrap();
        writer.commit().unwrap();
    }

    pub fn contains_key(&mut self, x: &T) -> bool{
        let tx = bincode::serialize(&x).unwrap();
        let reader = self.env.read().expect("reader");
        match self.store.get(&reader, tx) {
            Ok(None) => false,
            Ok(_) => true,
        }
    }

    pub fn get(&mut self, x: &T) ->Opt<String)> {
        let tx = bincode::serialize(&x).unwrap();
        let reader = self.env.read().expect("reader");

        match self.store.get(&reader, &tx).expect("fetch address") {
                Some(Value::Str(address)) => String::from(address),
                Some(_) => panic!("wrong type"),
                None => None,
        }
    }

    pub fn get_length(&mut self, x: &T) ->Option<usize> {
        let tx = bincode::serialize(&x).unwrap();
        let reader = self.env.read().expect("reader");

        match self.store.get(&reader, &tx).expect("fetch address") {
            Some(Value::U64(val)) => val,
            Some(_) => panic!("wrong type"),
            None => None,
        }

    }
    // add code here
}