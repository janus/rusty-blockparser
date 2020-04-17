use std::fs::{self, File, OpenOptions};
use std::io::{LineWriter, Write};
use std::path::PathBuf;

use clap::{App, Arg, ArgMatches, SubCommand};

use crate::blockchain::utils::csv::CsvFile;
use crate::callbacks::Callback;
use crate::errors::{OpError, OpErrorKind, OpResult};

use rustc_serialize::json::{self, Decoder, Json};
use rustc_serialize::Decodable;

use crate::blockchain::parser::types::CoinType;
use crate::blockchain::proto::block::Block;
use crate::blockchain::proto::tx::TxOutpoint;
use crate::blockchain::proto::tx::{EvaluatedTxOut, Tx, TxInput};
use crate::blockchain::proto::Hashed;
use crate::blockchain::utils;
use crate::blockchain::utils::{arr_to_hex_swapped, hex_to_arr32_swapped};
use crate::DisjointSet;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasherDefault, Hash};
use twox_hash::XxHash;

/// Dumps the whole blockchain into csv files
pub struct CsvDump {
    // Each structure gets stored in a seperate csv file
    dump_folder: PathBuf,
    chain_writer: LineWriter<File>,
    utxo_writer: LineWriter<File>,
    clusters: DisjointSet<String>,
    utxo_set: HashMap<TxOutpoint, String, BuildHasherDefault<XxHash>>,
    new_cluster_id: usize,
    start_height: usize,
    end_height: usize,
    tx_count: u64,
    in_count: u64,
    out_count: u64,
}

impl CsvDump {
    fn create_writer(path: PathBuf) -> OpResult<LineWriter<File>> {
        let file = match OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
        {
            Ok(f) => f,
            Err(err) => return Err(OpError::from(err)),
        };
        Ok(LineWriter::new(file))
    }

    /// Exports UTXO set to a CSV file.
    fn export_utxo_set_to_csv(&mut self) -> OpResult<usize> {
        info!(target: "Clusterizer [export_utxo_set_to_csv]", "Exporting {} UTXOs to CSV...", self.utxo_set.len());

        for (tx_outpoint, address) in self.utxo_set.iter() {
            self.utxo_writer
                .write_all(
                    format!(
                        "{};{};{}\n",
                        arr_to_hex_swapped(&tx_outpoint.txid),
                        tx_outpoint.index,
                        address
                    )
                    .as_bytes(),
                )
                .unwrap();
        }

        info!(target: "Clusterizer [export_utxo_set_to_csv]", "Exported {} UTXOs to CSV.",
                       self.utxo_set.len());
        Ok(self.utxo_set.len())
    }

    /// Renames temporary files.
    fn rename_tmp_files(&mut self) -> OpResult<usize> {
        fs::rename(
            self.dump_folder.as_path().join("clusters.dat.tmp"),
            self.dump_folder.as_path().join("clusters.dat"),
        )
        .expect("Unable to rename clusters.dat.tmp file!");
        fs::rename(
            self.dump_folder.as_path().join("clusters.csv.tmp"),
            self.dump_folder.as_path().join("clusters.csv"),
        )
        .expect("Unable to rename clusters.csv.tmp file!");
        fs::rename(
            self.dump_folder.as_path().join("utxo.csv.tmp"),
            self.dump_folder.as_path().join("utxo.csv"),
        )
        .expect("Unable to rename utxo.csv.tmp file!");
        Ok(3)
    }

    /// Loads the UTXO set from an existing CSV file.
    fn load_utxo_set(&mut self) -> OpResult<usize> {
        info!(target: "Clusterizer [load_utxo_set]", "Loading UTXO set...");

        let csv_file_path = self.dump_folder.join("utxo.csv");
        let csv_file_path_string = csv_file_path.as_path().to_str().unwrap();
        let mut csv_file = match CsvFile::new(csv_file_path.to_owned(), b';') {
            Ok(idx) => idx,
            Err(e) => {
                return Err(tag_err!(
                    e,
                    "Unable to load UTXO CSV file {}!",
                    csv_file_path_string
                ))
            }
        };

        for record in csv_file.reader.records().map(|r| r.unwrap()) {
            let tx_outpoint = TxOutpoint {
                txid: hex_to_arr32_swapped(&record[0]),
                index: record[1].parse::<u32>().unwrap(),
            };
            let address = record[2].to_owned();
            if address.is_empty() {
                // Skip non-standard outputs
                continue;
            }

            trace!(target: "Clusterizer [load_utxo_set]", "Adding UTXO {:#?} to the UTXO set.", tx_outpoint);
            self.utxo_set.insert(tx_outpoint, address);
        }

        info!(target: "Clusterizer [load_utxo_set]", "Done.");
        Ok(self.utxo_set.len())
    }
}

impl Callback for CsvDump {
    fn build_subcommand<'a, 'b>() -> App<'a, 'b>
    where
        Self: Sized,
    {
        SubCommand::with_name("csvdump")
            .about(
                "Dumps the whole blockchain into CSV files, including clusters. \
            The clusterizer needs to be run first",
            )
            .version("0.1")
            .author("Age Manning <AgeManning.com>")
            .arg(
                Arg::with_name("dump-folder")
                    .help("Folder to store csv files")
                    .index(1)
                    .required(true),
            )
            .arg(
                Arg::with_name("cluster-file")
                    .help("The .dat file corresponding to pre-processed clusters")
                    .index(1)
                    .required(true),
            )
    }

    fn new(matches: &ArgMatches) -> OpResult<Self>
    where
        Self: Sized,
    {
        let dump_folder = PathBuf::from(matches.value_of("dump-folder").unwrap());
        let cluster_file = PathBuf::from(matches.value_of("cluster-file").unwrap());

        let chain_writer = CsvDump::create_writer(dump_folder.join("transactions.csv.tmp"))?;
        let utxo_writer = CsvDump::create_writer(dump_folder.join("utxo.csv.tmp"))?;

        info!(target: "callback", "Loading clusters from file: {:?} ...", cluster_file);

        let mut file = File::open(cluster_file).map_err(|e| {
            error!(target: "callback", "Could not read cluster file: {:?} ...", e);
            OpError::new(OpErrorKind::CallbackError)
        })?;

        let json = Json::from_reader(&mut file).unwrap();
        let mut decoder = Decoder::new(json);
        let clusters: DisjointSet<String> = Decodable::decode(&mut decoder)?;
        info!(target: "Clusterizer [new]", "Loaded clusters: {} ...", clusters.set_size);

        Ok(CsvDump {
            dump_folder,
            chain_writer,
            utxo_writer,
            clusters,
            utxo_set: Default::default(),
            new_cluster_id: clusters.set_size,
            start_height: 0,
            end_height: 0,
            tx_count: 0,
            in_count: 0,
            out_count: 0,
        })
    }

    fn on_start(&mut self, _: CoinType, block_height: usize) {
        self.start_height = block_height;
        info!(target: "callback", "Using `csvdump` with dump folder: {:?} ...", &self.dump_folder);
        match self.load_utxo_set() {
            Ok(utxo_count) => {
                info!(target: "Clusterizer [on_start]", "Loaded {} UTXOs.", utxo_count);
            }
            Err(_) => {
                info!(target: "Clusterizer [on_start]", "No previous UTXO loaded.");
            }
        }
    }

    fn on_block(&mut self, block: Block, block_height: usize) {
        if block_height % 1000usize == 0 {
            info!(target: "Csvdump [on_block]", "Progress: block {}, {} transactions", block_height, self.tx_count);
        }

        // serialize block

        for (tx_index, tx) in block.txs.iter().enumerate() {
            self.in_count += tx.value.in_count.value;
            self.out_count += tx.value.out_count.value;

            // inputs
            let (total_input_value, src_cluster) = {
                let mut total_value = 0;
                for input in &tx.value.inputs {
                    // Ignore coinbase
                    let mut src_cluster = None;
                    if input.outpoint.txid == [0u8; 32] {
                        src_cluster = Some(0);
                        continue;
                    }

                    let tx_outpoint = TxOutpoint {
                        txid: input.outpoint.txid,
                        index: input.outpoint.index,
                    };

                    // The input is spent, remove it from the UTXO set
                    match self.utxo_set.remove(&tx_outpoint) {
                        Some((address, value)) => {
                            total_input_value += value;

                            if src_cluster.is_none() {
                            src_cluster = match self.clusters.find(&address) {
                                Some(id) => Some(id),
                                None => {
                                    // no clusters for this address
                                    self.new_cluster_id += 1;
                                    self.new_cluster_id
                                }
                            };
                        }
                        }
                        None => {
                            warn!("{:#?} is not present in the UTXO set!", tx_outpoint);
                            continue;
                        }
                    };
                    trace!(target: "Clusterizer [on_block] [TX inputs]", "Removing {:#?} from UTXO set.", tx_outpoint);
                }

                (total_input_value, src_cluster.expect("Must have a source"))
            };


            // Transaction outputs
            for (i, output) in tx.value.outputs.iter().enumerate() {

                // add the UTXO
                let tx_outpoint = TxOutpoint {
                    txid: tx.hash,
                    index: i as u32,
                };
                let value = output.out.value.clone();
                let mut address = output.script.address.to_owned();
                let mut dst_cluster = None;
                if address.is_empty() {
                    address = "invalid";
                }
                else {
                trace!(target: "Clusterizer [on_block] [TX outputs]", "Adding UTXO {:#?} to the UTXO set.", tx_outpoint);
                self.utxo_set.insert(tx_outpoint, (address, value));

                // get the dst cluster








            }
        }

        self.tx_count += block.tx_count.value;
        /*
        self.block_writer
            .write_all(block.as_csv(block_height).as_bytes())
            .unwrap();

        // serialize transaction
        let block_hash = utils::arr_to_hex_swapped(&block.header.hash);
        for tx in block.txs {
            self.tx_writer
                .write_all(tx.as_csv(&block_hash).as_bytes())
                .unwrap();
            let txid_str = utils::arr_to_hex_swapped(&tx.hash);

            // serialize inputs
            for input in &tx.value.inputs {
                self.txin_writer
                    .write_all(input.as_csv(&txid_str).as_bytes())
                    .unwrap();
            }
            self.in_count += tx.value.in_count.value;

            // serialize outputs
            for (i, output) in tx.value.outputs.iter().enumerate() {
                self.txout_writer
                    .write_all(output.as_csv(&txid_str, i).as_bytes())
                    .unwrap();
            }
            self.out_count += tx.value.out_count.value;
        }
        self.tx_count += block.tx_count.value;
        */
    }

    fn on_complete(&mut self, block_height: usize) {
        self.end_height = block_height;

        // Keep in sync with c'tor
        for f in vec!["blocks", "transactions", "tx_in", "tx_out"] {
            // Rename temp files
            fs::rename(
                self.dump_folder.as_path().join(format!("{}.csv.tmp", f)),
                self.dump_folder.as_path().join(format!(
                    "{}-{}-{}.csv",
                    f, self.start_height, self.end_height
                )),
            )
            .expect("Unable to rename tmp file!");
        }

        info!(target: "callback", "Done.\nDumped all {} blocks:\n\
                                   \t-> transactions: {:9}\n\
                                   \t-> inputs:       {:9}\n\
                                   \t-> outputs:      {:9}",
             self.end_height + 1, self.tx_count, self.in_count, self.out_count);
    }
}

impl Block {
    #[inline]
    fn as_csv(&self, block_height: usize) -> String {
        // (@hash, height, version, blocksize, @hashPrev, @hashMerkleRoot, nTime, nBits, nNonce)
        format!(
            "{};{};{};{};{};{};{};{};{}\n",
            &utils::arr_to_hex_swapped(&self.header.hash),
            &block_height,
            &self.header.value.version,
            &self.blocksize,
            &utils::arr_to_hex_swapped(&self.header.value.prev_hash),
            &utils::arr_to_hex_swapped(&self.header.value.merkle_root),
            &self.header.value.timestamp,
            &self.header.value.bits,
            &self.header.value.nonce
        )
    }
}

impl Hashed<Tx> {
    #[inline]
    fn as_csv(&self, block_hash: &str) -> String {
        // (@txid, @hashBlock, version, lockTime)
        format!(
            "{};{};{};{}\n",
            &utils::arr_to_hex_swapped(&self.hash),
            &block_hash,
            &self.value.tx_version,
            &self.value.tx_locktime
        )
    }
}

impl TxInput {
    #[inline]
    fn as_csv(&self, txid: &str) -> String {
        // (@txid, @hashPrevOut, indexPrevOut, scriptSig, sequence)
        format!(
            "{};{};{};{};{}\n",
            &txid,
            &utils::arr_to_hex_swapped(&self.outpoint.txid),
            &self.outpoint.index,
            &utils::arr_to_hex(&self.script_sig),
            &self.seq_no
        )
    }
}

impl EvaluatedTxOut {
    #[inline]
    fn as_csv(&self, txid: &str, index: usize) -> String {
        // (@txid, indexOut, value, @scriptPubKey, address)
        format!(
            "{};{};{};{};{}\n",
            &txid,
            &index,
            &self.out.value,
            &utils::arr_to_hex(&self.out.script_pubkey),
            &self.script.address
        )
    }
}
