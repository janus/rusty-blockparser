use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::hash::BuildHasherDefault;
use std::io::{LineWriter, Write};
use std::path::PathBuf;

use clap::{App, Arg, ArgMatches, SubCommand};
use rustc_serialize::json::{self, Decoder, Json};
use rustc_serialize::Decodable;
use twox_hash::XxHash;

use crate::callbacks::Callback;
use crate::errors::{OpError, OpResult};

use crate::blockchain::parser::types::CoinType;
use crate::blockchain::proto::block::Block;
use crate::blockchain::proto::kv::Datastore;
use crate::blockchain::proto::tx::TxOutpoint;
use crate::blockchain::utils::csv::CsvFile;
use crate::blockchain::utils::{arr_to_hex_swapped, hex_to_arr32_swapped};
use crate::DisjointSet;
use itertools::Itertools;

/// Groups addresses into ownership clusters.
pub struct Clusterizer {
    dump_folder: PathBuf,
    utxo_writer: LineWriter<File>,
    clusterizer_writer: LineWriter<File>,
    utxo_set: HashMap<TxOutpoint, String, BuildHasherDefault<XxHash>>,
    clusters: DisjointSet<String>,

    no_singletons: bool,

    start_height: usize,
    end_height: usize,
    tx_count: u64,
    in_count: u64,
    out_count: u64,
}

impl Clusterizer {
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

    /// Serializes clusters to a file.
    fn serialize_clusters(&mut self) -> OpResult<usize> {
        self.clusters.finalize();
        info!(target: "Clusterizer [serialize_clusters]", "Serializing {} clusters to file...",
                       self.clusters.set_size);
        let encoded = json::encode(&self.clusters)?;
        let temp_file_path = self
            .dump_folder
            .join("clusters.dat.tmp")
            .as_path()
            .to_owned();
        let mut file = File::create(temp_file_path.to_owned())?;
        file.write_all(encoded.as_bytes())?;

        info!(target: "Clusterizer [serialize_clusters]", "Serialized {} clusters to file.",
                       self.clusters.set_size);
        Ok(encoded.len())
    }

    /// Exports clusters to a CSV file.
    fn export_clusters_to_csv(&mut self) -> OpResult<usize> {
        self.clusters.finalize();
        info!(target: "Clusterizer [export_clusters_to_csv]", "Exporting {} clusters to CSV...",
                       self.clusters.set_size);

        for (address, tag) in &self.clusters.map {
            self.clusterizer_writer
                .write_all(format!("{};{}\n", address, self.clusters.parent[*tag]).as_bytes())
                .unwrap();
        }

        info!(target: "Clusterizer [export_clusters_to_csv]", "Exported {} clusters to CSV.",
                       self.clusters.set_size);
        Ok(self.clusters.set_size)
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

impl Callback for Clusterizer {
    fn build_subcommand<'a, 'b>() -> App<'a, 'b>
    where
        Self: Sized,
    {
        SubCommand::with_name("clusterizer")
            .about("Groups addresses into ownership clusters")
            .version("0.2")
            .author("Michele Spagnuolo <mikispag@gmail.com>")
            .arg(
                Arg::with_name("dump-folder")
                    .help("Folder with the utxo.csv file, where to store the cluster CSV")
                    .index(1)
                    .required(true),
            )
            .arg(
                Arg::with_name("no-singleton")
                    .short("x")
                    .help("Doesn't include all addresses into the clusters so that only clustered address exist in the union find")
            )
    }

    fn new(matches: &ArgMatches) -> OpResult<Self>
    where
        Self: Sized,
    {
        let ref dump_folder = PathBuf::from(matches.value_of("dump-folder").unwrap());
        let no_singletons = matches.is_present("no-singleton");

        match (|| -> OpResult<Self> {
            let cb = Clusterizer {
                dump_folder: PathBuf::from(dump_folder),
                no_singletons,
                clusterizer_writer: Clusterizer::create_writer(
                    dump_folder.join("clusters.csv.tmp"),
                )?,
                utxo_writer: Clusterizer::create_writer(dump_folder.join("utxo.csv.tmp"))?,
                utxo_set: Default::default(),
                clusters: {
                    let mut new_clusters: DisjointSet<String> = DisjointSet::new();

                    if let Ok(mut file) = File::open(dump_folder.join("clusters.dat")) {
                        let json = Json::from_reader(&mut file).unwrap();
                        let mut decoder = Decoder::new(json);
                        let clusters: DisjointSet<String> = Decodable::decode(&mut decoder)?;
                        info!(target: "Clusterizer [new]", "Resuming from saved clusters.");
                        new_clusters = clusters;
                    }

                    new_clusters
                },

                start_height: 0,
                end_height: 0,
                tx_count: 0,
                in_count: 0,
                out_count: 0,
            };
            Ok(cb)
        })() {
            Ok(s) => return Ok(s),
            Err(e) => Err(tag_err!(
                e,
                "Couldn't initialize Clusterizer with folder: `{:?}`",
                dump_folder.as_path()
            )),
        }
    }

    fn on_start(&mut self, _: CoinType, block_height: usize) {
        self.start_height = block_height;
        info!(target: "Clusterizer [on_start]", "Using `Clusterizer` with dump folder {:?} and start block {}...", &self.dump_folder, self.start_height);
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
        if block_height % 10000 == 0 {
            info!(target: "Clusterizer [on_block]", "Progress: block {}, {} clusters, {} transactions, {} UTXOs.", block_height, self.clusters.set_size, self.tx_count, self.utxo_set.len());
        }

        for (tx_index, tx) in block.txs.iter().enumerate() {
            trace!(target: "Clusterizer [on_block]", "tx_id: {} ({}/{}).", arr_to_hex_swapped(&tx.hash), tx_index, block.txs.len());

            self.in_count += tx.value.in_count.value;
            self.out_count += tx.value.out_count.value;

            // Transaction outputs
            for (i, output) in tx.value.outputs.iter().enumerate() {
                let tx_outpoint = TxOutpoint {
                    txid: tx.hash,
                    index: i as u32,
                };
                let address = output.script.address.to_owned();
                if address.is_empty() {
                    // Skip non-standard outputs
                    continue;
                }
                if !self.no_singletons {
                    self.clusters.make_set(address.clone());
                }

                trace!(target: "Clusterizer [on_block] [TX outputs]", "Adding UTXO {:#?} to the UTXO set.", tx_outpoint);
                self.utxo_set.insert(tx_outpoint, address);
            }

            let mut tx_inputs: HashSet<String, BuildHasherDefault<XxHash>> = Default::default();
            for input in &tx.value.inputs {
                // Ignore coinbase
                if input.outpoint.txid == [0u8; 32] {
                    continue;
                }

                let tx_outpoint = TxOutpoint {
                    txid: input.outpoint.txid,
                    index: input.outpoint.index,
                };

                match self.utxo_set.get(&tx_outpoint) {
                    Some(address) => {
                        tx_inputs.insert(address.to_owned());
                    }
                    None => {
                        warn!("{:#?} is not present in the UTXO set!", tx_outpoint);
                        continue;
                    }
                };

                trace!(target: "Clusterizer [on_block] [TX inputs]", "Removing {:#?} from UTXO set.", tx_outpoint);
                // The input is spent, remove it from the UTXO set
                self.utxo_set.remove(&tx_outpoint);
            }

            // Skip transactions with just one input
            if tx_inputs.len() < 2 {
                trace!(target: "Clusterizer [on_block]", "Skipping transaction with one distinct input.");
                continue;
            }

            if self.no_singletons {
                for input in tx_inputs.iter() {
                    self.clusters.make_set(input.clone());
                }
            }

            for combination in tx_inputs.iter().combinations(2) {
                let _ = self
                    .clusters
                    .union(combination[0].clone(), combination[1].clone());
            }
        }

        self.tx_count += block.tx_count.value;
    }

    fn on_complete(&mut self, block_height: usize) {
        self.end_height = block_height;

        // Write clusters to DAT file.
        let _ = self.serialize_clusters();
        // Export clusters to CSV.
        let _ = self.export_clusters_to_csv();
        // Write UTXO set to CSV.
        let _ = self.export_utxo_set_to_csv();
        // Rename temporary files.
        let _ = self.rename_tmp_files();

        info!(target: "Clusterizer [on_complete]", "Done.\nProcessed all {} blocks:\n\
                                   \t-> clusters:     {:9}\n\
                                   \t-> transactions: {:9}\n\
                                   \t-> inputs:       {:9}\n\
                                   \t-> outputs:      {:9}",
             self.end_height + 1, self.clusters.set_size, self.tx_count, self.in_count, self.out_count);
    }
}
