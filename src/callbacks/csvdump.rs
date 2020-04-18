use std::fs::{self, File, OpenOptions};
use std::io::{LineWriter, Write};
use std::path::PathBuf;

use clap::{App, Arg, ArgMatches, SubCommand};

use crate::blockchain::utils::csv::CsvFile;
use crate::callbacks::Callback;
use crate::errors::{OpError, OpResult};

use crate::blockchain::parser::types::CoinType;
use crate::blockchain::proto::block::Block;
use crate::blockchain::proto::tx::TxOutpoint;
use crate::blockchain::utils;
use crate::blockchain::utils::{arr_to_hex_swapped, hex_to_arr32_swapped};
use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use twox_hash::XxHash;

/// Dumps the whole blockchain into csv files
pub struct CsvDump {
    // Each structure gets stored in a seperate csv file
    resume: bool,
    dump_folder: PathBuf,
    chain_writer: LineWriter<File>,
    utxo_writer: LineWriter<File>,
    cluster_balance_writer: LineWriter<File>,
    clusters: HashMap<String, usize, BuildHasherDefault<XxHash>>,
    utxo_set: HashMap<TxOutpoint, (String, usize), BuildHasherDefault<XxHash>>,
    cluster_balances: HashMap<Option<usize>, usize, BuildHasherDefault<XxHash>>,
    start_height: usize,
    end_height: usize,
    tx_count: u64,
    in_count: u64,
    out_count: u64,
    last_completed_block: usize,
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
        info!(target: "CsvDump [export_utxo_set_to_csv]", "Exporting {} UTXOs to CSV...", self.utxo_set.len());

        for (tx_outpoint, (address, value)) in self.utxo_set.iter() {
            self.utxo_writer
                .write_all(
                    format!(
                        "{};{};{};{}\n",
                        arr_to_hex_swapped(&tx_outpoint.txid),
                        tx_outpoint.index,
                        address,
                        value,
                    )
                    .as_bytes(),
                )
                .unwrap();
        }

        info!(target: "CsvDump [export_utxo_set_to_csv]", "Exported {} UTXOs to CSV.",
                       self.utxo_set.len());
        Ok(self.utxo_set.len())
    }

    /// Exports Cluster balances to CSV
    fn export_cluster_balance_to_csv(&mut self) -> OpResult<usize> {
        let cluster_balances = self.cluster_balances.len();
        info!(target: "CsvDump [export_cluster_balance_to_csv]", "Exporting {} balances to CSV...", cluster_balances);

        for (cluster, balance) in self.cluster_balances.iter() {
            self.cluster_balance_writer
                .write_all(
                    format!(
                        "{};{};\n",
                        cluster
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "-1".into()),
                        balance.to_string(),
                    )
                    .as_bytes(),
                )
                .unwrap();
        }
        info!(target: "CsvDump []", "Exported {} balances to CSV.", cluster_balances);
        Ok(cluster_balances)
    }

    fn load_cluster_balance_from_csv(
        csv_file: PathBuf,
    ) -> OpResult<HashMap<Option<usize>, usize, BuildHasherDefault<XxHash>>> {
        info!(target: "CsvDump [load_cluster_balance_from_csv]", "Loading balances...");

        let csv_file_path_string = csv_file.as_path().to_str().unwrap();
        let mut csv_file = match CsvFile::new(csv_file.to_owned(), b';') {
            Ok(idx) => idx,
            Err(e) => {
                return Err(tag_err!(
                    e,
                    "Unable to load Cluster CSV balance file {}!",
                    csv_file_path_string
                ))
            }
        };

        let mut cluster_balances: HashMap<Option<usize>, usize, BuildHasherDefault<XxHash>> =
            Default::default();

        for record in csv_file.reader.records().map(|r| r.unwrap()) {
            let cluster = {
                if &record[0] == "-1" {
                    None
                } else {
                    Some(record[0].parse::<usize>().unwrap())
                }
            };
            cluster_balances.insert(cluster, record[1].parse::<usize>().unwrap());
        }

        info!(target: "CsvDump [load_cluster_balances]", "Done.");
        Ok(cluster_balances)
    }

    /// Loads the clusters as a hashmap for fast lookups
    fn load_cluster_as_hashmap(
        csv_file: PathBuf,
    ) -> OpResult<HashMap<String, usize, BuildHasherDefault<XxHash>>> {
        info!(target: "CsvDump [load_cluster_as_hashmap]", "Loading clusters...");

        let csv_file_path_string = csv_file.as_path().to_str().unwrap();
        let mut csv_file = match CsvFile::new(csv_file.to_owned(), b';') {
            Ok(idx) => idx,
            Err(e) => {
                return Err(tag_err!(
                    e,
                    "Unable to load Cluster CSV file {}!",
                    csv_file_path_string
                ))
            }
        };

        let mut cluster_hashmap: HashMap<String, usize, BuildHasherDefault<XxHash>> =
            Default::default();

        for record in csv_file.reader.records().map(|r| r.unwrap()) {
            cluster_hashmap.insert(record[0].into(), record[1].parse::<usize>().unwrap());
        }

        info!(target: "CsvDump [load_cluster_as_hashmap]", "Done.");
        Ok(cluster_hashmap)
    }

    /// Loads the UTXO set from an existing CSV file.
    fn load_utxo_set(&mut self) -> OpResult<usize> {
        info!(target: "CsvDump [load_utxo_set]", "Loading UTXO set...");

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
            let value = record[3].parse::<usize>().unwrap();
            if address.is_empty() {
                // Skip non-standard outputs
                continue;
            }
            trace!(target: "CsvDump [load_utxo_set]", "Adding UTXO {:#?} to the UTXO set.", tx_outpoint);
            self.utxo_set.insert(tx_outpoint, (address, value));
        }

        info!(target: "CsvDump [load_utxo_set]", "Done.");
        Ok(self.utxo_set.len())
    }

    fn rename_tmp_files(&self) {
        // Rename temp files
        fs::rename(
            self.dump_folder.as_path().join("transactions.csv.tmp"),
            self.dump_folder.as_path().join(format!(
                "transactions-{}-{}.csv",
                self.start_height, self.end_height
            )),
        )
        .expect("Unable to rename tmp file!");

        fs::rename(
            self.dump_folder.as_path().join("utxo.csv.tmp"),
            self.dump_folder.as_path().join("utxo.csv"),
        )
        .expect("Unable to rename utxo files");

        fs::rename(
            self.dump_folder.as_path().join("cluster_balances.csv.tmp"),
            self.dump_folder.as_path().join(format!(
                "cluster_balances-{}-{}.csv",
                self.start_height, self.end_height
            )),
        )
        .expect("Unable to rename cluster balances files");
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
                Arg::with_name("cluster-csv")
                    .help("The csv file corresponding to pre-processed clusters")
                    .takes_value(true)
                    .required(true),
            )
            .arg(
                Arg::with_name("cluster-balances-csv")
                    .help("The csv file corresponding to past-processed balances. Required if non-resume is not set.")
                    .takes_value(true)
            )
            .arg(
                Arg::with_name("no-resume")
                    .short("n")
                    .help("Do not load past UTXO's and account balances"),
            )
    }

    fn new(matches: &ArgMatches) -> OpResult<Self>
    where
        Self: Sized,
    {
        let dump_folder = PathBuf::from(matches.value_of("dump-folder").unwrap());
        let cluster_file = PathBuf::from(matches.value_of("cluster-csv").unwrap());

        let resume = !matches.is_present("no-resume");

        let cluster_balances = if resume {
            let balances_path = PathBuf::from(matches.value_of("cluster_balances-csv").unwrap());
            CsvDump::load_cluster_balance_from_csv(balances_path).unwrap()
        } else {
            Default::default()
        };

        let chain_writer = CsvDump::create_writer(dump_folder.join("transactions.csv.tmp"))?;
        let utxo_writer = CsvDump::create_writer(dump_folder.join("utxo.csv.tmp"))?;
        let cluster_balance_writer =
            CsvDump::create_writer(dump_folder.join("cluster_balances.csv.tmp"))?;

        info!("Loading clusters from file: {:?} ...", cluster_file);

        // build cluster hashmap from the csv
        let clusters = CsvDump::load_cluster_as_hashmap(cluster_file).unwrap();

        /* Load clusters as UnionFind
        let mut file = File::open(cluster_file).map_err(|e| {
            error!(target: "callback", "Could not read cluster file: {:?} ...", e);
            OpError::new(OpErrorKind::CallbackError)
        })?;
            let json = Json::from_reader(&mut file).unwrap();
            let mut decoder = Decoder::new(json);
            let clusters: DisjointSet<String> = Decodable::decode(&mut decoder)?;
            info!(target: "Clusterizer [new]", "Loaded clusters: {} ...", clusters.set_size);
        */

        Ok(CsvDump {
            resume,
            dump_folder,
            chain_writer,
            cluster_balance_writer,
            utxo_writer,
            clusters,
            utxo_set: Default::default(),
            cluster_balances,
            start_height: 0,
            end_height: 0,
            tx_count: 0,
            in_count: 0,
            out_count: 0,
            last_completed_block: 0,
        })
    }

    fn on_start(&mut self, _: CoinType, block_height: usize) {
        self.start_height = block_height;
        info!(target: "callback", "Using `csvdump` with dump folder: {:?} ...", &self.dump_folder);

        if self.resume {
            match self.load_utxo_set() {
                Ok(utxo_count) => {
                    info!(target: "CsvDump [on_start]", "Loaded {} UTXOs.", utxo_count);
                }
                Err(_) => {
                    info!(target: "CsvDump [on_start]", "No previous UTXO loaded.");
                }
            }
        } else {
            info!(target: "CsvDump [on_start]", "Not resuming, no data loaded");
        }
    }

    fn on_block(&mut self, block: Block, block_height: usize) {
        if block_height % 10000usize == 0 {
            info!(target: "Csvdump [on_block]", "Progress: block {}, {} transactions", block_height, self.tx_count);
        }

        for tx in block.txs.iter() {
            self.in_count += tx.value.in_count.value;
            self.out_count += tx.value.out_count.value;

            // inputs
            let (src_cluster, total_input_value) = {
                let mut total_input_value = 0;
                let mut src_cluster = None; // represents invalid
                let mut total_invalid_input_value = 0;
                for input in &tx.value.inputs {
                    // Ignore coinbase
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

                            // if the source is invalid increment invalid sources value. These
                            // throw of the balances of clusters
                            if address == "invalid" {
                                total_invalid_input_value += value;
                            }

                            if src_cluster.is_none() && address != "invalid" {
                                src_cluster = match self.clusters.get(&address) {
                                    Some(id) => Some(id.clone()),
                                    None => {
                                        warn!("Address not found in cluster. Must process with singletons! Address: {}", address);
                                        panic!();
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

                // if some of the inputs where invalid, the cluster balance can't account for
                // these. So we increment the cluster balance by these amounts.
                if total_invalid_input_value > 0 && src_cluster.is_some() {
                    *self
                        .cluster_balances
                        .get_mut(&src_cluster)
                        .expect("Source cluster must always exist") += total_invalid_input_value;
                }
                (src_cluster, total_input_value)
            };

            // Transaction outputs
            let mut total_output_value = 0;
            for (i, output) in tx.value.outputs.iter().enumerate() {
                // add the UTXO
                let tx_outpoint = TxOutpoint {
                    txid: tx.hash,
                    index: i as u32,
                };
                let value = output.out.value.clone() as usize;
                let address = output.script.address.to_owned();
                let mut dst_cluster = None;
                trace!(target: "Clusterizer [on_block] [TX outputs]", "Adding UTXO {:#?} to the UTXO set.", tx_outpoint);
                if address.is_empty() {
                    self.utxo_set.insert(tx_outpoint, ("invalid".into(), value));
                } else {
                    // get the dst cluster
                    dst_cluster = Some(
                        self.clusters
                            .get(&address)
                            .expect("Address must be in clusters. Must clusterize with singletons")
                            .clone(),
                    );
                    self.utxo_set.insert(tx_outpoint, (address, value));
                }

                // get and update the balances
                let (src_balance, dst_balance) = {
                    // update the balance of the addresses
                    let dst_balance = {
                        let dst_balance = self
                            .cluster_balances
                            .entry(dst_cluster)
                            .or_insert_with(|| 0);
                        *dst_balance += value;
                        dst_balance.clone()
                    };

                    let src_balance = {
                        // if we have generated coins ignore
                        if src_cluster == Some(0) {
                            0
                        } else {
                            // decrease the value
                            let src_balance = self
                                .cluster_balances
                                .get_mut(&src_cluster)
                                .expect("Source cluster must always exist");
                            if *src_balance < value {
                                error!("Negative value found. Bad clustering. Check block: {}, txid: {} src_cluster: {:?}, dst_cluster: {:?}, src_balance {} value: {}", block_height, utils::arr_to_hex_swapped(&tx.hash), src_cluster, dst_cluster, *src_balance, value);
                            }
                            // increment the total output value
                            total_output_value += value;

                            src_balance
                                .checked_sub(value)
                                .expect("Balances should never be negative"); // this will underflow if balances are wrong and panic
                            src_balance.clone()
                        }
                    };
                    (src_balance, dst_balance.clone())
                };

                let tx = Transaction {
                    height: block_height,
                    timestamp: block.header.value.timestamp,
                    tx_hash: tx.hash,
                    src_cluster,
                    dst_cluster,
                    value,
                    src_balance,
                    dst_balance,
                    is_fee: false,
                };

                // write to csv
                self.chain_writer.write_all(tx.as_csv().as_bytes()).unwrap();
            }

            // build fees
            let fee_paid = total_input_value - total_output_value;
            if fee_paid > 0 {
                let src_balance = {
                    if src_cluster == Some(0) {
                        0
                    } else {
                        // decrement the fee
                        let src_balance = self
                            .cluster_balances
                            .get_mut(&src_cluster)
                            .expect("Source cluster must always exist");
                        *src_balance -= fee_paid;
                        src_balance.clone()
                    }
                };
                let fee_transaction = Transaction {
                    height: block_height,
                    timestamp: block.header.value.timestamp,
                    tx_hash: tx.hash,
                    src_cluster,
                    dst_cluster: Some(0),
                    value: fee_paid,
                    src_balance,
                    dst_balance: 0,
                    is_fee: true,
                };
                self.chain_writer
                    .write_all(fee_transaction.as_csv().as_bytes())
                    .unwrap();
            }
        }

        self.tx_count += block.tx_count.value;
        self.last_completed_block = block_height;
    }

    fn on_complete(&mut self, _block_height: usize) {
        // should fix this in the parser.. hack for the time being
        self.end_height = self.last_completed_block;

        // Write UTXO set to CSV.
        let _ = self.export_utxo_set_to_csv();
        let _ = self.export_cluster_balance_to_csv();

        self.rename_tmp_files();

        info!(target: "callback", "Done.\nDumped all {} blocks:\n\
                                   \t-> transactions: {:9}\n\
                                   \t-> inputs:       {:9}\n\
                                   \t-> outputs:      {:9}",
             self.end_height + 1, self.tx_count, self.in_count, self.out_count);
    }
}

struct Transaction {
    height: usize,
    timestamp: u32,
    tx_hash: [u8; 32],
    src_cluster: Option<usize>,
    dst_cluster: Option<usize>,
    value: usize,
    src_balance: usize,
    dst_balance: usize,
    is_fee: bool,
}

impl Transaction {
    fn as_csv(&self) -> String {
        // (height, timestamp, tx_id, src_cluster, dst_cluster, value, src_balance, dst_balance, is_fee)
        let fee = if self.is_fee { 1 } else { 0 };
        format!(
            "{},{};{};{};{};{};{};{};{}\n",
            &self.height,
            chrono::NaiveDateTime::from_timestamp(self.timestamp as i64, 0).to_string(),
            &utils::arr_to_hex_swapped(&self.tx_hash),
            &self
                .src_cluster
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-1".into()),
            &self
                .dst_cluster
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-1".into()),
            &self.value.to_string(),
            &self.src_balance.to_string(),
            &self.dst_balance.to_string(),
            fee.to_string(),
        )
    }
}
