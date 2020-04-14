extern crate csv;

use crate::errors::{OpError, OpResult};

use csv::{Reader, ReaderBuilder};
use std::fs::File;
use std::path::PathBuf;

/// Holds all necessary data about a CSV file
pub struct CsvFile {
    pub path: PathBuf,
    pub reader: Reader<File>,
}

impl CsvFile {
    pub fn new(path: PathBuf, delimiter: u8) -> OpResult<CsvFile> {
        let csv_reader = match ReaderBuilder::new()
            .has_headers(false)
            .delimiter(delimiter)
            .flexible(true)
            .from_path(path.as_path())
        {
            Ok(r) => r,
            Err(e) => {
                return Err(OpError::from(format!(
                    "Unable to open CSV file: {:?} ({}).",
                    path.as_path(),
                    e
                )))
            }
        };

        Ok(CsvFile {
            path: path.to_owned(),
            reader: csv_reader,
        })
    }
}
