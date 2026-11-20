use super::*;
use context_deserialize::ContextDeserialize;
use fs2::FileExt;
use snap::raw::Decoder;
use std::fs::{self};
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use types::{BeaconState, LightClientUpdate};

/// See `log_file_access` for details.
const ACCESSED_FILE_LOG_FILENAME: &str = ".accessed_file_log.txt";

/// Writes `path` to a file that contains a log of all files accessed during testing.
///
/// That log file might later be used to ensure that all spec tests were accessed and none were
/// accidentally missed.
pub fn log_file_access<P: AsRef<Path>>(file_accessed: P) {
    let passed_test_list_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(ACCESSED_FILE_LOG_FILENAME);

    let mut file = fs::File::options()
        // Windows file locking requires read or write access, not append-only access.
        .read(true)
        .append(true)
        .create(true)
        .open(passed_test_list_path)
        .expect("should open file");

    file.lock_exclusive().expect("unable to lock file");

    writeln!(&mut file, "{:?}", file_accessed.as_ref()).expect("should write to file");

    fs2::FileExt::unlock(&file).expect("unable to unlock file");
}

pub fn yaml_decode<T: serde::de::DeserializeOwned>(string: &str) -> Result<T, Error> {
    yaml_serde::from_str(string).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))
}

pub fn context_yaml_decode<'de, T, C>(string: &'de str, context: C) -> Result<T, Error>
where
    T: ContextDeserialize<'de, C>,
{
    let deserializer = yaml_serde::Deserializer::from_str(string);
    T::context_deserialize(deserializer, context)
        .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))
}

pub fn context_yaml_decode_file<T, C>(path: &Path, context: C) -> Result<T, Error>
where
    T: for<'de> ContextDeserialize<'de, C>,
{
    log_file_access(path);
    fs::read_to_string(path)
        .map_err(|e| {
            Error::FailedToParseTest(format!("Unable to load {}: {:?}", path.display(), e))
        })
        .and_then(|s| context_yaml_decode(&s, context))
}

pub fn yaml_decode_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, Error> {
    log_file_access(path);
    fs::read_to_string(path)
        .map_err(|e| {
            Error::FailedToParseTest(format!("Unable to load {}: {:?}", path.display(), e))
        })
        .and_then(|s| yaml_decode(&s))
}

/// Decode a Snappy encoded file.
///
/// Files in the EF tests are unframed, so we need to use `snap::raw::Decoder`.
pub fn snappy_decode_file(path: &Path) -> Result<Vec<u8>, Error> {
    log_file_access(path);
    let bytes = fs::read(path).map_err(|e| {
        Error::FailedToParseTest(format!("Unable to load {}: {:?}", path.display(), e))
    })?;
    let mut decoder = Decoder::new();
    decoder.decompress_vec(&bytes).map_err(|e| {
        Error::FailedToParseTest(format!(
            "Error decoding snappy encoding for {}: {:?}",
            path.display(),
            e
        ))
    })
}

pub fn ssz_decode_file_with<T, F>(path: &Path, f: F) -> Result<T, Error>
where
    F: FnOnce(&[u8]) -> Result<T, ssz::DecodeError>,
{
    log_file_access(path);
    let bytes = snappy_decode_file(path)?;
    f(&bytes).map_err(|e| {
        match e {
            // NOTE: this is a bit hacky, but seemingly better than the alternatives
            ssz::DecodeError::BytesInvalid(message) if message.contains("Blst") => {
                Error::InvalidBLSInput(message)
            }
            e => Error::InvalidSSZInput(format!(
                "Unable to parse SSZ at {}: {:?}",
                path.display(),
                e
            )),
        }
    })
}

pub fn ssz_decode_file<T: ssz::Decode>(path: &Path) -> Result<T, Error> {
    log_file_access(path);
    ssz_decode_file_with(path, T::from_ssz_bytes)
}

pub fn ssz_decode_state<E: EthSpec>(
    path: &Path,
    spec: &ChainSpec,
) -> Result<BeaconState<E>, Error> {
    log_file_access(path);
    ssz_decode_file_with(path, |bytes| BeaconState::from_ssz_bytes(bytes, spec))
}

pub fn ssz_decode_light_client_update<E: EthSpec>(
    path: &Path,
    fork_name: &ForkName,
) -> Result<LightClientUpdate<E>, Error> {
    log_file_access(path);
    ssz_decode_file_with(path, |bytes| {
        LightClientUpdate::from_ssz_bytes(bytes, fork_name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use snap::raw::Encoder;
    use ssz_types::VariableList;
    use typenum::U1;

    #[test]
    fn overlong_list_is_invalid_ssz_input() {
        let dir = tempfile::tempdir().unwrap();
        let fixture_dir = dir.path().join("consensus-spec-tests");
        fs::create_dir(&fixture_dir).unwrap();
        let path = fixture_dir.join("list.ssz_snappy");
        let bytes = Encoder::new().compress_vec(&[0, 1]).unwrap();
        fs::write(&path, bytes).unwrap();

        let error = ssz_decode_file::<VariableList<u8, U1>>(&path).unwrap_err();
        assert!(matches!(error, Error::InvalidSSZInput(_)));
    }
}
