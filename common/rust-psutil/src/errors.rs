use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(feature = "sensors")]
use glob::glob as other_glob;

#[derive(Debug, thiserror::Error)]
pub enum ParseStatusError {
	/// Linux only.
	#[error("Length is not 1. Contents: '{}'", contents)]
	IncorrectLength { contents: String },

	/// Linux and macOS.
	#[error("Incorrect char. Contents: '{}'", contents)]
	IncorrectChar { contents: String },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// Linux only.
	#[error("Failed to read file '{}': {}", path.display(), source)]
	ReadFile { path: PathBuf, source: io::Error },

	/// Linux only.
	#[error("File '{}' is missing data. Contents: '{}'", path.display(), contents)]
	MissingData { path: PathBuf, contents: String },

	/// Linux only.
	#[error("Parse error for file '{}'. Contents: '{}'. {}", path.display(), contents, source)]
	ParseInt {
		path: PathBuf,
		contents: String,
		source: std::num::ParseIntError,
	},

	/// Linux only.
	#[error("Parse error for file '{}'. Contents: '{}'. {}", path.display(), contents, source)]
	ParseFloat {
		path: PathBuf,
		contents: String,
		source: std::num::ParseFloatError,
	},

	/// Linux and macOS.
	#[error("Failed to parse status. {}", source)]
	ParseStatus { source: ParseStatusError },

	// Unix only.
	#[error("nix error: {}", source)]
	NixError { source: nix::Error },

	/// macOS only.
	#[error("OS error: {}", source)]
	OsError { source: io::Error },
}

impl From<nix::Error> for Error {
	fn from(error: nix::Error) -> Self {
		Error::NixError { source: error }
	}
}

impl From<io::Error> for Error {
	fn from(error: io::Error) -> Self {
		Error::OsError { source: error }
	}
}

impl From<ParseStatusError> for Error {
	fn from(error: ParseStatusError) -> Self {
		Error::ParseStatus { source: error }
	}
}

pub(crate) fn read_file<P>(path: P) -> Result<String>
where
	P: AsRef<Path>,
{
	fs::read_to_string(&path).map_err(|err| Error::ReadFile {
		path: path.as_ref().into(),
		source: err,
	})
}

pub(crate) fn read_dir<P>(path: P) -> Result<Vec<fs::DirEntry>>
where
	P: AsRef<Path>,
{
	fs::read_dir(&path)
		.map_err(|err| Error::ReadFile {
			path: path.as_ref().into(),
			source: err,
		})?
		.map(|entry| {
			entry.map_err(|err| Error::ReadFile {
				path: path.as_ref().into(),
				source: err,
			})
		})
		.collect()
}

pub(crate) fn read_link<P>(path: P) -> Result<PathBuf>
where
	P: AsRef<Path>,
{
	fs::read_link(&path).map_err(|err| Error::ReadFile {
		path: path.as_ref().into(),
		source: err,
	})
}

#[cfg(feature = "sensors")]
pub(crate) fn glob(path: &str) -> Vec<Result<PathBuf>> {
	other_glob(path)
		.unwrap() // only errors on invalid pattern
		.map(|result| {
			result.map_err(|err| Error::ReadFile {
				path: path.into(),
				source: err.into_error(),
			})
		})
		.collect()
}
