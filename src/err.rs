use std::fmt;

use forensic_rs::prelude::ForensicError;

#[derive(Debug)]
pub enum DumpBinError {
    Io(std::io::Error),
    DumpBinError { exit_code: i32, stderr: String },
    Other(String),
}


impl From<String> for DumpBinError {
    fn from(err: String) -> Self {
        DumpBinError::Other(err)
    }
}

impl From<ForensicError> for DumpBinError {
    fn from(err: ForensicError) -> Self {
        DumpBinError::Other(format!("{:?}",err))
    }
}

impl std::fmt::Display for DumpBinError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DumpBinError::Io(e) => write!(f, "I/O error: {}", e),
            DumpBinError::DumpBinError { exit_code, stderr } => write!(f, "SignTool exited with code {exit_code}: {stderr}"),
            DumpBinError::Other(e) => write!(f, "{}", e)
        }
    }
}

impl std::error::Error for DumpBinError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }

    fn description(&self) -> &str {
        "DumpbinError: dont use description"
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.source()
    }
}