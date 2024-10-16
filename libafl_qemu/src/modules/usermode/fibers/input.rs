use libafl::{inputs::{HasTargetBytes, Input}, corpus::CorpusId};
use libafl_bolts::{fs::write_file_atomic, ErrorBacktrace, HasLen, ownedref::OwnedSlice};
use serde::{Deserialize, Serialize};
use std::{borrow::Borrow, fs::File, io::Read, path::Path};
use libafl_bolts::Error;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QemuFibersInput<T> {
    pub(crate) input: T,
    pub(crate) seed: usize,
}

impl<T> QemuFibersInput<T> {
    pub fn new(input: T, seed: usize) -> Self {
        Self { input, seed }
    }
}

impl<I> Input for QemuFibersInput<I>
where
    I: Input,
{
    fn to_file<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        let ser = serde_json::to_string(self)?;
        write_file_atomic(path, ser.as_bytes())
    }

    fn from_file<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut file = File::open(&path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;

        let s = String::from_utf8(bytes)?;
        serde_json::from_str(&s).map_err(|e| Error::Serialize(format!("{}", e), ErrorBacktrace::new()))
    }

    fn generate_name(&self, idx: std::option::Option<CorpusId>) -> String {
        format!("fibers-{}-{}", self.input.borrow().generate_name(idx), self.seed)
    }
}

impl<T> HasLen for QemuFibersInput<T>
where
    T: HasLen,
{
    fn len(&self) -> usize {
        self.input.len()
    }
}

pub trait HasSeed {
    fn get_seed(&self) -> usize;
    fn get_seed_mut(&mut self) -> &mut usize;
}

impl<T> HasSeed for QemuFibersInput<T>
where
    T: HasTargetBytes + Clone + Default,
{
    fn get_seed(&self) -> usize {
        self.seed.clone()
    }

    fn get_seed_mut(&mut self) -> &mut usize {
        &mut self.seed
    }
}

impl<T> HasTargetBytes for QemuFibersInput<T>
where
    T: HasTargetBytes,
{
    fn target_bytes(&self) -> OwnedSlice<u8> {
        self.input.target_bytes()
    }
}

impl<T> Unpin for QemuFibersInput<T> {}