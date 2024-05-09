use libafl::inputs::{HasBytesVec, Input};
use libafl_bolts::{fs::write_file_atomic, ErrorBacktrace, HasLen};
use serde::{Deserialize, Serialize};
use std::{borrow::Borrow, fs::File, io::Read, path::Path};
use libafl_bolts::Error;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QemuFibersInput<T> {
    pub(crate) input: T,
    pub(crate) seed: u64,
}

impl<T> QemuFibersInput<T>
where
    T: HasBytesVec + Default + Clone,
{
    pub fn new() -> Self {
        Self {
            input: T::default(),
            seed: 1,
        }
    }
    pub fn get_input(&self) -> T {
        self.input.clone()
    }
    pub fn get_input_mut(&mut self) -> &mut T {
        &mut self.input
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

    fn generate_name(&self, idx: usize) -> String {
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
    fn get_seed(&self) -> u64;
    fn get_seed_mut(&mut self) -> &mut u64;
}

impl<T> HasSeed for QemuFibersInput<T>
where
    T: HasBytesVec + Clone + Default,
{
    fn get_seed(&self) -> u64 {
        self.seed.clone()
    }

    fn get_seed_mut(&mut self) -> &mut u64 {
        &mut self.seed
    }
}

impl<T> HasBytesVec for QemuFibersInput<T>
where
    T: HasBytesVec,
{
    fn bytes(&self) -> &[u8] {
        self.input.bytes()
    }

    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        self.input.bytes_mut()
    }
}