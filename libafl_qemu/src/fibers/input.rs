use libafl::inputs::{Input, HasBytesVec, UsesInput};
use libafl_bolts::HasLen;
use std::rc::Rc;
use std::cell::RefCell;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QemuFibersInput<T> {
    pub(crate) input: T,
}

impl<T> QemuFibersInput<T> where T: Default + HasBytesVec {
    pub fn new() -> Self {
        Self {
            input: T::default(),
        }
    }
    pub fn get_seed(&self) -> u64 {
        let input_bytes: &[u8] = self.input.bytes();
        let u64_bytes: &[u8] = &input_bytes[..std::mem::size_of::<u64>()];
        let u64_array: [u8; 8] = u64_bytes.try_into().expect("slice with incorrect length");
        u64::from_le_bytes(u64_array)
    }
    pub fn get_input(&self) -> Vec<u8> {
        self.input.bytes()[std::mem::size_of::<u64>()..].to_vec()
    }
}

impl<T> UsesInput for QemuFibersInput<T> where T: Input{
    type Input = QemuFibersInput<T>;
}

impl<I> Input for QemuFibersInput<I>
where
    I: Input,
{
    fn generate_name(&self, idx: usize) -> String {
        format!("fibers-{}", self.input.generate_name(idx))
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

impl<T> From<QemuFibersInput<T>> for Rc<RefCell<QemuFibersInput<T>>>
{
    fn from(input: QemuFibersInput<T>) -> Self {
        Rc::new(RefCell::new(input))
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

pub trait HasSeed {
    fn get_seed(&self) -> u64;
}

impl<T> HasSeed for QemuFibersInput<T> where T: Default + HasBytesVec{
    fn get_seed(&self) -> u64 {
       QemuFibersInput::get_seed(&self)
    }
}