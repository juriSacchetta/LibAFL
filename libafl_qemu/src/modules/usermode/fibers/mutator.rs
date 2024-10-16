use std::borrow::Cow;
use std::num::NonZero;

use libafl::{inputs::UsesInput, mutators::Mutator, state::HasRand};
use libafl::mutators::MutationResult;
use libafl_bolts::Named;
use libafl_bolts::rands::Rand;
use libafl_bolts::Error;

use super::input::HasSeed;

pub struct QemuFibersSeedMutator {}

impl QemuFibersSeedMutator {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for QemuFibersSeedMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl<I, S> Mutator<I, S> for QemuFibersSeedMutator
where
    S: UsesInput + HasRand,
    I: HasSeed,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        let seed = state.rand_mut().below(NonZero::new(0xFFFF_FFFF_FFFF_FFFF).unwrap());
        *input.get_seed_mut() = seed;
        Ok(MutationResult::Mutated)
    }
}

impl Named for QemuFibersSeedMutator {
    fn name(&self) -> &Cow<'static, str> {
        &std::borrow::Cow::Borrowed("QemuFibersSeedMutator")
    }
}
