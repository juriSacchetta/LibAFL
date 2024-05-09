use libafl::{inputs::UsesInput, mutators::Mutator, state::HasRand};
use libafl_bolts::Named;
use libafl_bolts::rands::Rand;

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
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<libafl::prelude::MutationResult, libafl::prelude::Error> {
        let seed = state.rand_mut().below(0xFFFF_FFFF_FFFF_FFFF);
        *input.get_seed_mut() = seed;
        Ok(libafl::prelude::MutationResult::Mutated)
    }
}

impl Named for QemuFibersSeedMutator {
    fn name(&self) -> &str {
        "QemuFibersSeedMutator"
    }
}
