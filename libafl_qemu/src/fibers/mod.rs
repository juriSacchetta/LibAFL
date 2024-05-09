#![cfg(all(emulation_mode = "usermode", feature = "qemu_fibers"))]

use core::fmt::Debug;
use libafl::inputs::UsesInput;
use libafl_bolts::rands::{Rand, RomuDuoJrRand};

use crate::{
    Emulator, Hook, QemuHelper, QemuHelperTuple, QemuHooks,
};

use crate::fibers::input::HasSeed;

pub mod input;

pub mod mutator;

extern "C" {
    fn fibers_call_scheduler() -> ();
}

#[derive(Clone, Copy, Debug)]
pub struct QemuFibersSchedulerHelper {
    pnrg: RomuDuoJrRand,
    seed: u64,
}

impl QemuFibersSchedulerHelper {
    pub fn new(init_seed: u64) -> Self {
        Self {
            pnrg: RomuDuoJrRand::with_seed(init_seed),
            seed: init_seed,
        }
    }
    pub fn should_call_scheduler(&self) -> bool {
        let mut pnrg = self.pnrg.clone();
        let rand = pnrg.next();
        rand % 100 == 0
    }
    pub fn set_seed(&mut self, seed: u64) {
        self.pnrg = RomuDuoJrRand::with_seed(seed);
        self.seed = seed;
    }
}

impl Default for QemuFibersSchedulerHelper {
    fn default() -> Self {
        Self::new(1)
    }
}

impl<S> QemuHelper<S> for QemuFibersSchedulerHelper
where
    S: UsesInput, S::Input: HasSeed
{
    const HOOKS_DO_SIDE_EFFECTS: bool = true;

    fn init_hooks<QT>(&self, hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        hooks.blocks(
            Hook::Empty,
            Hook::Empty,
            Hook::Function(call_scheduler::<QT, S>),
        );
    }

    fn pre_exec(&mut self, _: &Emulator, _input: &S::Input) {
        self.set_seed(_input.get_seed());
    }
}

pub fn call_scheduler<QT, S>(hooks: &mut QemuHooks<QT, S>, _state: Option<&mut S>, _data: u64)
where
    QT: QemuHelperTuple<S>,
    S: UsesInput,
{
    if let Some(h) = hooks
        .helpers()
        .match_first_type::<QemuFibersSchedulerHelper>()
    {
        if h.should_call_scheduler() {
            unsafe { fibers_call_scheduler() };
        }
    }
}
