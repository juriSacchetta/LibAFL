use core::fmt::Debug;
use libafl_bolts::rands::{Rand, RomuDuoJrRand};

use crate::{Hook, modules::{EmulatorModule, EmulatorModules, UsesInput, EmulatorModuleTuple}};
use crate::modules::NopAddressFilter;

use std::ptr::addr_of_mut;
use crate::modules::NOP_ADDRESS_FILTER;

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

impl<S> EmulatorModule<S> for QemuFibersSchedulerHelper
where
    S: UsesInput + Unpin,
{
    type ModuleAddressFilter = NopAddressFilter;

    fn init_module<ET>(&self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        _emulator_modules.blocks(
            Hook::Empty,
            Hook::Empty,
            Hook::Function(call_scheduler),
        );
    }

    fn address_filter(&self) -> &Self::ModuleAddressFilter {
        &NopAddressFilter
    }
    fn address_filter_mut(&mut self) -> &mut Self::ModuleAddressFilter {
        unsafe { addr_of_mut!(NOP_ADDRESS_FILTER).as_mut().unwrap().get_mut() }
    }
}

pub fn call_scheduler<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    _size: u64,
)
where
    ET: EmulatorModuleTuple<S>,
    S: Unpin + UsesInput,
{
    if let Some(h) = emulator_modules.get::<QemuFibersSchedulerHelper>() {
        if h.should_call_scheduler() {
            unsafe { fibers_call_scheduler() };
        }
    }
}
