use libafl::inputs::UsesInput;
use libafl_bolts::rands::{Rand, RomuDuoJrRand};

use crate::{Hook, QemuHelper, QemuHelperTuple, QemuHooks};

extern "C" {
    fn fibers_call_scheduler() -> ();
}

#[cfg(emulation_mode = "usermode")]
#[derive(Debug)]
pub struct QemuFibersSchedulerHelper {
    pnrg: RomuDuoJrRand,
}

impl QemuFibersSchedulerHelper {
    pub fn new() -> Self {
        Self {
            pnrg: RomuDuoJrRand::with_seed(1),
        }
    }
    pub fn should_call_scheduler(&self) -> bool {
        let mut pnrg = self.pnrg.clone();
        let rand = pnrg.next();
        rand % 2 == 0
    }
}

impl Default for QemuFibersSchedulerHelper {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> QemuHelper<S> for QemuFibersSchedulerHelper
where
    S: UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = true;

    fn init_hooks<QT>(&self, hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        hooks.blocks(Hook::Empty, Hook::Empty, Hook::Function(call_scheduler::<QT, S>));
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
            println!("Calling scheduler...");
            unsafe { fibers_call_scheduler() };
        }
    }
}
