use clap::{Arg, Command};
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::ExitKind,
    feedbacks::{CrashFeedback, MaxMapFeedback},
    inputs::{BytesInput, HasBytesVec, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::{HitcountsMapObserver, VariableMapObserver},
    schedulers::QueueScheduler,
    stages::{MutationalStage, StdMutationalStage},
    state::{HasCorpus, StdState},
    Error, Fuzzer, StdFuzzer,
};
use libafl_bolts::{
    current_nanos,
    os::{dup, dup2},
    rands::StdRand,
    tuples::tuple_list,
    AsSlice,
};
use libafl_qemu::{
    edges::{edges_map_mut_slice, MAX_EDGES_NUM},
    elf::EasyElf, fibers::{input::QemuFibersInput, mutator::QemuFibersSeedMutator, QemuFibersSchedulerHelper}, filter_qemu_args, Emulator, GuestReg, MmapPerms, QemuEdgeCoverageHelper, QemuExecutor, QemuHooks, QemuSnapshotHelper, Regs,
};
use std::{
    env,
    fs::{self, File},
    os::fd::FromRawFd,
    path::PathBuf,
    process,
    ptr::addr_of_mut,
    time::Duration,
};
use std::{
    io::{self, Write},
    os::fd::AsRawFd,
};

pub fn main() {
    let res = match Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author("AFLplusplus team")
        .about("LibAFL-based fuzzer with QEMU for Fuzzbench")
        .arg(
            Arg::new("out")
                .help("The directory to place finds in ('corpus')")
                .long("libafl-out")
                .required(true),
        )
        .arg(
            Arg::new("in")
                .help("The directory to read initial inputs from ('seeds')")
                .long("libafl-in")
                .required(true),
        )
        .arg(
            Arg::new("tokens")
                .long("libafl-tokens")
                .help("A file to read tokens from, to be used during fuzzing"),
        )
        .arg(
            Arg::new("timeout")
                .long("libafl-timeout")
                .help("Timeout for each individual execution, in milliseconds")
                .default_value("10000000000"),
        )
        .try_get_matches_from(filter_qemu_args())
    {
        Ok(res) => res,
        Err(err) => {
            println!(
                "Syntax: {}, --libafl-in <input> --libafl-out <output>\n{:?}",
                env::current_exe()
                    .unwrap_or_else(|_| "fuzzer".into())
                    .to_string_lossy(),
                err,
            );
            return;
        }
    };

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    // For fuzzbench, crashes and finds are inside the same `corpus` directory, in the "queue" and "crashes" subdir.
    let mut out_dir = PathBuf::from(res.get_one::<String>("out").unwrap().to_string());
    if fs::create_dir(&out_dir).is_err() {
        println!("Out dir at {:?} already exists.", &out_dir);
        if !out_dir.is_dir() {
            println!("Out dir at {:?} is not a valid directory!", &out_dir);
            return;
        }
    }
    let mut crashes = out_dir.clone();
    crashes.push("crashes");
    out_dir.push("queue");

    let in_dir = PathBuf::from(res.get_one::<String>("in").unwrap().to_string());
    if !in_dir.is_dir() {
        println!("In dir at {:?} is not a valid directory!", &in_dir);
        return;
    }

    let timeout = Duration::from_millis(
        res.get_one::<String>("timeout")
            .unwrap()
            .to_string()
            .parse()
            .expect("Could not parse timeout in milliseconds"),
    );

    fuzz(out_dir, crashes, in_dir, timeout).expect("An error occurred while fuzzing");
}

//pub const MAX_INPUT_SIZE: usize = 1048576; // 1MB
pub const MAX_INPUT_SIZE: usize = 100;

fn fuzz(
    corpus_dir: PathBuf,
    objective_dir: PathBuf,
    seed_dir: PathBuf,
    timeout: Duration,
) -> Result<(), Error> {
    env::remove_var("LD_LIBRARY_PATH");

    let args: Vec<String> = env::args().collect();
    let env: Vec<(String, String)> = env::vars().collect();
    let emu = Emulator::new(&args, &env).unwrap();

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer)?;

    let test_one_input_ptr = elf
        .resolve_symbol("LLVMFuzzerTestOneInput", emu.load_addr())
        .expect("Symbol LLVMFuzzerTestOneInput not found");
    println!("LLVMFuzzerTestOneInput @ {test_one_input_ptr:#x}");

    emu.set_breakpoint(test_one_input_ptr); // LLVMFuzzerTestOneInput
    unsafe {
        let _ = emu.run();
    };

    println!("Break at {:#x}", emu.read_reg::<_, u64>(Regs::Rip).unwrap());

    let stack_ptr: u64 = emu.read_reg(Regs::Rsp).unwrap();
    let mut ret_addr = [0; 8];
    unsafe { emu.read_mem(stack_ptr, &mut ret_addr) };
    let ret_addr = u64::from_le_bytes(ret_addr);

    println!("Stack pointer = {stack_ptr:#x}");
    println!("Return address = {ret_addr:#x}");

    emu.remove_breakpoint(test_one_input_ptr); // LLVMFuzzerTestOneInput
    emu.set_breakpoint(ret_addr); // LLVMFuzzerTestOneInput ret addr

    let input_addr = emu
        .map_private(0, MAX_INPUT_SIZE, MmapPerms::ReadWrite)
        .unwrap();
    println!("Placing input at {input_addr:#x}");


    // Create an observation channel using the coverage map
    let edges_observer = unsafe {
        HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
            "edges",
            edges_map_mut_slice(),
            addr_of_mut!(MAX_EDGES_NUM),
        ))
    };

    let mut feedback = MaxMapFeedback::tracking(&edges_observer, true, false);

    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryOnDiskCorpus::new(corpus_dir).unwrap(),
        OnDiskCorpus::new(objective_dir).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    // The Monitor trait define how the fuzzer stats are displayed to the user
    let mon = SimpleMonitor::new(|s| {
        println!("{s}");
    });

    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &QemuFibersInput<BytesInput>| {
        let target = input.get_input();
        let mut buf = target.bytes().as_slice();
        let mut len = buf.len();

        if len > MAX_INPUT_SIZE {
            buf = &buf[0..MAX_INPUT_SIZE];
            len = MAX_INPUT_SIZE;
        }

        unsafe {
            emu.write_mem(input_addr, buf);

            emu.write_reg(Regs::Rdi, input_addr).unwrap();
            emu.write_reg(Regs::Rsi, len as GuestReg).unwrap();
            emu.write_reg(Regs::Rip, test_one_input_ptr).unwrap();
            emu.write_reg(Regs::Rsp, stack_ptr).unwrap();

            let _ = emu.run();
        }

        ExitKind::Ok
    };

    let mut hooks = QemuHooks::new(
        emu.clone(),
        tuple_list!(
            QemuEdgeCoverageHelper::default(),
            QemuFibersSchedulerHelper::default(),
            //QemuSnapshotHelper::default(),
        ),
    );

    // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
    let mut executor = QemuExecutor::new(
        &mut hooks,
        &mut harness,
        tuple_list!(edges_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )?;

    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seed_dir.clone()])
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus at {:?}", &seed_dir);
                process::exit(0);
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    // Setup a mutational stage with a basic bytes mutator
    // let mutator = StdScheduledMutator::new(havoc_mutations());
    // let mut stages = tuple_list!(StdMutationalStage::new(mutator), StdMutationalStage::new(QemuFibersSeedMutator::new()));
    let mut stages = tuple_list!(StdMutationalStage::new(QemuFibersSeedMutator::new()));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");

    Ok(())
}
