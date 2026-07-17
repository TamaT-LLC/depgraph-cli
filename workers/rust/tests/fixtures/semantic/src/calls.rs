pub fn direct_target(value: u32) -> u32 {
    value + 1
}

pub fn alternate_target(value: u32) -> u32 {
    value + 2
}

pub fn generic_target<T>(value: T) -> T {
    value
}

pub struct Worker(pub u32);

pub struct GenericWorker<T>(pub T);

impl<T: Copy> GenericWorker<T> {
    pub fn create(value: T) -> Self {
        Self(value)
    }

    pub fn copied(&self) -> T {
        self.0
    }
}

impl Worker {
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    pub fn inherent(&self) -> u32 {
        self.0
    }
}

struct Backup(u32);

trait ClosedDispatch {
    fn dispatch(&self) -> u32;

    fn associated(value: u32) -> u32;

    fn defaulted(&self) -> u32 {
        99
    }

    fn associated_default(value: u32) -> u32 {
        value + 20
    }
}

impl ClosedDispatch for Worker {
    fn dispatch(&self) -> u32 {
        self.0
    }

    fn associated(value: u32) -> u32 {
        value + 3
    }
}

impl ClosedDispatch for Backup {
    fn dispatch(&self) -> u32 {
        self.0 + 10
    }

    fn associated(value: u32) -> u32 {
        value + 4
    }
}

pub trait OpenDispatch {
    fn open_dispatch(&self) -> u32;
}

impl OpenDispatch for Worker {
    fn open_dispatch(&self) -> u32 {
        self.0
    }
}

macro_rules! generated_call {
    ($value:expr) => {
        direct_target($value)
    };
}

pub fn exact_calls(value: u32) -> u32 {
    let worker = Worker::new(value);
    let direct = direct_target(value);
    let generic = generic_target::<u32>(direct);
    generic
        + worker.inherent()
        + worker.dispatch()
        + worker.defaulted()
        + <Worker as ClosedDispatch>::associated(value)
        + <Worker as ClosedDispatch>::associated_default(value)
}

pub fn generic_impl_calls(value: u32) -> u32 {
    let worker = GenericWorker::<u32>::create(value);
    worker.copied()
}

fn closed_dynamic(value: &dyn ClosedDispatch) -> u32 {
    value.dispatch() + value.defaulted()
}

fn closed_generic<T: ClosedDispatch>(value: &T) -> u32 {
    value.dispatch()
}

pub fn exercise_closed_dispatch(value: u32) -> u32 {
    let worker = Worker(value);
    closed_dynamic(&worker) + closed_generic(&worker)
}

pub fn open_dynamic(value: &dyn OpenDispatch) -> u32 {
    value.open_dispatch()
}

pub fn closure_calls(value: u32) -> u32 {
    let closure = |input| direct_target(input);
    closure(value) + (|| alternate_target(value))()
}

pub fn function_pointer_calls(flag: bool, value: u32) -> u32 {
    let single: fn(u32) -> u32 = direct_target;
    let selected: fn(u32) -> u32 = if flag {
        direct_target
    } else {
        alternate_target
    };
    let alias = selected;
    single(value) + alias(value)
}

pub fn unknown_function_pointer(callback: fn(u32) -> u32, value: u32) -> u32 {
    callback(value)
}

pub fn external_call() -> usize {
    std::mem::size_of::<Worker>()
}

pub fn external_alias_call() -> usize {
    external_size::<Worker>()
}

pub fn unresolved_call(value: u32) -> u32 {
    missing_call(value)
}

pub fn macro_call(value: u32) -> u32 {
    generated_call!(value)
}

#[cfg(any(unix, windows))]
pub fn conditioned_call(value: u32) -> u32 {
    direct_target(value)
}

pub struct TupleConstructor(pub u32);

pub fn tuple_constructor_is_not_a_call(value: u32) -> TupleConstructor {
    TupleConstructor(value)
}
use std::mem::size_of as external_size;

pub fn match_arm_conditioned(value: Option<u32>) -> u32 {
    match value {
        #[cfg(unix)]
        Some(value) => direct_target(value),
        _ => 0,
    }
}
