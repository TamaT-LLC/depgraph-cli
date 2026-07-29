#![crate_type = "lib"]

#[inline(never)]
fn generic<T: Copy>(value: T) -> T {
    value
}

#[inline(never)]
fn direct() {}

#[inline(never)]
fn alternative() {}

struct Dropped;

impl Drop for Dropped {
    fn drop(&mut self) {
        direct();
    }
}

#[inline(never)]
pub fn candidate(flag: bool) {
    let function: fn() = if flag { direct } else { alternative };
    function();
}

#[inline(never)]
pub fn unknown(function: fn()) {
    function();
}

#[inline(never)]
pub fn root() -> u32 {
    let _dropped = Dropped;
    let closure = |value| generic::<u32>(value);
    candidate(true);
    closure(7)
}
