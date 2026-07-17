pub mod domain;

pub fn exercise(input: u32) -> domain::Envelope<u32> {
    let local = input;
    let direct = domain::Envelope::<u32> { value: local };
    let _ = direct;
    let wrapped = domain::wrap::<u32>(local);
    let _ = wrapped;
    domain::wrap::<u32>(local)
}
