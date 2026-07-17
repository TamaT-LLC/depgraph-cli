pub mod domain;

use domain::{Named as NameContract, Status};
use missing::BrokenImport as MissingImport;
use std::path::PathBuf;

pub use domain::Envelope as PublicEnvelope;
pub use domain::*;

#[cfg(any(unix, windows))]
pub struct TypeUseFixture<T>
where
    T: NameContract + Identified,
{
    pub field: PublicEnvelope<RecordId>,
    pub external: PathBuf,
    pub missing: missing::Thing,
    pub marker: std::marker::PhantomData<T>,
}

pub type PublicRecord = domain::Record;

pub fn typed<T: NameContract>(
    value: domain::Record,
    external: std::path::PathBuf,
) -> domain::Envelope<T>
where
    T: domain::Identified,
{
    let _ = (value, external, Status::Ready);
    let _ = std::mem::size_of::<Option<MissingImport>>();
    todo!()
}

pub fn exercise(input: u32) -> domain::Envelope<u32> {
    let local = input;
    let direct = domain::Envelope::<u32> { value: local };
    let _ = direct;
    let wrapped = domain::wrap::<u32>(local);
    let _ = wrapped;
    domain::wrap::<u32>(local)
}
