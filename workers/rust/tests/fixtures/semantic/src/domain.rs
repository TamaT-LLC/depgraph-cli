pub struct Envelope<T> {
    pub value: T,
}

pub enum Status {
    Ready,
    Failed { code: u32 },
}

pub type RecordId = u32;

pub trait Identified {
    type Id;
    const PREFIX: u32;

    fn id(&self) -> Self::Id;
    fn create(value: Self::Id) -> Self
    where
        Self: Sized;
}

pub trait Named: Identified {
    fn name(&self) -> &'static str;
}

pub struct Record {
    pub id: RecordId,
}

impl Record {
    pub fn new(id: RecordId) -> Self {
        Self { id }
    }

    pub fn raw(&self) -> RecordId {
        self.id
    }
}

impl Identified for Record {
    type Id = RecordId;
    const PREFIX: u32 = 7;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn create(value: Self::Id) -> Self {
        Self { id: value }
    }
}

impl Named for Record {
    fn name(&self) -> &'static str {
        "record"
    }
}

pub fn wrap<T>(value: T) -> Envelope<T> {
    Envelope { value }
}
