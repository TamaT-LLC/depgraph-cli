pub mod model;

#[path = "special/custom.rs"]
pub mod custom;

mod inline {
    #[cfg(unix)]
    pub use crate::model::Thing;
}

#[cfg(feature = "renamed")]
pub use renamed::helper;
extern crate renamed;
use std::collections::BTreeMap;

pub const MESSAGE: &str = include_str!("../data/message.txt");
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

pub fn value() -> usize {
    let _map: BTreeMap<String, String> = BTreeMap::new();
    helper()
}
