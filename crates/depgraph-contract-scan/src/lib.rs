//! Bounded static contract extractors for GraphQL, OpenAPI, Protobuf, and FFI.
//!
//! Each `scan_*_repository` walks a repository with fixed byte, file, and
//! depth limits and returns a cross-language adapter delta. The surface
//! identifiers that the core pins in its release compatibility contract live
//! in `depgraph-protocol`, so the core does not depend on this crate.

pub mod ffi;
pub mod graphql;
pub mod openapi;
pub mod protobuf;

pub use ffi::{
    FFI_CAPABILITY, FFI_FORMAT_VERSION, MAX_FFI_DECLARATIONS, MAX_FFI_FILE_BYTES, MAX_FFI_FILES,
    MAX_FFI_TOTAL_BYTES, scan_ffi_repository,
};
pub use graphql::{
    GRAPHQL_CAPABILITY, GRAPHQL_FORMAT_VERSION, GRAPHQL_REPOSITORY_MAPPING_CAPABILITY,
    GRAPHQL_REPOSITORY_MAPPING_SCHEMA_VERSION, MAX_GRAPHQL_DEFINITIONS, MAX_GRAPHQL_DEPTH,
    MAX_GRAPHQL_FILE_BYTES, MAX_GRAPHQL_FILES, MAX_GRAPHQL_SELECTIONS, MAX_GRAPHQL_TOKENS,
    MAX_GRAPHQL_TOTAL_BYTES, scan_graphql_repository,
};
pub use openapi::{
    MAX_OPENAPI_DEPTH, MAX_OPENAPI_DOCUMENT_BYTES, MAX_OPENAPI_DOCUMENTS,
    MAX_OPENAPI_REFERENCE_DEPTH, MAX_OPENAPI_REFERENCES, MAX_OPENAPI_SCALAR_BYTES,
    MAX_OPENAPI_TOTAL_BYTES, MAX_OPENAPI_VALUES, OPENAPI_CAPABILITY,
    OPENAPI_GENERATED_MAPPING_SCHEMA_VERSION, scan_openapi_repository,
};
pub use protobuf::{
    MAX_PROTOBUF_DEPTH, MAX_PROTOBUF_DESCRIPTOR_BYTES, MAX_PROTOBUF_DESCRIPTOR_FILES,
    MAX_PROTOBUF_FILE_BYTES, MAX_PROTOBUF_FILES, MAX_PROTOBUF_TOKENS, MAX_PROTOBUF_TOTAL_BYTES,
    PROTOBUF_CAPABILITY, PROTOBUF_DESCRIPTOR_SUFFIX, PROTOBUF_GENERATED_MAPPING_SCHEMA_VERSION,
    scan_protobuf_repository,
};
