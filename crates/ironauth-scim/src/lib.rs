// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SCIM 2.0 inbound server surface (issue #135).
//!
//! This crate begins with the FILTER GRAMMAR, because the filter is where a SCIM server is
//! attacked. A provisioning client sends `filter=userName eq "alice"`, and a server that
//! forwards that text toward its datastore has handed an untrusted string to the one place
//! it must never reach. The acceptance criterion says so directly: the parser must handle the
//! RFC 7644 grammar, reject malformed input with SCIM errors, and NEVER reach the datastore
//! unparsed.
//!
//! "Never unparsed" is made STRUCTURAL here rather than promised. [`Filter`] has no variant
//! that can hold raw filter text, and no constructor that takes any: the only way to obtain
//! one is [`parse_filter`]. A future caller cannot smuggle a string through this type,
//! because the type cannot represent one.

#![forbid(unsafe_code)]

mod filter;
mod path;
mod resource;

pub use path::{PathError, ResourceRef, ResourceType, parse_resource_path};
pub use resource::ScimUser;

pub use filter::{
    AttributePath, CompareOp, Filter, FilterError, PresentOp, ScimErrorBody, Value, parse_filter,
};
