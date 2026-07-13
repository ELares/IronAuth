// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict JSON object parsing shared by the header and claims stages.
//!
//! `serde_json` silently keeps the LAST value for a duplicate object key. In a
//! security header or claim set that is a smuggling seam: a token could carry
//! two `alg` members and have a lenient parser disagree with a strict one about
//! which one signed. This helper rejects any object with a duplicate key, so
//! the header and claim views are unambiguous.

use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::{Map, Value};

/// A JSON object whose keys are guaranteed unique.
pub(crate) struct UniqueObject(pub(crate) Map<String, Value>);

impl<'de> Deserialize<'de> for UniqueObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ObjectVisitor;

        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = Map<String, Value>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object with unique keys")
            }

            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut map = Map::new();
                while let Some((key, value)) = access.next_entry::<String, Value>()? {
                    if map.contains_key(&key) {
                        return Err(de::Error::custom("duplicate object key"));
                    }
                    map.insert(key, value);
                }
                Ok(map)
            }
        }

        deserializer
            .deserialize_map(ObjectVisitor)
            .map(UniqueObject)
    }
}

/// Parse `bytes` as a top-level JSON object with unique keys.
///
/// Rejects a non-object top-level value (array, string, number, and so on) and
/// any duplicate key.
pub(crate) fn parse_unique_object(bytes: &[u8]) -> Result<Map<String, Value>, ()> {
    serde_json::from_slice::<UniqueObject>(bytes)
        .map(|obj| obj.0)
        .map_err(|_| ())
}
