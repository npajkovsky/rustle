// Copyright The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generic implementation and conditional method-presence checks.

#![forbid(unsafe_code)]

use rustle_macros::vtable;

#[vtable]
trait Operations<T> {
    fn r#type(&self) -> u8 {
        0
    }
    fn required(&self, value: T) -> T;
    fn optional(&self) -> bool {
        false
    }
    fn disabled(&self) -> bool {
        false
    }
    fn attr_disabled(&self) -> bool {
        false
    }
}

struct Generic<T>(T);

#[vtable]
impl<T: Copy> Operations<T> for Generic<T> {
    fn r#type(&self) -> u8 {
        1
    }
    fn required(&self, value: T) -> T {
        value
    }

    fn optional(&self) -> bool {
        true
    }

    #[cfg(any())]
    fn disabled(&self) -> bool {
        true
    }

    #[cfg_attr(all(), cfg(any()))]
    fn attr_disabled(&self) -> bool {
        true
    }
}

#[test]
fn generic_methods_follow_conditional_compilation() {
    const {
        assert!(Generic::<u8>::HAS_REQUIRED);
        assert!(Generic::<u8>::HAS_TYPE);
        assert!(Generic::<u8>::HAS_OPTIONAL);
        assert!(!Generic::<u8>::HAS_DISABLED);
        assert!(!Generic::<u8>::HAS_ATTR_DISABLED);
    }
    let value = Generic(0u8);
    assert_eq!(value.r#type(), 1);
    assert_eq!(value.required(7), 7);
    assert!(value.optional());
    assert!(!value.disabled());
    assert!(!value.attr_disabled());
}
