// Copyright The OpenSSL Project Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

struct Configurable(u8);

#[crate::vtable]
impl Digest for Configurable {
    fn newctx() -> Result<Self> {
        Ok(Self(0))
    }
    fn init(&mut self, params: Option<Params<'_>>) -> Result {
        self.apply_ctx_params(params)
    }
    fn update(&mut self, _input: &[u8]) -> Result {
        Ok(())
    }
    fn finalize(&mut self, out: &mut Output<'_>) -> Result {
        out.write(&[self.0])
    }

    crate::gettable_params! {
        c"size": UNSIGNED_INTEGER => |p| p.set_size_t(1),
    }
    crate::settable_ctx_params! {
        c"value": INTEGER => |this, p| match p.get_int().and_then(|n| u8::try_from(n).ok()) {
            Some(value) => { this.0 = value; true }
            None => false,
        },
    }
}

#[test]
fn cooperating_macros_register_setters_after_an_absent_dupctx() {
    const {
        assert!(Configurable::HAS_GET_PARAM);
        assert!(Configurable::HAS_GETTABLE_PARAMS);
        assert!(Configurable::HAS_SET_CTX_PARAM);
        assert!(Configurable::HAS_SETTABLE_CTX_PARAMS);
        assert!(!Configurable::HAS_DUPCTX);
    }
    let entries = DigestAlgorithm::<Configurable>::ENTRIES;
    // There must be no END in the hole left by the absent optional DUPCTX.
    assert_eq!(
        entries.iter().take_while(|entry| !entry.is_end()).count(),
        9
    );
    assert!(entries.last().is_some_and(OSSL_DISPATCH::is_end));
    assert_eq!(Configurable(0).dupctx().err(), Some(Error::Unsupported));
}

#[test]
fn output_tracks_only_successful_bounded_writes() {
    let mut storage = [MaybeUninit::new(0xa5); 6];
    {
        let mut out = Output::new(&mut storage[1..5]);
        let mut called = false;
        assert_eq!(
            out.write_with(5, |_| {
                called = true;
                Ok(())
            }),
            Err(Error::BufferTooSmall)
        );
        assert!(!called);
        assert_eq!(out.written(), 0);
        assert_eq!(out.write(b"ab"), Ok(()));
        assert_eq!(
            out.write_with(1, |bytes| {
                assert_eq!(bytes, &[0]);
                if let Some(byte) = bytes.first_mut() {
                    *byte = b'x';
                }
                Err(Error::Unsupported)
            }),
            Err(Error::Unsupported)
        );
        assert_eq!(out.written(), 2);
        assert_eq!(
            out.write_with(1, |bytes| {
                assert_eq!(bytes, &[0]);
                if let Some(byte) = bytes.first_mut() {
                    *byte = b'c';
                }
                Ok(())
            }),
            Ok(())
        );
        assert_eq!(out.written(), 3);
        assert_eq!(out.write(b"de"), Err(Error::BufferTooSmall));
    }
    // SAFETY: the complete allocation was initialized at construction;
    // Output only overwrites initialized bytes and never deinitializes them.
    let actual = storage.map(|byte| unsafe { byte.assume_init() });
    assert_eq!(actual, [0xa5, b'a', b'b', b'c', 0xa5, 0xa5]);
}

#[test]
fn finalize_reports_length_and_preserves_guards() {
    let mut ctx = Configurable(42);
    let mut bytes = [0xa5u8; 3];
    let mut written = usize::MAX;
    // SAFETY: ctx is a live exclusively borrowed Configurable; the one-byte
    // output region and written slot are disjoint, live and writable.
    let result = unsafe {
        DigestAlgorithm::<Configurable>::finalize(
            core::ptr::from_mut(&mut ctx).cast(),
            bytes.as_mut_ptr().wrapping_add(1),
            &raw mut written,
            1,
        )
    };
    assert_eq!(result, 1);
    assert_eq!(written, 1);
    assert_eq!(bytes, [0xa5, 42, 0xa5]);
    // SAFETY: ctx remains live; null input with zero length is an empty input.
    let result = unsafe {
        DigestAlgorithm::<Configurable>::update(
            core::ptr::from_mut(&mut ctx).cast(),
            core::ptr::null(),
            0,
        )
    };
    assert_eq!(result, 1);
}
