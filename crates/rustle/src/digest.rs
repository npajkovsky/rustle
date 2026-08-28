//! Digest operation (`OSSL_OP_DIGEST`): a safe [`Digest`] trait plus the
//! generic FFI glue that adapts any implementation of it to the
//! `OSSL_FUNC_digest_*` dispatch contract.
//!
//! A provider crate implements [`Digest`] for a plain-Rust hash type and gets
//! an opaque, complete, `END`-terminated dispatch table from
//! [`DigestAlgorithm::functions`] — without writing a single `unsafe` block.
//! All pointer handling required to cross the FFI boundary is confined here.

use core::ffi;
use core::marker::PhantomData;

use crate::bindings::OSSL_DISPATCH;
use crate::heap;
use crate::params::{OSSL_PARAM, ParamMut, ParamTable, Params, ParamsMut};

/// A streaming hash exposable through the provider digest operation.
pub trait Digest: Clone + Default {
    /// Digest output length in bytes, used to size the `final` output
    /// buffer. Implementations typically also report this as `size` from
    /// [`get_param`](Self::get_param).
    const DIGEST_LEN: usize;
    /// Input block length in bytes. Implementations typically also report
    /// this as `blocksize` from [`get_param`](Self::get_param).
    const BLOCK_LEN: usize;

    /// The `END`-terminated descriptor table of params [`get_param`](Self::get_param)
    /// serves, served as `gettable_params`.
    fn gettable_params() -> ParamTable;

    /// Fill one core-requested param named in [`gettable_params`](Self::gettable_params).
    fn get_param(name: &ffi::CStr, param: &mut ParamMut<'_>) -> bool;

    /// The `END`-terminated descriptor table of context params
    /// [`set_ctx_param`](Self::set_ctx_param) accepts, served as
    /// `settable_ctx_params`. Default: none.
    fn settable_ctx_params() -> ParamTable {
        crate::param_table! {}
    }

    /// Apply one core-supplied ctx param to `self`; shared by `init` and
    /// `set_ctx_params`. Default: reject, matching the default empty
    /// [`settable_ctx_params`](Self::settable_ctx_params) (so it is never
    /// actually reached).
    fn set_ctx_param(&mut self, name: &ffi::CStr, param: &OSSL_PARAM) -> bool {
        let _ = (name, param);
        false
    }

    /// Absorb `data` into the hash state. Called any number of times.
    fn update(&mut self, data: &[u8]);

    /// Write the digest into `out`, which is exactly
    /// [`DIGEST_LEN`](Self::DIGEST_LEN) bytes long.
    ///
    /// The state afterwards is unspecified: the core always re-`init`s a
    /// context (resetting it to `Default`) before reusing it.
    fn finalize(&mut self, out: &mut [u8]);
}

/// Ties a [`Digest`] implementation to the `OSSL_FUNC_digest_*` C entry
/// points.
///
/// Never instantiated — it only exists so each digest type gets its own
/// monomorphized dispatch table: `DigestAlgorithm::<MyHash>::functions()`.
pub struct DigestAlgorithm<D>(PhantomData<D>);

/// A complete digest dispatch table whose callbacks share one context type.
///
/// Obtained only from [`DigestAlgorithm::functions`]. The private entries
/// keep allocation, duplication, updates, finalization, and freeing tied to
/// the same [`Digest`] implementation. Copying this value copies the whole
/// table reference; individual callbacks cannot be extracted or replaced.
///
/// Callbacks from different implementations cannot be combined:
///
/// ```compile_fail,E0608
/// use rustle::bindings::OSSL_DISPATCH;
/// use rustle::digest::{Digest, DigestAlgorithm};
/// fn mix<A: Digest, B: Digest>() {
///     let a = DigestAlgorithm::<A>::functions();
///     let b = DigestAlgorithm::<B>::functions();
///     let _mixed = [a[0], b[4], OSSL_DISPATCH::END];
/// }
/// ```
///
/// An arbitrary dispatch slice cannot be wrapped by external code:
///
/// ```compile_fail,E0451
/// use rustle::bindings::OSSL_DISPATCH;
/// use rustle::digest::DigestFunctions;
/// let functions = DigestFunctions { entries: &[OSSL_DISPATCH::END] };
/// ```
#[derive(Clone, Copy)]
pub struct DigestFunctions {
    entries: &'static [OSSL_DISPATCH],
}

impl DigestFunctions {
    // Only this module assembles digest tables. Termination is checked in
    // the associated const below; each callback is monomorphized for one D.
    const fn new(entries: &'static [OSSL_DISPATCH]) -> Self {
        assert!(
            !entries.is_empty() && entries[entries.len() - 1].is_end(),
            "dispatch table must be OSSL_DISPATCH::END-terminated"
        );
        Self { entries }
    }

    pub(crate) const fn as_ptr(&self) -> *const OSSL_DISPATCH {
        self.entries.as_ptr()
    }
}

impl<D: Digest> DigestAlgorithm<D> {
    const FUNCTIONS: DigestFunctions = DigestFunctions::new(&[
        OSSL_DISPATCH::digest_newctx(Self::newctx),
        OSSL_DISPATCH::digest_freectx(Self::freectx),
        OSSL_DISPATCH::digest_dupctx(Self::dupctx),
        OSSL_DISPATCH::digest_init(Self::init),
        OSSL_DISPATCH::digest_update(Self::update),
        OSSL_DISPATCH::digest_final(Self::r#final),
        OSSL_DISPATCH::digest_get_params(Self::get_params),
        OSSL_DISPATCH::digest_gettable_params(Self::gettable_params),
        OSSL_DISPATCH::digest_set_ctx_params(Self::set_ctx_params),
        OSSL_DISPATCH::digest_settable_ctx_params(Self::settable_ctx_params),
        OSSL_DISPATCH::END,
    ]);

    /// The `END`-terminated dispatch table implementing this digest, ready to
    /// be placed in an [`OSSL_ALGORITHM`](crate::bindings::OSSL_ALGORITHM)
    /// entry. The opaque result preserves the complete set of callbacks for
    /// this context type.
    #[must_use]
    pub const fn functions() -> DigestFunctions {
        Self::FUNCTIONS
    }

    /// Forwards every core-supplied ctx param named in
    /// [`Digest::settable_ctx_params`] to `ctx`; shared by `init` and
    /// `set_ctx_params`. A null/absent array is a success, a present-but-
    /// rejected value is a failure.
    fn apply_ctx_params(ctx: &mut D, params: Option<Params<'_>>) -> ffi::c_int {
        // A null array means "nothing to set" — a success, not an error:
        // EVP_DigestInit reaches `init` with NULL params on every plain use.
        let Some(params) = params else {
            return 1;
        };
        let table = D::settable_ctx_params();
        for defn in table.iter() {
            let Some(name) = defn.key() else {
                break;
            };
            if let Some(p) = params.locate(name) {
                if !ctx.set_ctx_param(name, p) {
                    return 0;
                }
            }
        }
        1
    }

    /// `OSSL_FUNC_digest_newctx`: malloc a context holding a fresh hash
    /// state, null on allocation failure.
    unsafe extern "C" fn newctx(_provctx: *mut ffi::c_void) -> *mut ffi::c_void {
        heap::alloc(D::default()).cast()
    }

    /// `OSSL_FUNC_digest_freectx`: drop and release a context.
    ///
    /// Scrubbing sensitive state is `D`'s policy, not the shim's: a hash
    /// type wanting `OPENSSL_clear_free` semantics zeroes itself in `Drop`
    /// (plain safe stores suffice).
    unsafe extern "C" fn freectx(dctx: *mut ffi::c_void) {
        // SAFETY: `dctx` is null or a live `D` from `newctx`/`dupctx`.
        unsafe { heap::free(dctx.cast::<D>()) }
    }

    /// `OSSL_FUNC_digest_dupctx`: clone a context, mid-hash state included.
    unsafe extern "C" fn dupctx(dctx: *mut ffi::c_void) -> *mut ffi::c_void {
        if dctx.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: `dctx` is a live `D` from `newctx`/`dupctx`.
        let src = unsafe { &*dctx.cast_const().cast::<D>() };
        heap::alloc(src.clone()).cast()
    }

    /// `OSSL_FUNC_digest_init`: (re)start the hash computation, applying any
    /// context params passed alongside.
    unsafe extern "C" fn init(dctx: *mut ffi::c_void, params: *const OSSL_PARAM) -> ffi::c_int {
        if dctx.is_null() {
            return 0;
        }
        // SAFETY: `dctx` is a live `D` from `newctx`/`dupctx`.
        let ctx = unsafe { &mut *dctx.cast::<D>() };
        *ctx = D::default();
        // SAFETY: the core supplies a null or valid END-terminated array,
        // with readable keys and typed data unchanged for this call.
        let params = unsafe { Params::from_ptr(params) };
        Self::apply_ctx_params(ctx, params)
    }

    /// `OSSL_FUNC_digest_update`: absorb `inl` bytes of input.
    unsafe extern "C" fn update(dctx: *mut ffi::c_void, r#in: *const u8, inl: usize) -> ffi::c_int {
        if dctx.is_null() || r#in.is_null() {
            return 0;
        }
        if inl == 0 {
            return 1;
        }

        // SAFETY: `dctx` is a live `D` from `newctx`/`dupctx`.
        let ctx = unsafe { &mut *dctx.cast::<D>() };
        // SAFETY: `in` is non-null and the core guarantees it points to `inl`
        // readable bytes.
        let data = unsafe { core::slice::from_raw_parts(r#in, inl) };
        ctx.update(data);
        1
    }

    /// `OSSL_FUNC_digest_final`: write the digest into `out`.
    unsafe extern "C" fn r#final(
        dctx: *mut ffi::c_void,
        out: *mut u8,
        outl: *mut usize,
        outsz: usize,
    ) -> ffi::c_int {
        if dctx.is_null() || out.is_null() || outl.is_null() || outsz < D::DIGEST_LEN {
            return 0;
        }
        // SAFETY: `dctx` is a live `D` from `newctx`/`dupctx`.
        let ctx = unsafe { &mut *dctx.cast::<D>() };
        // SAFETY: `out` is non-null with at least `outsz >= DIGEST_LEN`
        // writable bytes.
        let md = unsafe { core::slice::from_raw_parts_mut(out, D::DIGEST_LEN) };
        ctx.finalize(md);
        // SAFETY: `outl` is a valid out-pointer per the core's contract.
        unsafe { *outl = D::DIGEST_LEN };
        1
    }

    /// `OSSL_FUNC_digest_get_params`: hand each core-requested name listed in
    /// [`Digest::gettable_params`] to [`Digest::get_param`]. Type-level — no
    /// context exists yet, which is why `get_param` takes no `&self`.
    unsafe extern "C" fn get_params(params: *mut OSSL_PARAM) -> ffi::c_int {
        // SAFETY: the core lends a null or valid END-terminated array
        // exclusively for this call, with valid keys and writable typed
        // buffers. Null means nothing was requested, which is a success.
        let Some(mut params) = (unsafe { ParamsMut::from_ptr(params) }) else {
            return 1;
        };

        let table = D::gettable_params();
        for defn in table.iter() {
            let Some(name) = defn.key() else {
                break;
            };
            if let Some(mut p) = params.locate(name) {
                if !D::get_param(name, &mut p) {
                    return 0;
                }
            }
        }
        1
    }

    /// `OSSL_FUNC_digest_gettable_params`: the implementation's descriptor
    /// table.
    unsafe extern "C" fn gettable_params(_provctx: *mut ffi::c_void) -> *const OSSL_PARAM {
        D::gettable_params().as_ptr()
    }

    /// `OSSL_FUNC_digest_set_ctx_params`: forward each parameter to the
    /// implementation's setter.
    unsafe extern "C" fn set_ctx_params(
        dctx: *mut ffi::c_void,
        params: *const OSSL_PARAM,
    ) -> ffi::c_int {
        if dctx.is_null() {
            return 0;
        }
        // SAFETY: `dctx` is a live `D` from `newctx`/`dupctx`; `params` is
        // null or a valid `END`-terminated array per the core's contract.
        let ctx = unsafe { &mut *dctx.cast::<D>() };
        // SAFETY: the core supplies a null or valid END-terminated array,
        // with readable keys and typed data unchanged for this call.
        let params = unsafe { Params::from_ptr(params) };
        Self::apply_ctx_params(ctx, params)
    }

    /// `OSSL_FUNC_digest_settable_ctx_params`: the implementation's
    /// descriptor table.
    unsafe extern "C" fn settable_ctx_params(
        _dctx: *mut ffi::c_void,
        _provctx: *mut ffi::c_void,
    ) -> *const OSSL_PARAM {
        D::settable_ctx_params().as_ptr()
    }
}
