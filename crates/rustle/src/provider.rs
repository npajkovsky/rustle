//! Provider scaffolding: the [`Provider`] descriptor plus the base dispatch
//! table OpenSSL calls (`OSSL_FUNC_PROVIDER_*`).
//!
//! A provider crate declares a `static Provider` with its metadata and
//! algorithm table — all safe, `const` code — and exports the mandatory
//! `OSSL_provider_init` symbol with [`provider_init!`](crate::provider_init).
//! The provider context handed back to the core is simply a pointer to that
//! `'static` descriptor, which is how the (non-generic) callbacks below find
//! the right metadata again on every upcall.

use core::ffi;

use crate::bindings::{OSSL_ALGORITHM, OSSL_CORE_HANDLE, OSSL_DISPATCH};
use crate::params::{OSSL_PARAM, ParamTable, ParamsMut};

/// Everything the OpenSSL core asks a provider for: identity parameters
/// (`name`, `version`, `buildinfo`, `status`) and the algorithm table served
/// by `query_operation`.
///
/// Construction is safe and `const`: [`from_desc`](Self::from_desc) takes
/// only `'static` data ([`ProviderDesc`]) and validates table termination at
/// compile time, so a provider crate can declare its descriptor without any
/// `unsafe`.
pub struct Provider {
    name: &'static ffi::CStr,
    version: &'static ffi::CStr,
    buildinfo: &'static ffi::CStr,
    digests: &'static [OSSL_ALGORITHM],
}

/// Plain public data describing a provider. A provider crate builds one as a
/// struct literal — fields in any order, missing/duplicate fields caught by
/// the compiler — and passes it to [`Provider::from_desc`] for validation:
///
/// ```ignore
/// static PROVIDER: Provider = Provider::from_desc(ProviderDesc {
///     name: c"bc_rust",
///     version: c"0.1.0",
///     buildinfo: c"0.1.0-dev",
///     digests: &DIGESTS,
/// });
///
/// rustle::provider_init!(PROVIDER);
/// ```
pub struct ProviderDesc {
    /// Provider name reported to the core.
    pub name: &'static ffi::CStr,
    /// Version string reported to the core.
    pub version: &'static ffi::CStr,
    /// Build-info string reported to the core.
    pub buildinfo: &'static ffi::CStr,
    /// The `OSSL_OP_DIGEST` algorithm table; must end with
    /// [`OSSL_ALGORITHM::END`].
    pub digests: &'static [OSSL_ALGORITHM],
}

impl Provider {
    /// Builds a provider descriptor from its plain-data description.
    ///
    /// The algorithm table must end with [`OSSL_ALGORITHM::END`], which is
    /// checked at `const`-evaluation time (a violation is a compile error).
    #[must_use]
    pub const fn from_desc(desc: ProviderDesc) -> Self {
        assert!(
            !desc.digests.is_empty() && desc.digests[desc.digests.len() - 1].is_end(),
            "algorithm table must be OSSL_ALGORITHM::END-terminated"
        );
        Self {
            name: desc.name,
            version: desc.version,
            buildinfo: desc.buildinfo,
            digests: desc.digests,
        }
    }

    /// The body of `OSSL_provider_init`; use
    /// [`provider_init!`](crate::provider_init) to export the actual
    /// entry-point symbol.
    ///
    /// Stores `self` as the provider context and hands the core the static
    /// base dispatch table below.
    ///
    /// # Returns
    /// `1` on success, `0` on failure (matching the C provider ABI).
    ///
    /// # Safety
    /// Must be called with the pointers OpenSSL passes to
    /// `OSSL_provider_init`: `out` and `provctx` must be valid out-pointers.
    /// (`handle`/`core_dispatch` are currently unused and only forwarded.)
    pub unsafe fn entry(
        &'static self,
        _handle: *const OSSL_CORE_HANDLE,
        _in_dispatch: *const OSSL_DISPATCH,
        out_dispatch: *mut *const OSSL_DISPATCH,
        provctx: *mut *mut ffi::c_void,
    ) -> ffi::c_int {
        if out_dispatch.is_null() || provctx.is_null() {
            return 0;
        }

        // SAFETY: `provctx` is a valid out-pointer (checked non-null, and the
        // core's contract); we store a pointer to `self`, whose `'static`
        // lifetime outlives the provider instance.
        unsafe { *provctx = core::ptr::from_ref(self).cast_mut().cast::<ffi::c_void>() };
        // SAFETY: `out` is a valid out-pointer; we store a pointer to a
        // `'static` table that outlives the provider.
        unsafe { *out_dispatch = OUT_DISPATCH.as_ptr() };
        1
    }
}

/// The base functions every provider hands back to the core. The callbacks
/// recover their [`Provider`] from `provctx` (set in [`Provider::entry`]), so
/// one static table serves any provider built with this crate.
static OUT_DISPATCH: [OSSL_DISPATCH; 5] = [
    OSSL_DISPATCH::provider_teardown(teardown),
    OSSL_DISPATCH::provider_gettable_params(gettable_params),
    OSSL_DISPATCH::provider_get_params(get_params),
    OSSL_DISPATCH::provider_query_operation(query_operation),
    OSSL_DISPATCH::END,
];

unsafe extern "C" fn teardown(_provctx: *mut ffi::c_void) {
    // The provider context is a borrowed &'static Provider: nothing to free.
}

// gettable_params: the static descriptor table (myprov_param_types[]).
const GETTABLE: ParamTable = crate::param_table! {
    c"name": UTF8_PTR,
    c"version": UTF8_PTR,
    c"buildinfo": UTF8_PTR,
    c"status": INTEGER,
};

unsafe extern "C" fn gettable_params(_provctx: *mut ffi::c_void) -> *const OSSL_PARAM {
    GETTABLE.as_ptr()
}

/// Recovers the `&'static Provider` stored in `provctx` by [`Provider::entry`].
///
/// # Safety
/// `provctx` must be the provider context this crate's `entry` produced (the
/// core passes it back verbatim on every upcall).
unsafe fn provider_from_ctx<'a>(provctx: *mut ffi::c_void) -> Option<&'a Provider> {
    if provctx.is_null() {
        return None;
    }
    // SAFETY: per this function's contract, `provctx` is the pointer `entry`
    // stored: a valid `&'static Provider`.
    Some(unsafe { &*provctx.cast_const().cast::<Provider>() })
}

unsafe extern "C" fn get_params(provctx: *mut ffi::c_void, params: *mut OSSL_PARAM) -> ffi::c_int {
    // SAFETY: the core hands back the provctx that `entry` produced.
    let Some(prov) = (unsafe { provider_from_ctx(provctx) }) else {
        return 0;
    };
    // SAFETY: the core lends a null or valid END-terminated array exclusively
    // for this call, with valid keys and writable typed buffers. Null means
    // nothing was requested, which is a success.
    let Some(mut params) = (unsafe { ParamsMut::from_ptr(params) }) else {
        return 1;
    };

    if let Some(mut p) = params.locate(c"name") {
        if !p.set_utf8_ptr(prov.name) {
            return 0;
        }
    }
    if let Some(mut p) = params.locate(c"version") {
        if !p.set_utf8_ptr(prov.version) {
            return 0;
        }
    }
    if let Some(mut p) = params.locate(c"buildinfo") {
        if !p.set_utf8_ptr(prov.buildinfo) {
            return 0;
        }
    }
    if let Some(mut p) = params.locate(c"status") {
        if !p.set_int(1) {
            return 0;
        }
    }
    1
}

/// Return the algorithm table for the requested operation id.
///
/// Mirrors the C `query_operation` — the core calls this to discover which
/// algorithms the provider supports. `no_cache` is set to `0` to indicate the
/// table never changes (it is `'static`).
unsafe extern "C" fn query_operation(
    provctx: *mut ffi::c_void,
    operation_id: ffi::c_int,
    no_cache: *mut ffi::c_int,
) -> *const OSSL_ALGORITHM {
    if !no_cache.is_null() {
        // SAFETY: `no_cache` is a writable `c_int` pointer provided by the
        // core; we write a single `0` and then discard the pointer.
        unsafe { *no_cache = 0 };
    }

    // SAFETY: the core hands back the provctx that `entry` produced.
    let Some(prov) = (unsafe { provider_from_ctx(provctx) }) else {
        return core::ptr::null();
    };

    match operation_id {
        OSSL_DISPATCH::OSSL_OP_DIGEST => prov.digests.as_ptr(),
        _ => core::ptr::null(),
    }
}

/// Exports the `OSSL_provider_init` entry point for a `static`
/// [`Provider`] descriptor.
///
/// This is the only piece of a provider crate that inherently needs `unsafe`
/// (an unmangled `unsafe extern "C"` symbol) — the expansion lives here, in
/// this crate's tokens, so a provider crate can invoke it even under
#[macro_export]
macro_rules! provider_init {
    ($provider:expr) => {
        /// Provider entry point: OpenSSL looks this symbol up when loading
        /// the module.
        ///
        /// # Safety
        /// Called by OpenSSL across the FFI boundary with valid pointers per
        /// the provider ABI.
        #[allow(non_snake_case)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn OSSL_provider_init(
            handle: *const $crate::bindings::OSSL_CORE_HANDLE,
            in_dispatch: *const $crate::bindings::OSSL_DISPATCH,
            out_dispatch: *mut *const $crate::bindings::OSSL_DISPATCH,
            provctx: *mut *mut ::core::ffi::c_void,
        ) -> ::core::ffi::c_int {
            // SAFETY: every pointer is forwarded verbatim from the core's
            // call, which honours the provider ABI `entry` documents.
            unsafe {
                $crate::provider::Provider::entry(
                    &$provider,
                    handle,
                    in_dispatch,
                    out_dispatch,
                    provctx,
                )
            }
        }
    };
}
