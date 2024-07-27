use std::mem::zeroed;
use std::{mem::transmute_copy, sync::LazyLock};
use windows::Win32::Foundation::{HANDLE, HMODULE};
use windows::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};

// TODO: document
// Get the size of the current process
#[must_use]
#[inline(always)]
pub fn base() -> *const usize {
    struct Base(*const usize);
    unsafe impl Send for Base {}
    unsafe impl Sync for Base {}

    static BASE: LazyLock<Base> = LazyLock::new(|| {
        #[cfg(target_os = "windows")]
        {
            use windows::core::PCWSTR;
            use windows::Win32::System::LibraryLoader::GetModuleHandleW;

            // SAFETY: `GetModuleHandleW(null)` returns a handle to the current process, which is (presumably) always valid for the lifetime of the process.
            // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlew
            let address =
                unsafe { GetModuleHandleW(PCWSTR::null()).unwrap_unchecked().0 as *const usize };

            Base(address)
        }

        #[cfg(target_os = "linux")]
        {
            use core::mem::zeroed;
            use libc::{dladdr, getauxval, Dl_info, AT_PHDR};

            let address = {
                let mut info: Dl_info = unsafe { zeroed() };
                let dummy_address = unsafe { getauxval(AT_PHDR) as *const usize };
                unsafe { dladdr(dummy_address.cast(), &mut info) };
                info.dli_fbase as *const usize
            };

            Base(address)
        }
    });

    BASE.0
}

// TODO: document
// Get the size of the current process
#[must_use]
pub fn size() -> usize {
    let base = base() as *mut _;

    let process = HANDLE(base);
    let module = HMODULE(base);

    let info = unsafe { zeroed() };

    unsafe { GetModuleInformation(process, module, info, size_of::<MODULEINFO>() as u32).unwrap() };
    unsafe { (*info).SizeOfImage as usize }
}

/// Calculates the offset from the base address of the calling process (.exe file).
///
/// # Safety
/// If any of the following conditions are violated, the result is Undefined Behavior:
/// - The computed offset, in bytes, cannot overflow an `isize`.
/// - The resulting function pointer from the computed offset must point to a function with the same signature as `F`.
///
/// # Examples
/// ```
/// type Add = unsafe extern "C" fn(u32, u32) -> u32;
///
/// let offset = 0x2843A0;
/// let add: Add = resolve_fn(offset);
///
/// unsafe { assert_eq!(2, add(1, 1)); }
/// ```
#[must_use]
#[inline(always)]
pub unsafe fn resolve_fn<F: FnPtr>(offset: usize) -> F {
    // SAFETY: The caller guarantees that `F` is an `unsafe extern "ABI" fn`.
    unsafe { transmute_copy(&base().add(offset)) }
}

pub trait FnPtr {}

macro_rules! impl_fnptr {
    ($(($($args:ident),*)),*) => {
        $(
            impl<R, $($args),*> FnPtr for unsafe extern "C" fn($($args),*) -> R {}
            impl<R, $($args),*> FnPtr for unsafe extern "cdecl" fn($($args),*) -> R {}
            impl<R, $($args),*> FnPtr for unsafe extern "win64" fn($($args),*) -> R {}
            impl<R, $($args),*> FnPtr for unsafe extern "fastcall" fn($($args),*) -> R {}
            impl<R, $($args),*> FnPtr for unsafe extern "thiscall" fn($($args),*) -> R {}
        )*
    };
}

impl_fnptr! {
    (),
    (A1),
    (A1, A2),
    (A1, A2, A3),
    (A1, A2, A3, A4)
}
