use rayon::iter::IndexedParallelIterator;
use rayon::slice::ParallelSlice;
use std::ffi::CStr;
use std::mem::zeroed;
use std::slice::from_raw_parts;
use std::{mem::transmute_copy, sync::LazyLock};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows::Win32::System::Threading::GetCurrentProcess;

#[cfg(feature = "macros")]
pub use transcend_macros::sig;

// TODO: document
// Get the base of the current process
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
    #[cfg(target_os = "windows")]
    {
        let process = unsafe { GetCurrentProcess() };
        let module = HMODULE(base() as *mut _);
        let mut info = unsafe { zeroed() };

        unsafe {
            GetModuleInformation(process, module, &mut info, size_of::<MODULEINFO>() as u32)
                .unwrap()
        };
        info.SizeOfImage as usize
    }
}

// Find first occurance of a byte pattern and returns it's start address
pub fn scan(pattern: &[u8]) -> Option<*const usize> {
    let base = base();
    let slice = unsafe { from_raw_parts(base as *const u8, size()) };

    slice
        .par_windows(pattern.len())
        .position_first(|window| {
            pattern
                .iter()
                .enumerate()
                .all(|(i, &p)| p == 0xFF || window[i] == p)
        })
        .map(|offset| unsafe { base.add(offset) })
}

#[derive(Debug)]
pub struct Section {
    pub name: String,
    pub base: *const usize,
    pub size: usize,
}

pub fn sections() -> Vec<Section> {
    let base = base();

    let dos_header = unsafe { &*(base as *const IMAGE_DOS_HEADER) };
    if dos_header.e_magic != 0x5A4D {
        println!("Invalid DOS signature.");
        return Vec::new();
    }

    let nt_headers =
        unsafe { &*((base as usize + dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64) };
    if nt_headers.Signature != 0x00004550 {
        println!("Invalid NT signature.");
        return Vec::new();
    }

    let section_header_ptr =
        (base as usize + dos_header.e_lfanew as usize + size_of::<IMAGE_NT_HEADERS64>())
            as *const IMAGE_SECTION_HEADER;

    let mut sections = Vec::new();
    let number_of_sections = nt_headers.FileHeader.NumberOfSections;

    for i in 0..number_of_sections {
        let section = unsafe { &*section_header_ptr.offset(i as isize) };
        let name = unsafe {
            CStr::from_ptr(section.Name.as_ptr() as *const i8)
                .to_string_lossy()
                .into_owned()
        };

        sections.push(Section {
            name,
            base: unsafe { base.offset(section.VirtualAddress as isize) },
            size: unsafe { section.Misc.VirtualSize as usize },
        });
    }

    sections
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
