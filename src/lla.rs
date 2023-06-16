use cural::Process;

use winapi::um::handleapi::CloseHandle;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::libloaderapi::GetProcAddress;
use winapi::um::memoryapi::VirtualAllocEx;
use winapi::um::memoryapi::VirtualFreeEx;
use winapi::um::memoryapi::WriteProcessMemory;
use winapi::um::processthreadsapi::CreateRemoteThread;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::INFINITE;
use winapi::um::winnt::MEM_COMMIT;
use winapi::um::winnt::MEM_RELEASE;
use winapi::um::winnt::MEM_RESERVE;
use winapi::um::winnt::PAGE_READWRITE;

use std::ffi::CString;
use std::io;
use std::ptr;
use std::mem;

pub unsafe fn inject_lla(process: &Process, dll: CString) -> io::Result<()> {
  let handle = process.get_handle();

  let dll_bytes = dll.as_bytes_with_nul();
  let dll_memory = unsafe {
    VirtualAllocEx(
      handle,
      ptr::null_mut(),
      dll_bytes.len(),
      MEM_COMMIT | MEM_RESERVE,
      PAGE_READWRITE
    )
  };
  if dll_memory.is_null() {
    return Err(io::Error::new(
      io::ErrorKind::Interrupted,
      "VirtualAllocEx failed"
    ));
  }

  let result = unsafe {
    WriteProcessMemory(
      handle,
      dll_memory,
      dll_bytes.as_ptr() as *const _,
      dll_bytes.len(),
      ptr::null_mut()
    )
  };
  if result == 0 {
    unsafe { VirtualFreeEx(handle, dll_memory, 0, MEM_RELEASE) };
    return Err(io::Error::new(
      io::ErrorKind::Interrupted,
      "WriteProcessMemory failed"
    ));
  }

  let kernel32_cstr = CString::new("kernel32.dll").unwrap();
  let kernel_module = unsafe {
    GetModuleHandleA(kernel32_cstr.as_ptr())
  };
  if kernel_module.is_null() {
    unsafe { VirtualFreeEx(handle, dll_memory, 0, MEM_RELEASE) };
    return Err(io::Error::new(
      io::ErrorKind::NotFound,
      "no kernel32.dll found"
    ));
  }

  let load_library_cstr = CString::new("LoadLibraryA").unwrap();
  let load_library = unsafe {
      GetProcAddress(kernel_module, load_library_cstr.as_ptr())
  };
  let thread = unsafe {
    CreateRemoteThread(
      handle,
      ptr::null_mut(),
      0,
      mem::transmute(load_library),
      dll_memory,
      0,
      ptr::null_mut()
    )
  };

  if thread == INVALID_HANDLE_VALUE {
    unsafe { VirtualFreeEx(handle, dll_memory, 0, MEM_RELEASE) };
    return Err(io::Error::new(
      io::ErrorKind::Interrupted,
      "CreateRemoteThread returned invalid handle"
    ));
  }

  unsafe {
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    VirtualFreeEx(handle, dll_memory, 0, MEM_RELEASE)
  };

  Ok(())
}