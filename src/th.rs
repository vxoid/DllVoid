use cural::Process;

use std::ffi::CString;
use std::io;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use winapi::um::{ handleapi::*, libloaderapi::*, memoryapi::*, tlhelp32::*, processthreadsapi::*, winnt::*, winuser::PostThreadMessageA };
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use std::{ mem, ptr, time, thread };

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn get_thread_id_off_process_id(pid: u32) -> io::Result<u32> {
  let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
  if snapshot == INVALID_HANDLE_VALUE {
    return Err(io::Error::new(
      io::ErrorKind::Interrupted,
      "CreateToolhelp32Snapshot returned invalid handle"
    ));
  }

  let mut entry: THREADENTRY32 = mem::zeroed();
  entry.dwSize = mem::size_of::<THREADENTRY32>() as u32;

  if Thread32First(snapshot, &mut entry) == 1 {
    while Thread32Next(snapshot, &mut entry) != 0 {
      if entry.th32OwnerProcessID == pid {
        CloseHandle(snapshot);
        return Ok(entry.th32ThreadID);
      }
    }
  }

  CloseHandle(snapshot);
  Err(io::Error::new(
    io::ErrorKind::NotFound,
    format!("no thread found by pid {}", pid)
  ))
}

#[cfg(target_arch = "x86")]
#[repr(C, align(16))] // required by `CONTEXT`, is a FIXME in winapi right now
struct WowContext(WOW64_CONTEXT);

#[cfg(target_arch = "x86")]
unsafe fn x86_threadhijack(process: &Process, cstring: CString) -> io::Result<()> {
  use winapi::um::winbase::*;

  let handle = process.get_handle();
  let thread_id = get_thread_id_off_process_id(process.get_id().clone())?;
  let dll_bytes = cstring.as_bytes_with_nul();

  let thread_handle = OpenThread(THREAD_ALL_ACCESS, 0, thread_id);
  if thread_handle == INVALID_HANDLE_VALUE {
    return Err(io::Error::last_os_error());
  }
  if SuspendThread(thread_handle) == u32::MAX {
    CloseHandle(thread_handle);
    return Err(io::Error::last_os_error());
  }

  let mut tcontext = mem::zeroed::<WowContext>();
  tcontext.0.ContextFlags = CONTEXT_FULL;
  if Wow64GetThreadContext(thread_handle, &mut tcontext.0) != 1 {
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);
    return Err(io::Error::last_os_error());
  }

  let dll_addr = VirtualAllocEx(
    handle,
    core::ptr::null_mut(),
    dll_bytes.len(),
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE,
  );
  if dll_addr.is_null() {
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);
    return Err(io::Error::last_os_error());
  }
  if WriteProcessMemory(
    handle,
    dll_addr,
    dll_bytes.as_ptr() as *const _,
    dll_bytes.len(),
    core::ptr::null_mut(),
  ) == 0
  {
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);
    VirtualFreeEx(handle, dll_addr, 0, MEM_RELEASE);
    return Err(io::Error::last_os_error());
  }

  let kernel_module = CString::new("kernel32.dll").unwrap();
  let kernel_module = GetModuleHandleA(kernel_module.as_ptr());
  if kernel_module.is_null() {
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);
    VirtualFreeEx(handle, dll_addr, 0, MEM_RELEASE);
    return Err(io::Error::last_os_error());
  }

  let load_library = CString::new("LoadLibraryA").unwrap();
  let load_library = GetProcAddress(kernel_module, load_library.as_ptr());
  let mut payload = [
    0x00, 0x00, 0x00,
    0x00, // - 0x04 (pCodecave)	-> returned value							;buffer to store returned value (eax)
    0x83, 0xEC, 0x04, // + 0x00				-> sub esp, 0x04							;prepare stack for ret
    0xC7, 0x04, 0x24, 0x00, 0x00, 0x00,
    0x00, // + 0x03 (+ 0x06)		-> mov [esp], OldEip						;store old eip as return address
    0x50, 0x51, 0x52, // + 0x0A				-> psuh e(a/c/d)							;save e(a/c/d)x
    0x9C, // + 0x0D				-> pushfd									;save flags register
    0xB9, 0x00, 0x00, 0x00,
    0x00, // + 0x0E (+ 0x0F)		-> mov ecx, pArg							;load pArg into ecx
    0xB8, 0x00, 0x00, 0x00, 0x00, // + 0x13 (+ 0x14)		-> mov eax, pRoutine
    0x51, // + 0x18				-> push ecx									;push pArg
    0xFF, 0xD0, // + 0x19				-> call eax									;call target function
    0xA3, 0x00, 0x00, 0x00,
    0x00, // + 0x1B (+ 0x1C)		-> mov dword ptr[pCodecave], eax			;store returned value
    0x9D, // + 0x20				-> popfd									;restore flags register
    0x5A, 0x59, 0x58, // + 0x21				-> pop e(d/c/a)								;restore e(d/c/a)x
    0xC6, 0x05, 0x00, 0x00, 0x00, 0x00,
    0x00, // + 0x24 (+ 0x26)		-> mov byte ptr[pCodecave + 0x06], 0x00		;set checkbyte to 0
    0xC3u8,
  ];
  let mut payload_pointer;
  let code_cave = VirtualAllocEx(
    handle,
    core::ptr::null_mut(),
    payload.len(),
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,
  );
  if code_cave.is_null() {
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);
    VirtualFreeEx(handle, dll_addr, 0, MEM_RELEASE);
    return Err(io::Error::last_os_error());
  }

  // set up shellcode
  let dissected_address;
  let dissected_dllpath_addr;
  let dissected_loadlib_addr;
  let dissected_code_cave_addr;
  let dissected_byte_offset_addr;

  if cfg!(target_endian = "big") {
    dissected_byte_offset_addr = (code_cave as u32 + 0x06).to_be_bytes();
    dissected_code_cave_addr = (code_cave as u32).to_be_bytes();
    dissected_address = tcontext.0.Eip.to_be_bytes();
    dissected_dllpath_addr = (dll_addr as u32).to_be_bytes();
    dissected_loadlib_addr =
      (mem::transmute::<_, *const u32>(load_library) as u32).to_be_bytes();
  } else {
    dissected_byte_offset_addr = (code_cave as u32 + 0x06).to_le_bytes();
    dissected_code_cave_addr = (code_cave as u32).to_le_bytes();
    dissected_address = tcontext.0.Eip.to_le_bytes();
    dissected_dllpath_addr = (dll_addr as u32).to_le_bytes();
    dissected_loadlib_addr =
      (mem::transmute::<_, *const u32>(load_library) as u32).to_le_bytes();
  }
  payload_pointer = payload.as_mut_ptr().add(10); // ret
  ptr::copy_nonoverlapping(dissected_address.as_ptr(), payload_pointer, 4);
  payload_pointer = payload.as_mut_ptr().add(19); // arg for LoadLibraryW
  ptr::copy_nonoverlapping(dissected_dllpath_addr.as_ptr(), payload_pointer, 4);
  payload_pointer = payload.as_mut_ptr().add(24); // LoadLibraryW address
  ptr::copy_nonoverlapping(dissected_loadlib_addr.as_ptr(), payload_pointer, 4);
  payload_pointer = payload.as_mut_ptr().add(32); // code cave address
  ptr::copy_nonoverlapping(dissected_code_cave_addr.as_ptr(), payload_pointer, 4);
  payload_pointer = payload.as_mut_ptr().add(42); // code cave address + byte offset thing
  ptr::copy_nonoverlapping(dissected_byte_offset_addr.as_ptr(), payload_pointer, 4);
  // end of setting up shellcode

  tcontext.0.Eip = code_cave as u32 + 0x04;
  if WriteProcessMemory(
    handle,
    code_cave,
    payload.as_ptr() as *const _,
    payload.len(),
    core::ptr::null_mut(),
  ) == 0
  {
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);
    VirtualFreeEx(handle, dll_addr, 0, MEM_RELEASE);
    VirtualFreeEx(handle, code_cave, 0, MEM_RELEASE);
    return Err(io::Error::last_os_error());
  }

  if Wow64SetThreadContext(thread_handle, &tcontext.0) != 1 {
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);
    VirtualFreeEx(handle, dll_addr, 0, MEM_RELEASE);
    VirtualFreeEx(handle, code_cave, 0, MEM_RELEASE);
    return Err(io::Error::last_os_error());
  }

  PostThreadMessageA(thread_id, 0, 0, 0);
  ResumeThread(thread_handle);
  CloseHandle(thread_handle);


  let _initial_instant = time::Instant::now();
  let mut check_byte = 1u8;
  while check_byte != 0 {
    if ReadProcessMemory(
      handle,
      (code_cave as u64 + 0x06) as *mut _,
      &mut check_byte as *mut u8 as *mut _,
      1,
      core::ptr::null_mut(),
    ) != 1
    {
      return Err(io::Error::last_os_error());
    }
    if _initial_instant.elapsed().as_millis() > 10000 {
      return Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "ReadProcessMemory has timed out"
      ));
    }
    thread::sleep(time::Duration::from_millis(200));
  }
  VirtualFreeEx(handle, code_cave, 0, MEM_RELEASE);
  VirtualFreeEx(handle, dll_addr, 0, MEM_RELEASE);
  Ok(())
}

#[cfg(target_arch = "x86_64")]
#[repr(C, align(16))] // required by `CONTEXT`, is a FIXME in winapi right now
struct WinContext(CONTEXT);

#[cfg(target_arch = "x86_64")]
unsafe fn x64_threadhijack(process: &Process, cstring: CString) -> io::Result<()> {
  let dll_bytes = cstring.as_bytes_with_nul();
  let handle = process.get_handle();
  let thread_id = get_thread_id_off_process_id(process.get_id().clone())?;

  let thread_handle = OpenThread(THREAD_ALL_ACCESS, 0, thread_id);
  if thread_handle == INVALID_HANDLE_VALUE {
    return Err(io::Error::last_os_error());
  }

  if SuspendThread(thread_handle) == u32::MAX {
    CloseHandle(thread_handle);
    return Err(io::Error::last_os_error());
  }

  let mut tcontext = mem::zeroed::<WinContext>();
  tcontext.0.ContextFlags = CONTEXT_FULL;
  if GetThreadContext(thread_handle, &mut tcontext.0) != 1 {
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);
    return Err(io::Error::last_os_error());
  }
  
  let dll_addr = VirtualAllocEx(
    handle,
    core::ptr::null_mut(),
    dll_bytes.len(),
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE,
  );
  if dll_addr.is_null() {
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);
    return Err(io::Error::last_os_error());
  }

  if WriteProcessMemory(
    handle,
    dll_addr,
    dll_bytes.as_ptr() as *const _,
    dll_bytes.len(),
    core::ptr::null_mut(),
  ) == 0
  {
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);
    VirtualFreeEx(handle, dll_addr, 0, MEM_RELEASE);
    return Err(io::Error::last_os_error());
  }

  let kernel_module = CString::new("kernel32.dll").unwrap();
  let kernel_module = GetModuleHandleA(kernel_module.as_ptr());
  if kernel_module.is_null() {
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);
    VirtualFreeEx(handle, dll_addr, 0, MEM_RELEASE);
    return Err(io::Error::last_os_error());
  }

  let load_library = CString::new("LoadLibraryA").unwrap();
  let load_library = GetProcAddress(kernel_module, load_library.as_ptr());
  let mut payload = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // - 0x08			-> returned value
    0x48, 0x83, 0xEC, 0x08, // + 0x00			-> sub rsp, 0x08
    0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00, // + 0x04 (+ 0x07)	-> mov [rsp], RipLowPart
    0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00,
    0x00, // + 0x0B (+ 0x0F)	-> mov [rsp + 0x04], RipHighPart
    0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41,
    0x53, // + 0x13			-> push r(a/c/d)x / r (8 - 11)
    0x9C, // + 0x1E			-> pushfq
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // + 0x1F (+ 0x21)	-> mov rax, pRoutine
    0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // + 0x29 (+ 0x2B)	-> mov rcx, pArg
    0x48, 0x83, 0xEC, 0x20, // + 0x33			-> sub rsp, 0x20
    0xFF, 0xD0, // + 0x37			-> call rax
    0x48, 0x83, 0xC4, 0x20, // + 0x39			-> add rsp, 0x20
    0x48, 0x8D, 0x0D, 0xB4, 0xFF, 0xFF, 0xFF, // + 0x3D			-> lea rcx, [pCodecave]
    0x48, 0x89, 0x01, // + 0x44			-> mov [rcx], rax
    0x9D, // + 0x47			-> popfq
    0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59,
    0x58, // + 0x48			-> pop r(11-8) / r(d/c/a)x
    0xC6, 0x05, 0xA9, 0xFF, 0xFF, 0xFF, 0x00, // + 0x53			-> mov byte ptr[$ - 0x57], 0
    0xC3u8,
  ];
  let mut payload_pointer;
  let code_cave = VirtualAllocEx(
    handle,
    core::ptr::null_mut(),
    payload.len(),
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,
  );
  if code_cave.is_null() {
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);
    VirtualFreeEx(handle, dll_addr, 0, MEM_RELEASE);
    return Err(io::Error::last_os_error());
  }

  let high = tcontext.0.Rip & 0xffffffff;
  let low = (tcontext.0.Rip >> 0x20) & 0xffffffff;
  let dissected_high;
  let dissected_low;
  let dissected_dllpath_addr;
  let dissected_loadlib_addr;

  if cfg!(target_endian = "big") {
    dissected_high = high.to_be_bytes();
    dissected_low = low.to_be_bytes();
    dissected_dllpath_addr = (dll_addr as usize).to_be_bytes();
    dissected_loadlib_addr =
      (mem::transmute::<_, *const usize>(load_library) as usize).to_be_bytes();
  } else {
    dissected_high = high.to_le_bytes();
    dissected_low = low.to_le_bytes();

    dissected_dllpath_addr = (dll_addr as usize).to_le_bytes();
    dissected_loadlib_addr =
      (mem::transmute::<_, *const usize>(load_library) as usize).to_le_bytes();
  }
  payload_pointer = payload.as_mut_ptr().add(23); // low ret
  ptr::copy_nonoverlapping(dissected_low.as_ptr(), payload_pointer, 4);
  payload_pointer = payload.as_mut_ptr().add(15); // high ret
  ptr::copy_nonoverlapping(dissected_high.as_ptr(), payload_pointer, 4);
  payload_pointer = payload.as_mut_ptr().add(51); // arg for LoadLibraryW
  ptr::copy_nonoverlapping(dissected_dllpath_addr.as_ptr(), payload_pointer, 8);
  payload_pointer = payload.as_mut_ptr().add(41); // LoadLibraryW address
  ptr::copy_nonoverlapping(dissected_loadlib_addr.as_ptr(), payload_pointer, 8);
  // end of setting up shellcode

  tcontext.0.Rip = code_cave as u64 + 0x08;
  if WriteProcessMemory(
    handle,
    code_cave,
    payload.as_ptr() as *const _,
    payload.len(),
    core::ptr::null_mut(),
  ) == 0
  {
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);
    VirtualFreeEx(handle, dll_addr, 0, MEM_RELEASE);
    VirtualFreeEx(handle, code_cave, 0, MEM_RELEASE);
    return Err(io::Error::last_os_error());
  }

  if SetThreadContext(thread_handle, &tcontext.0) != 1 {
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);
    VirtualFreeEx(handle, dll_addr, 0, MEM_RELEASE);
    VirtualFreeEx(handle, code_cave, 0, MEM_RELEASE);
    return Err(io::Error::last_os_error());
  }

  PostThreadMessageA(thread_id, 0, 0, 0);
  ResumeThread(thread_handle);
  CloseHandle(thread_handle);

  let _initial_instant = time::Instant::now();
  let mut check_byte = 1u8;
  while check_byte != 0 {
    if ReadProcessMemory(
      handle,
      (code_cave as u64 + 0x0B) as *mut _,
      &mut check_byte as *mut u8 as *mut _,
      1,
      core::ptr::null_mut(),
    ) != 1
    {
      return Err(io::Error::last_os_error());
    }
    if _initial_instant.elapsed().as_millis() > 10000 {
      return Err(io::Error::last_os_error());
    }
    thread::sleep(time::Duration::from_millis(200));
  }
  VirtualFreeEx(handle, code_cave, 0, MEM_RELEASE);
  VirtualFreeEx(handle, dll_addr, 0, MEM_RELEASE);
  Ok(())
}

pub unsafe fn thread_hijack(process: &Process, cstring: CString) -> io::Result<()> {
  #[cfg(target_arch = "x86")]
  {
    x86_threadhijack(process, cstring)
  }
  #[cfg(target_arch = "x86_64")]
  {
    x64_threadhijack(process, cstring)
  }
  #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
  {
    let _ = process;
    let _ = cstring;
    Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "{} arch isn't supported for thread hijacking"
    ))
  }
}