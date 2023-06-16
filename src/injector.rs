use crate::lla::inject_lla;
use crate::th::thread_hijack;
use cural::Process;

use std::io;
use std::ffi;

/// Struct for injecting dlls into processes
/// 
/// # Examples
/// ```
/// use dllvoid::*;
/// 
/// let injector = Injector::new("cheat.dll", Process::find("csgo.exe").expect("no such process")).expect("injector error");
/// injector.inject_lla().expect("inject error");
/// ```
#[derive(Clone)]
pub struct Injector {
  process: Process,
  dll: ffi::CString
}

impl Injector {
  /// Initializes the struct
  /// 
  /// # Examples
  /// ```
  /// use dllvoid::*;
  /// 
  /// let injector = Injector::new("cheat.dll", Process::find("csgo.exe").expect("no such process")).expect("injector error");
  /// ```
  pub fn new(dll: &str, process: Process) -> Result<Self, ffi::NulError> {
    Ok(Self { process, dll: ffi::CString::new(dll)? })
  }

  /// Injects dll into process using LoadLibraryA
  /// 
  /// # Examples
  /// ```
  /// use dllvoid::*;
  /// 
  /// let injector = Injector::new("cheat.dll", Process::find("csgo.exe").expect("no such process")).expect("injector error");
  /// injector.inject_lla().expect("inject error");
  /// ```
  pub fn inject_lla(&self) -> io::Result<()> {
    unsafe { inject_lla(&self.process, self.dll.clone()) }
  }

  /// Injects dll into process using thread hijacking
  /// 
  /// # Examples
  /// ```
  /// use dllvoid::*;
  /// 
  /// let injector = Injector::new("cheat.dll", Process::find("csgo.exe").expect("no such process")).expect("injector error");
  /// injector.inject_th().expect("inject error");
  /// ```
  pub fn inject_th(&self) -> io::Result<()> {
    unsafe { thread_hijack(&self.process, self.dll.clone()) }
  }
}