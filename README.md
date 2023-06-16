# DllVoid v0.1.0 | Dll injector library
## Changelog
- Added `inject_lla` which uses LoadLibraryA for injection
- Added `inject_th` which uses thread hijacking for injection
## Usage
```rust
use dllvoid::*;

let injector = Injector::new("cheat.dll", Process::find("csgo.exe").expect("no such process")).expect("injector error");
injector.inject_th().expect("inject error");
```
## Platforms
- Windows
## Links
- `github` - https://github.com/CURVoid/DllVoid
- `docs` - https://docs.rs/dllvoid