# OreansCrack
WIP PoC for license emulation in Oreans products.

# What does this PoC do?
- Removed some restrictions of the demo version. (Demo version reminder, no option to protect ELF executables)

# What is planned for the future?
- Removing restrictions on macros and removing the demo splash screen.
- Enable additional options.

# Short manual
1. Copy `Console.exe` and `Library.dll` into product directory.
2. Run `Console.exe`.
- `Console.exe /cv` - Code Virtualizer
- `Console.exe /cv64` - Code Virtualizer x64
- `Console.exe /th` - Themida
- `Console.exe /th64` - Themida x64
- `Console.exe /wl` - WinLicense
- `Console.exe /wl64` - WinLicense x64
3. Done
