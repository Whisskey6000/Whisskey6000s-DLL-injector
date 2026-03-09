# WHISSKY — DLL Injector v1.0

A lightweight and efficient DLL injector built with Python. This is my first "serious" project where I focused on combining low-level Windows API interactions with a modern Terminal User Interface (TUI). 

I built this tool for my own learning purposes to better understand process memory and systems programming. If you find it useful or interesting, feel free to check it out!

---

## Key Features

* **Modern TUI:** Instead of a classic CLI, I used the `Textual` framework to create a responsive and user-friendly terminal interface.
* **Process Management:** Live process list with filtering by name or PID, powered by `psutil`.
* **Safety Checks:** The app automatically checks for Admin privileges and validates the DLL (PE header/MZ bytes) before attempting injection.
* **Clean Architecture:** Logic is separated into UI and Core modules, making the codebase easy to read and maintain.
* **Real-time Logging:** Built-in log console to track the injection status and troubleshoot errors.

## How It Works

The injection core uses the classic **CreateRemoteThread** method via `ctypes`:
1. Opens the target process with `PROCESS_ALL_ACCESS`.
2. Allocates memory using `VirtualAllocEx`.
3. Writes the DLL path into the target process memory via `WriteProcessMemory`.
4. Executes `LoadLibraryA` from `kernel32.dll` in the remote thread to load the library.

## Getting Started

### Prerequisites
* Windows OS
* Python 3.10+
* Administrator privileges
