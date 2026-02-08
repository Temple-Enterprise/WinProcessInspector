<h1 align="center">Runtime Inspector</h1>

<p align="center">
  <img src="https://img.shields.io/github/stars/PhilipPanda/RuntimeInspector?style=for-the-badge&label=Stars&color=0A1A2F&labelColor=0F172A">
  <img src="https://img.shields.io/github/downloads/PhilipPanda/RuntimeInspector/total?style=for-the-badge&label=Downloads&color=0A1A2F&labelColor=0F172A">
  <img src="https://img.shields.io/github/license/PhilipPanda/RuntimeInspector?style=for-the-badge&label=License&color=0A1A2F&labelColor=0F172A">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows-0A1A2F?style=for-the-badge&labelColor=0F172A">
  <img src="https://img.shields.io/badge/Language-C%2B%2B-0A1A2F?style=for-the-badge&labelColor=0F172A">
</p>

---

### Runtime Inspector is a Windows runtime analysis and instrumentation tool for inspecting, monitoring, and interacting with live processes.

---

## How to Build and Launch Runtime Inspector

### 1. Build the Executable
- Open the project in **Visual Studio**.
- Set the build configuration to **Release x64**.
- Build the solution (`Build` → `Build Solution`).
- Locate the compiled executable in the `\Release\x64\` directory.

### 2. Run Runtime Inspector
- Double-click `RuntimeInspector.exe` to launch it.
- The application will enumerate running processes automatically.

### 3. Use the Tool
- Select a process from the list to inspect its runtime state.
- Access modules, threads, memory, and instrumentation features through the UI.
