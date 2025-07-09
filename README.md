A terminal application that lists the name, PID, and optional RAM usage of all running processes.

- It can obtain a PID from the user and send a "kill" command.
- Written in C using the native API on Windows.
- API: https://learn.microsoft.com/en-us/windows/win32/api/

Features

- List all running processes
- Filter by specific name
- Kill processes by PID
- Save process list to .txt file
- Live view mode:
- Display CPU and RAM usage
- Detect and highlight PID and RAM changes
- Sort by RAM usage