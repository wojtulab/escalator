# PrivEscAudit - Windows Privilege Escalation Audit Tool

This is a console application written in C# for .NET Framework to audit Windows Server for potential privilege escalation vectors. It runs with standard user privileges and identifies common misconfigurations.

## Features

1.  **Service Misconfigurations**: Identifies services with `AUTO_START` or `DEMAND_START` where the current user has write permissions to the binary file or the service configuration (Registry).
2.  **Writable System Folders**: Checks if the folders containing service binaries are writable by the current user.
3.  **AlwaysInstallElevated**: Checks if the `AlwaysInstallElevated` policy is enabled in the Registry.
4.  **Exploit/Fix Suggestions**: Generates ready-to-use commands for exploitation or remediation.

## Compilation

You can compile this tool using Visual Studio or the command-line compiler (`csc.exe`).

### Using Visual Studio
1.  Open `PrivEscAudit.sln` in Visual Studio (2017, 2019, 2022, etc.).
2.  Select `Release` configuration.
3.  Build the solution (`Ctrl+Shift+B`).
4.  The executable will be in `PrivEscAudit\bin\Release\PrivEscAudit.exe`.

### Using Command Line (csc.exe)
If you just have the `.cs` file or want to compile manually without the solution:

```cmd
csc.exe /out:PrivEscAudit.exe PrivEscAudit\Program.cs /reference:System.ServiceProcess.dll
```

## Usage

Run the compiled executable from a command prompt:

```cmd
PrivEscAudit.exe
```

The tool will display any found vulnerabilities and suggest commands to exploit them (for testing purposes) or fix them.

## Disclaimer

This tool is for educational and authorized security audit purposes only. Use responsibly.
