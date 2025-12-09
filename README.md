# PrivEscAudit - Windows Privilege Escalation Audit Tool

This is a console application written in C# for .NET Framework to audit Windows Server for potential privilege escalation vectors. It runs with standard user privileges and identifies common misconfigurations.

## Features

1.  **Service Misconfigurations**: Identifies services with `AUTO_START` or `DEMAND_START` where the current user has write permissions to the binary file or the service configuration (Registry).
2.  **Writable System Folders**: Checks if the folders containing service binaries are writable by the current user.
3.  **AlwaysInstallElevated**: Checks if the `AlwaysInstallElevated` policy is enabled in the Registry.
4.  **Exploit/Fix Suggestions**: Generates ready-to-use commands for exploitation or remediation.

## Compilation

To compile this tool, you need the .NET Framework SDK (part of Visual Studio or available separately). You can use the C# compiler (`csc.exe`) typically found in `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\` (or similar version).

```cmd
csc.exe /out:PrivEscAudit.exe PrivEscAudit.cs /reference:System.ServiceProcess.dll
```

## Usage

Run the compiled executable from a command prompt:

```cmd
PrivEscAudit.exe
```

The tool will display any found vulnerabilities and suggest commands to exploit them (for testing purposes) or fix them.

## Disclaimer

This tool is for educational and authorized security audit purposes only. Use responsibly.
