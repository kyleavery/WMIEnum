# WMIEnum

WMIEnum is a C# tool for enumerating Windows hosts with WMI. The default protocol for accessing remote hosts is WinRM, but DCOM can be used as well.

This project is based on a PowerShell tool called [WMIOps](https://github.com/FortyNorthSecurity/WMIOps) with a focus on enumeration and opsec safety. Thanks to my colleague, [Dean Valentine](https://github.com/hugbubby), for introducing me to many programming best practices and revising this project.

## Example Usage
```
WMIEnum.exe procs
WMIEnum.exe av /target:HOST /domain:DOMAIN /user:USERNAME /pass:PASSWORD /ssl:FALSE
WMIEnum.exe find /file:NAME.TXT /target:HOST /domain:DOMAIN /user:USERNAME /pass:PASSWORD
```

## Commands

```
basicinfo - Hostname and domain.
procs - Running processes.
services - All services, state, start mode, and service path.
drives - Local and remote system drives.
nics - Active NICs, IP address, and gateway.
av - AV products that write to root\SecurityCenter2, whether they are enabled, and if they are updated.
dir - Directory contents.
cat - File contents.
find - Location of file on disk.
```

## Arguments
```
/target - IP address or hostname of the machine you would like to query. Leave blank for local enum.
/user - Username for target machine. Leave blank for local enum.
/pass - Password for target machine. Leave blank for local enum.
/domain - Domain of target machine. Leave blank for local enum.
/dir - Directory for dir command.
/file - Filename for cat and file commands.
/proto - Protocol to use (WinRM or DCOM). Default is WinRM.
/ssl - Encrypt the traffic (true or false). Only applicable if using WinRM. Default is true.
```
