# windows-debloat

This is my attempt to make a usable windows 10.

To run this enter a powershell with administrator privileges and run
```
powershell -ExecutionPolicy Bypass -File debloat.ps1
```

Disable task for updating windows regulary.
```
Get-ScheduledTask -TaskPath '\Microsoft\Windows\WindowsUpdate\' | Disable-ScheduledTask
```