# TLS_PowerShell_Standalone
 PowerShell script to apply TLS 1.2 settings for Windows servers

 # Usage

 To apply TLS settings to the local computer, run the following command and then reboot the server:

    PS> .\ApplyTLSRegistrySettings.bat

The script will automatically create backups (.reg files) of existing settings prior to applying the changes. The backup .reg files will be stored in the C:\scripts\TLS\backup directory. These files MUST remain at this location for the revert function to operate properly.

To revert the changes, run the following command and the reboot the server:

    PS> .\ApplyTLSRegistrySettings.ps1 -RestoreBackup

# Notes

This script has been tested on the following operating systems:

    - Windows Server 2008 SP2
    - Windows Server 2008 R2
    - Windows Server 2012
    - Windows Server 2012R2
    - Windows Server 2016
    - Windows Server 2019
    - Windows Server 2022

The script has also been verified to run on the following versions of PowerShell:

    - PowerShell 2.0
    - PowerShell 3.0
    - PowerShell 4.0
    - PowerShell 5.1

Note that PowerShell 7 is untested at this time.
