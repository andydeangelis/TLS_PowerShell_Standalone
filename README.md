# TLS_PowerShell_Standalone
 PowerShell script to apply TLS 1.2 settings for Windows servers

 # Usage - Batch scripts

 For ease of use, download the entire repository, right click the applyTLSSettings.bat batch file, and select 'Run as administrator.' This will create the c:\scripts\TLS directory structure for you, copy all relevant files to that directory and apply the changes. When the script completes, reboot the server for the changes to take affect.

 To revert TLS settings using the included batch files (recommended), navigate to C:\scripts\TLS, right click the revertTLSSettings.bat batch file and select 'Run as administrator.' This will restore the backups that were created when initially running the scripts.

# Usage - Standalone PS1 script file

 To apply TLS settings to the local computer, run the following command and then reboot the server:

    PS> .\ApplyTLSRegistrySettings.ps1

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

# Note for SCCM Clients

Note that if the script detects the SCCM/MECM client installed, it will also update the 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData' key with various settings. These values flag the server as needing a reboot in the SCCM console, but it will not cause an automatic reboot.

For SCCM deployments, this script has been tested as both a stand-alone script (via SCCM Run Scripts function) as well as tested via a Package/Task Sequence deployment.