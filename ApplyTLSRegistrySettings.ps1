[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [switch]
    $RestoreBackup
)

If (-not (Test-Path ./reports -ea SilentlyContinue)) { New-Item ./reports -ItemType Directory -Force }
$dateTime = Get-Date -f "MM-dd-yyy_HH-mm-ss"

if ($RestoreBackup) {

    $files = Get-ChildItem "C:\scripts\TLS\backup" | ? { $_.Extension -like '.reg' }

    if ($files) {
        Invoke-Command { reg delete "hkey_local_machine\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /f }
        Invoke-Command { reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" /f }
        Invoke-Command { reg delete "hkey_local_machine\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /f }
        Invoke-Command { reg delete "hkey_local_machine\SYSTEM\CityNationalBank\TLSControls" /f }

        $testSMSPath = Test-Path 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData' -ErrorAction SilentlyContinue
        $testRebootByKey = Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData' -name 'RebootBy' -ErrorAction SilentlyContinue
        if ($testSMSPath -and (-not($testRebootByKey))) {    
            $regFile = 'Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData]

"RebootBy"=hex(b):00,00,00,00,00,00,00,00
"RebootValueInUTC"=dword:00000001
"NotifyUI"=dword:00000001
"HardReboot"=dword:00000000
"OverrideRebootWindowTime"=hex(b):00,00,00,00,00,00,00,00
"OverrideRebootWindow"=dword:00000000
"PreferredRebootWindowTypes"=hex(7):34,00,00,00,00,00
"GraceSeconds"=dword:00000000'

            $regfile | Out-file sccmReboot.reg
            Invoke-Command { reg import .\sccmReboot.reg }
        }

        $files | % {
            $fileName = $_.FullName
            Invoke-Command { reg import $fileName }
        } 
    }
    else {
        Write-Host "No registry backup files found. Unable to restore settings." -ForegroundColor Red   
    }
}
elseif ((Get-ItemProperty -Path 'HKLM:\System\CityNationalBank\TLSControls' -ErrorAction SilentlyContinue).TLSControlsApplied -ne 1) {

    Start-Transcript -Path ./reports/tls_transcript_$dateTime.txt
    
    # Backup existing settings
    $regBackupPath = "C:\scripts\TLS\backup"
    if (-not (Test-Path $regBackupPath -ea SilentlyContinue)) { New-Item -Path $regBackupPath -Force -ItemType Directory }

    Invoke-Command { reg export "hkey_local_machine\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" "C:\scripts\TLS\backup\dotNet4_x64_pre_tls12_backup.reg" /y }
    Invoke-Command { reg export "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" "C:\scripts\TLS\backup\dotNet4_x86_pre_tls12_backup.reg" /y }
    Invoke-Command { reg export "hkey_local_machine\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" "C:\scripts\TLS\backup\schannel_pre_tls12_backup.reg" /y }

    #region Set Ciphers
    $cipherPath = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'
    $testCipherPath = Test-Path "HKLM:\$cipherPath" -ErrorAction SilentlyContinue
    if (-not $testCipherPath) { New-Item "HKLM:\$cipherPath" -Force }
    $ciphers = "AES 128/128", "AES 256/256", "DES 56/56", "NULL", "RC2 128/128", "RC2 40/128", "RC2 56/128", "RC4 128/128", "RC4 40/128", "RC4 56/128", "RC4 64/128", "Triple DES 168"
    $ciphers | % { 
        $testCipherPathExist = Test-Path "HKLM:\$cipherPath\$_" -ErrorAction SilentlyContinue
        $testCipherSettingExist = Get-ItemProperty -Path "HKLM:\$cipherPath\$_" -Name 'Enabled' -ErrorAction SilentlyContinue

        if (-not $testCipherPathExist) {
            $cipherKey = (Get-Item HKLM:\).OpenSubKey($cipherPath, $true)
            $cipherKey.CreateSubKey($_)
            $cipherKey.Close()
        }

        if (-not $testCipherSettingExist) {
            if (($_ -eq 'AES 128/128') -or ($_ -eq 'AES 256/256')) {
                New-ItemProperty -Path "HKLM:\$cipherPath\$_" -Name "Enabled" -Value 0xffffffff -PropertyType DWord -Force
            }
            else {
                New-ItemProperty -Path "HKLM:\$cipherPath\$_" -Name "Enabled" -Value 0 -PropertyType DWord -Force
            }
        }
        elseif ($testCipherSettingExist) {
            if (($_ -eq 'AES 128/128') -or ($_ -eq 'AES 256/256')) {
                Set-ItemProperty -Path "HKLM:\$cipherPath\$_" -Name "Enabled" -Value 0xffffffff -Force
            }
            else {
                Set-ItemProperty -Path "HKLM:\$cipherPath\$_" -Name "Enabled" -Value 0 -Force
            }
        }
    }
    #endregion

    #region Configure .NET 4 to use strong Crypto
    $netX64Path = "SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
    $testNETx64Path = Test-Path "HKLM:\$netX64Path" -ErrorAction SilentlyContinue
    $testNETx64Crypto = Get-ItemProperty -Path "HKLM:\$netX64Path" -Name 'SchUseStrongCrypto' -ErrorAction SilentlyContinue

    $netX86Path = "SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
    $testNetx86Path = Test-Path "HKLM:\$netX86Path" -ErrorAction SilentlyContinue
    $testNETx86Crypto = Get-ItemProperty -Path "HKLM:\$netX86Path" -Name 'SchUseStrongCrypto' -ErrorAction SilentlyContinue

    if ($testNETx64Path) {
        if (-not $testNETx64Crypto) { New-ItemProperty -Path "HKLM:\$netX64Path" -Name 'SchUseStrongCrypto' -Value 1 -PropertyType DWord -Force }
        else { Set-ItemProperty -Path "HKLM:\$netX64Path" -Name 'SchUseStrongCrypto' -Value 1 -Force }
    }

    if ($testNETx86Path) {
        if (-not $testNETx86Crypto) { New-ItemProperty -Path "HKLM:\$netX86Path" -Name 'SchUseStrongCrypto' -Value 1 -PropertyType DWord -Force }
        else { Set-ItemProperty -Path "HKLM:\$netX86Path" -Name 'SchUseStrongCrypto' -Value 1 -Force }
    }
    #endregion

    #region Configure allowed Hashes
    $hashPath = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes"
    $testHashPath = Test-Path "HKLM:\$hashPath" -ErrorAction SilentlyContinue
    if (-not $testHashPath) { New-Item "HKLM:\$hashPath" -Force }
    $hashes = "MD5", "SHA", "SHA256", "SHA384", "SHA512"

    $hashes | % {
        $testHashPathExist = Test-Path "HKLM:\$hashPath\$_" -ErrorAction SilentlyContinue
        $testHashSettingExist = Get-ItemProperty "HKLM:\$hashPath\$_" -Name "Enabled" -ErrorAction SilentlyContinue

        if (-not $testHashPathExist) {
            $hashKey = (Get-Item HKLM:\).OpenSubKey($hashPath, $true)
            $hashKey.CreateSubKey($_)
            $hashKey.Close()
        }

        if (-not $testHashSettingExist) { New-ItemProperty -Path "HKLM:\$hashPath\$_" -Name 'Enabled' -Value 0xffffffff -PropertyType DWord -Force }
        else { Set-ItemProperty -Path "HKLM:\$hashPath\$_" -Name 'Enabled' -Value 0xffffffff -Force }
    }
    #endregion

    #region Configure Key Exchange Algorithms
    $keyPath = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms"
    $testKeyPath = Test-Path "HKLM:\$keyPath" -ErrorAction SilentlyContinue
    if (-not $testKeyPath) { New-Item "HKLM:\$keyPath" -Force }
    $keyAlgorithms = "Diffie-Hellman", "ECDH", "PKCS"

    $keyAlgorithms | % {
        $testKeyPathExist = Test-Path "HKLM:\$keyPath\$_" -ErrorAction SilentlyContinue
        $testKeySettingExist = Get-ItemProperty "HKLM:\$keyPath\$_" -Name "Enabled" -ErrorAction SilentlyContinue

        if (-not $testKeyPathExist) {
            $algorithmKey = (Get-Item HKLM:\).OpenSubKey($keyPath, $true)
            $algorithmKey.CreateSubKey($_)
            $algorithmKey.Close()
        }

        if (-not $testKeySettingExist) {
            New-ItemProperty -Path "HKLM:\$keyPath\$_" -Name 'Enabled' -Value 0xffffffff -PropertyType DWord -Force
            if ($_ -eq "Diffie-Hellman") { New-ItemProperty -Path "HKLM:\$keyPath\$_" -Name "ServerMinKeyBitLength" -Value 0x0000800 -PropertyType DWord -Force }
        }
        else {
            Set-ItemProperty -Path "HKLM:\$keyPath\$_" -Name 'Enabled' -Value 0xffffffff -Force
            if ($_ -eq "Diffie-Hellman") { 
                $testServerMinKeyBitLength = Get-ItemProperty "HKLM:\$keyPath\$_" -Name "ServerMinKeyBitLength" -ErrorAction SilentlyContinue
                if (-not $testServerMinKeyBitLength) {
                    New-ItemProperty -Path "HKLM:\$keyPath\$_" -Name "ServerMinKeyBitLength" -Value 0x00000800 -PropertyType DWord -Force
                }
                else {
                    Set-ItemProperty -Path "HKLM:\$keyPath\$_" -Name "ServerMinKeyBitLength" -Value 0x00000800 -Force
                }
            }
        }
    }
    #endregion

    #region Configure Protocols
    $protoPath = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    $testProtoPath = Test-Path "HKLM:\$protoPath" -ErrorAction SilentlyContinue
    if (-not $testProtoPath) { New-Item "HKLM:\$protoPath" -Force }
    $protocols = "Multi-Protocol Unified Hello", "PCT 1.0", "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2"

    $protocols | % {
        # Create the protocol, server and client keys
        $testProtoKey = Test-Path "HKLM:\$protoPath\$_" -ErrorAction SilentlyContinue
        $testClientPath = Test-Path "HKLM:\$protoPath\$_\Client" -ErrorAction SilentlyContinue
        $testServerPath = Test-Path "HKLM:\$protoPath\$_\Server" -ErrorAction SilentlyContinue
        if (-not $testProtoKey) {
            # Create protocol key
            $protoKey = (Get-Item HKLM:\).OpenSubKey($protoPath, $true)
            $protoKey.CreateSubKey($_)
            $protoKey.Close()
            # Create client and server sub-keys
            $clientProtoKey = (Get-Item HKLM:\).OpenSubKey("$protoPath\$_", $true)
            $clientProtoKey.CreateSubKey("Client")
            $clientProtoKey.CreateSubKey("Server")
            $clientProtoKey.Close()
        }
        if (-not $testClientPath) {
            $clientProtoKey = (Get-Item HKLM:\).OpenSubKey("$protoPath\$_", $true)
            $clientProtoKey.CreateSubKey("Client")
            $clientProtoKey.Close()
        }
        if (-not $testServerPath) {
            $clientProtoKey = (Get-Item HKLM:\).OpenSubKey("$protoPath\$_", $true)
            $clientProtoKey.CreateSubKey("Server")
            $clientProtoKey.Close()
        }

        # Configure the client protocol settings
        $testProtoClientEnabled = Get-ItemProperty "HKLM:\$protoPath\$_\Client" -Name 'Enabled' -ErrorAction SilentlyContinue
        $testProtoClientDisabledByDefault = Get-ItemProperty "HKLM:\$protoPath\$_\Client" -Name 'DisabledByDefault' -ErrorAction SilentlyContinue

        if ($_ -ne "TLS 1.2") {
            # Set Enabled to false if lower than TLS 1.2.
            if (-not $testProtoClientEnabled) {
                New-ItemProperty -Path "HKLM:\$protoPath\$_\Client" -Name 'Enabled' -Value 0 -PropertyType DWord -Force
            }
            else {
                Set-ItemProperty -Path "HKLM:\$protoPath\$_\Client" -Name 'Enabled' -Value 0 -Force
            }
            # Set DisabledByDefault to true if lower than TLS 1.2
            if (-not $testProtoClientDisabledByDefault) {
                New-ItemProperty -Path "HKLM:\$protoPath\$_\Client" -Name 'DisabledByDefault' -Value 1 -PropertyType DWord -Force
            }
            else {
                Set-ItemProperty -Path "HKLM:\$protoPath\$_\Client" -Name 'DisabledByDefault' -Value 1 -Force
            }
        }
        elseif ($_ -eq "TLS 1.2") {
            # Set Enabled to true for TLS 1.2
            if (-not $testProtoClientEnabled) {
                New-ItemProperty -Path "HKLM:\$protoPath\$_\Client" -Name 'Enabled' -Value 0xffffffff -PropertyType DWord -Force
            }
            else {
                Set-ItemProperty -Path "HKLM:\$protoPath\$_\Client" -Name 'Enabled' -Value 0xffffffff -Force
            }
            # Set DisabledByDefault to false for TLS 1.2
            if (-not $testProtoClientDisabledByDefault) {
                New-ItemProperty -Path "HKLM:\$protoPath\$_\Client" -Name 'DisabledByDefault' -Value 0 -PropertyType DWord -Force
            }
            else {
                Set-ItemProperty -Path "HKLM:\$protoPath\$_\Client" -Name 'DisabledByDefault' -Value 0 -Force
            }
        }

        # Configure the server protocol settings
        $testProtoServerEnabled = Get-ItemProperty "HKLM:\$protoPath\$_\Server" -Name 'Enabled' -ErrorAction SilentlyContinue
        $testProtoSrvDisabledByDefault = Get-ItemProperty "HKLM:\$protoPath\$_\Server" -Name 'DisabledByDefault' -ErrorAction SilentlyContinue

        if ($_ -ne "TLS 1.2") {
            # Set Enabled to false if lower than TLS 1.2.
            if (-not $testProtoServerEnabled) {
                New-ItemProperty -Path "HKLM:\$protoPath\$_\Server" -Name 'Enabled' -Value 0 -PropertyType DWord -Force
            }
            else {
                Set-ItemProperty -Path "HKLM:\$protoPath\$_\Server" -Name 'Enabled' -Value 0 -Force
            }
            # Set DisabledByDefault to true if lower than TLS 1.2
            if (-not $testProtoSrvDisabledByDefault) {
                New-ItemProperty -Path "HKLM:\$protoPath\$_\Server" -Name 'DisabledByDefault' -Value 1 -PropertyType DWord -Force
            }
            else {
                Set-ItemProperty -Path "HKLM:\$protoPath\$_\Server" -Name 'DisabledByDefault' -Value 1 -Force
            }
        }
        elseif ($_ -eq "TLS 1.2") {
            # Set Enabled to true for TLS 1.2
            if (-not $testProtoServerEnabled) {
                New-ItemProperty -Path "HKLM:\$protoPath\$_\Server" -Name 'Enabled' -Value 0xffffffff -PropertyType DWord -Force
            }
            else {
                Set-ItemProperty -Path "HKLM:\$protoPath\$_\Server" -Name 'Enabled' -Value 0xffffffff -Force
            }
            # Set DisabledByDefault to false for TLS 1.2
            if (-not $testProtoSrvDisabledByDefault) {
                New-ItemProperty -Path "HKLM:\$protoPath\$_\Server" -Name 'DisabledByDefault' -Value 0 -PropertyType DWord -Force
            }
            else {
                Set-ItemProperty -Path "HKLM:\$protoPath\$_\Server" -Name 'DisabledByDefault' -Value 0 -Force
            }
        }
    }
    #endregion
    
    #region Update SCCM client if installed
    #if (Get-Service CCMEXEC) {
    $testSMSPath = Test-Path 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData' -ErrorAction SilentlyContinue
    $testRebootByKey = Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData' -name 'RebootBy' -ErrorAction SilentlyContinue
    if ($testSMSPath -and (-not($testRebootByKey))) {    
        $regFile = 'echo Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData]

"RebootBy"=hex(b):00,00,00,00,00,00,00,00
"RebootValueInUTC"=dword:00000001
"NotifyUI"=dword:00000001
"HardReboot"=dword:00000000
"OverrideRebootWindowTime"=hex(b):00,00,00,00,00,00,00,00
"OverrideRebootWindow"=dword:00000000
"PreferredRebootWindowTypes"=hex(7):34,00,00,00,00,00
"GraceSeconds"=dword:00000000'

        $regfile | Out-file sccmReboot.reg
        Invoke-Command { reg import .\sccmReboot.reg }
    }

    #Restart-Service CCMEXEC -Force
    #}
    #endregion

    #region Create custom registry entry in HKLM:\SYSTEM\CityNationalBank\TLSControls

    if (-not(Get-ItemProperty -Path 'HKLM:\System\CityNationalBank\TLSControls' -Name 'TLSControlsApplied' -ErrorAction SilentlyContinue)) {
        try { New-Item 'HKLM:\System\CityNationalBank' } catch { $_ }
        try { New-Item 'HKLM:\System\CityNationalBank\TLSControls' } catch { $_ }
        try { New-ItemProperty -Path 'HKLM:\System\CityNationalBank\TLSControls' -Name 'TLSControlsApplied' -Value 1 -PropertyType DWord -Force } catch { $_ }
    }

    #endregion
    Stop-Transcript
}