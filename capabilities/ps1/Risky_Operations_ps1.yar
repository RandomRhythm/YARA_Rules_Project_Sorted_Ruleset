

rule risky_operations_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect risky operations"
    reference1  = "https://www.microsoft.com/security/blog/2021/03/25/analyzing-attacks-taking-advantage-of-the-exchange-server-vulnerabilities/"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="iex"
    $s2="IEX"
    $s3="I`E`X"
    $s3_1="IE`x"
    $s3_2="I`ex"
    $s4="invoke-expression" nocase
    $s5="[System.Runtime.InteropServices.Marshal]::Copy"
    $s6="GetDelegateForFunctionPointer"
    $s8=".LoadLibrary"
    $s9="VirtualAlloc"
    $s10="VirtualAddress"
    $s11="[IntPtr]"
    $s12="PtrToStructure"
    $s13="PtrToStringAnsi"
    $s14="GetProcAddress"
    $s15="System.Runtime.InteropServices.HandleRef"
    $s16="Microsoft.Win32.UnsafeNativeMethods"
    $s17="InMemoryModule"
    $s18="CreateThread"
    $s19="invoke-callbackiex" nocase
	condition:
		any of them
}


rule suspicious_InvokeExpression_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/10"
    description = "Detect risky operations"
    reference1  = "https://www.microsoft.com/security/blog/2021/03/25/analyzing-attacks-taking-advantage-of-the-exchange-server-vulnerabilities/"
    filetype    = "ps1"
	strings:
    $s1="iex"
    $s2="IEX"
    $s3="Invoke-Expression"
    $d1 = "iex" nocase
    $d2="i`e`x" nocase
    $d3="ie`x" nocase
    $d4="i`ex" nocase
    $d5=/(i|I)(`|)(n|N)(`|)(v|V)(`|)(o|O)(`|)(k|K)(`|)(e|E)(`|)-(`|)(e|E)(`|)(x|X)(`|)(p|P)(`|)(r|R)(`|)(`|)(e|E)(`|)(s|S)(`|)(s|S)(`|)(i|I)(`|)(o|O)(`|)(n|N)/

	condition:
		0 of ($s*) and any of ($d*)
}


rule suspicious_operations_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect risky operations"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s7=".Invoke"
	condition:
		any of them
}

rule invoke_badness_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect risky operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="invoke-adsbackdoor" nocase
    $s2="invoke-allchecks" nocase
    $s3="invoke-createcertificate" nocase
    $s4="invoke-decode" nocase
    $s5="invoke-dllencode" nocase
    $s6="invoke-dllinjection" nocase
    $s7="invoke-encode" nocase
    $s8="invoke-finddllhijack" nocase
    $s9="invoke-findpathhijack" nocase
    $s10="invoke-masscommand" nocase
    $s11="invoke-masssearch" nocase
    $s12="invoke-masstemplate" nocase
    $s13="invoke-masstokens" nocase
    $s14="invoke-networkrelay" nocase
    $s15="invoke-ninjacopy" nocase
    $s16="invoke-poshrathttp" nocase
    $s17="invoke-poshrathttps" nocase
    $s18="invoke-powershellicmp" nocase
    $s19="invoke-powershelltcp" nocase
    $s20="invoke-powershelludp" nocase
    $s21="invoke-psgcat" nocase
    $s22="invoke-psgcatagent" nocase
    $s23="invoke-psinject" nocase
    $s24="invoke-shellcode" nocase
    $s25="invoke--shellcode" nocase
    $s26="invoke-shellcodemsil" nocase
	condition:
		any of them
}

rule private_key_export_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect risky operations"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s1="Export-PfxCertificate"
	condition:
		any of them
}

rule dll_hijack_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect risky operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="Find-ProcessDLLHijack"
	condition:
		any of them
}

rule backdoor_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect risky operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="add-scrnsavebackdoor" nocase
    $s2="gupt-backdoor" nocase
    $s3="http-backdoor" nocase
	condition:
		any of them
}

rule process_injection_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect risky operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="dllinjection" nocase
    $s2="reflectivepeinjection" nocase
	condition:
		any of them
}


rule keystroke_logging_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect risky operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="get-keystrokes" nocase
	condition:
		any of them
}

rule execution_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect risky operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="execute-command-mssql" nocase
    $s2="execute-dnstxt-code" nocase
    $s3="execute-ontime" nocase
    $s4="download-execute-ps" nocase
    $s5="Invoke-ShellCommand"
	condition:
		any of them
}

rule volume_shadow_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect risky operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="VolumeShadowCopyTools"
    $s2="copy-vss" nocase
    $s3="new-volumeshadowcopy" nocase
	condition:
		any of them
}

rule antivirus_modification_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect risky operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="Set-MpPreference -DisableRealtimeMonitoring"
    $s2="DisableRealtimeMonitoring"
    $s3="Set-MpPreference"
	condition:
		any of them
}

rule privilege_escalation_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect risky operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="Get-System"
    $s2="privesc" nocase
    $s3="Set-MpPreference"
    $s4="enable-duplicatetoken" nocase
    $s5="exploittable" nocase
    $s6="write-useraddmsi" nocase
    $s7="remove-update" nocase
	condition:
		any of them
}

rule payload_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect risky operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="payload" nocase
	condition:
		any of them
}

rule credential_dump_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect risky operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="extract-wifi-creds" nocase
    $s2="get-lsasecret" nocase
    $s3="get-passhashes" nocase
    $s4="get-vaultcredential" nocase
    $s5="invoke-massmimikatz" nocase
    $s6="invoke-mimikatzwdigestdowngrade" nocase
    $s7="mimikatz" nocase
    $s8="Get-GPPAutologon"
	condition:
		any of them
}

rule remote_execution_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect risky operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="run-exeonremote" nocase

	condition:
		any of them
}

rule MBR_Access_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect risky operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="set-masterbootrecord" nocase

	condition:
		any of them
}

rule credential_attack_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect risky operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    reference3  = "https://gist.github.com/gfoss/2b39d680badd2cad9d82"
    filetype    = "ps1"
	strings:
    $s1="invoke-credentialinjection" nocase
    $s2="invoke-credentialsphish" nocase
    $s3="get-passhashes" nocase
    $s4="get-vaultcredential" nocase
    $s5="invoke-tokenmanipulation" nocase
    $s6="invoke-bruteforce" nocase
    $s7="create-multiplesessions" nocase
    $s8="mimikatz" nocase
    $s9="Invoke-Kerberoast"
	condition:
		any of them
}

rule attack_toolsets_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/18"
    description = "Detect risky operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "https://gist.github.com/gfoss/2b39d680badd2cad9d82"
	strings:
    $s1="powerview" nocase
    $s2="powerup" nocase
    $s3="powercat" nocase
    $s4="remove-poshrat" nocase
    $s5="invoke-tokenmanipulation" nocase
    $s6="invoke-bruteforce" nocase
    $s7="sherlock" nocase
    $s8="Find-AVSignature" //PowerSploit
    $s9="get-gpppassword" nocase //PowerSploit
    $s10="get-timedscreenshot" //PowerSploit
    $s12="out-minidump" //PowerSploit
    $s13="new-elevatedpersistenceoption" //PowerSploit
    $s14="get-serviceunquoted" nocase
    $s15="get-serviceexeperms" nocase //PowerUp
    $s16="get-serviceperms" //PowerUp
    $s17="invoke-serviceuseradd" nocase //PowerUp
    $s18="invoke-servicecmd" nocase //PowerTools
    $s19="write-useraddservicebinary" nocase
    $s20="write-cmdservicebinary" nocase //PowerSploit
    $s21="write-serviceexe" nocase //PowerSploit
    $s22="write-serviceexecmd" nocase
    $s23="restore-serviceexe" nocase
    $s24="invoke-servicestart" nocase
    $s25="invoke-serviceenable" nocase
    $s26="invoke-servicedisable" nocase
    $s27="get-regalwaysinstallelevated" nocase
    $s28="get-regautologon" nocase //PowerSploit
    $s29="get-unattendedinstallfiles" nocase //PowerSploit
    $s30="get-webconfig" nocase //PowerSploit
    $s31="get-applicationhost" nocase //PowerSploit
    $s32="dns_txt_pwnage" nocase
    $s33="out-word" nocase
    $s34="out-excel" nocase
    $s35="out-java" nocase
    $s36="out-shortcut" nocase
    $s37="out-chm" nocase
    $s38="out-hta" nocase
    $s39="enable-duplicatetoken" nocase
    $s40="download_execute" nocase
    $s41="get-information" nocase
    $s42="check-vm" nocase
    $s43="port-scan" nocase
    $s44="invoke-powershellwmi" nocase
    $s45="texttoexe" nocase
    $s46="base64tostring" nocase
    $s47="stringtobase64" nocase
    $s48="parse_keys" nocase
    $s49="add-persistence" nocase
    $s50="remove-persistence" nocase
    $s51="find-psserviceaccounts" nocase
    $s52="get-psadforestkrbtgtinfo" nocase
    $s53="discover-psmssqlservers" nocase
    $s54="discover-psmsexchangeservers" nocase
    $s55="get-psadforestinfo" nocase
    $s56="get-kerberospolicy" nocase
    $s57="discover-psinterestingservices" nocase
	condition:
		any of them
}

rule exfiltration_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect risky operations"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s1="add-exfiltration" nocase
    $s2="do-exfiltration" nocase
	condition:
		any of them
}


rule memory_operations_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect risky operations"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s1="IMAGE_SCN_MEM_EXECUTE"
    $s2="IMAGE_SCN_MEM_READ"
    $s3="IMAGE_SCN_MEM_WRITE"
    $s4="IMAGE_SCN_MEM_NOT_CACHED"
    $s5="PAGE_EXECUTE_READWRITE"
    $s6="PAGE_EXECUTE_READ"
    $s7="PAGE_EXECUTE_WRITECOPY"
    $s8="PAGE_EXECUTE"
    $s9="PAGE_READWRITE"
    $s10="PAGE_READONLY"
    $s11="PAGE_NOACCESS"
    $s12="PAGE_NOCACHE"
    $s13="VirtualProtect"
    $s14="memcpy"
    $s15="Copy-ArrayOfMemAddresses"
    $s16="System.IO.MemoryStream"
    $s17="MemoryAddress"
    $s18="Write-BytesToMemory"
    $s19="GetProcAddress"
    $s20="AllocHGlobal"
    $s21="StructureToPtr"
    $s22="MEM_COMMIT"
    $s23="MEM_RESERVE"
    $s24="WriteProcessMemory"
    $s25="[System.Runtime.InteropServices.Marshal]::Copy"
    $s26="Add-SignedIntAsUnsigned"
    $s27="Create-RemoteThread"
    $s28="Get-MemoryProcAddress"
    $s29="IntPtr"
	condition:
		any of them
}


rule set_executionpolicy_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/18"
    description = "Detect risky operations"
    reference1  = "placeholder"
    reference2  = "https://gist.github.com/gfoss/2b39d680badd2cad9d82"
    filetype    = "ps1"
	strings:
    $s1="Set-ExecutionPolicy"
	condition:
		any of them
}
