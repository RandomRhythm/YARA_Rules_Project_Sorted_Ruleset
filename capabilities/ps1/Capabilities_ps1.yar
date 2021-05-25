
rule powershell_Logging_policy_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/11"
    description = "Detect logging policy access/modification"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
		$ScriptLogging1 = "EnableScriptBlockInvocationLogging"
	condition:
		any of them
}


rule system_fingerprinting_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect risky operations"
    reference1  = "https://www.microsoft.com/security/blog/2021/03/25/analyzing-attacks-taking-advantage-of-the-exchange-server-vulnerabilities/"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="win32_operatingSystem"
    $s2=".OSArchitecture"
    $s3=".osarchitecture"
    $s4=".Domain"
    $s5="$env:USERNAME"
    $s6="$env:COMPUTERNAME"
    $s7="[Environment]::Is64BitProcess"
    $s8="Security.Principal.WindowsBuiltinRole]::Administrator"
    $s9=".LastBootUpTime"
    $s10=".version"
    $s11="Get-NetIPConfiguration"
    $s12="Security.Principal.WindowsIdentity"
    $s13=".ProcessName"
    $s14="get_CurrentDomain"
    $s15="Win32_NetworkAdapterConfiguration"
    $s16="osVersion.versionString"
    $s17="PSVersion"
    $s18="CurrentDomain.GetAssemblies"
    $s19="discover-psinterestingservices" nocase
    $s20="find-allvulns" nocase
    $s21="find-avsignature" nocase
    $s22="find-ms" nocase
    $s23="find-ms13081" nocase
    $s24="find-psserviceaccounts" nocase
    $s25="get-information" nocase
    $s26="get-kerberospolicy" nocase
    $s27="get-gpppassword" nocase
    $s28="get-applicationhost" nocase
    $s29="Get-WmiObject Win32_ComputerSystem"
    $s30="get-regalwaysinstallelevated" nocase
    $s31="get-regautologon" nocase
    $s32="get-registryalwaysinstallelevated" nocase
    $s33="get-registryautologon" nocase
    $s44="get-webconfig" nocase
    $s45="{$o = $_.getowner(); if(-not $($o.User))" nocase
	condition:
		any of them
}


rule active_directory_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect risky operations"
    reference1  = "https://www.microsoft.com/security/blog/2021/03/25/analyzing-attacks-taking-advantage-of-the-exchange-server-vulnerabilities/"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="get-psadforestinfo"
    $s2="get-psadforestkrbtgtinfo"
	condition:
		any of them
}

rule network_reconnaissance_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/10"
    description = "Detect risky operations"
    reference1  = "https://www.microsoft.com/security/blog/2021/03/25/analyzing-attacks-taking-advantage-of-the-exchange-server-vulnerabilities/"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="netstat"
    $s2="'^172.'"
    $s3="'^192.168'"
    $s4="Win32_PingStatus"
    $s5="system.net.dns"
    $s6="discover-psmsexchangeservers" nocase
    $s7="discover-psmssqlservers" nocase
    $s8="port-scan" nocase
	condition:
		any of them
}

rule remote_access_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect risky operations"
    reference1  = "https://www.microsoft.com/security/blog/2021/03/25/analyzing-attacks-taking-advantage-of-the-exchange-server-vulnerabilities/"
    filetype    = "ps1"
	strings:
    $s1="Enter-PSSession"
	condition:
		any of them
}

rule persistence_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect persistence"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="schtasks" nocase
    $s2="Schedule.Service"
    $s3="CreateServiceA"
    $s4="remove-persistence" nocase
    $s5="add-persistence" nocase
    $s6="write-cmdservicebinary" nocase
    $s7="write-servicebinary" nocase
    $s8="write-serviceexe" nocase
    $s9="write-serviceexecmd" nocase
    $s10="restore-servicebinary" nocase
    $s11="restore-serviceexe" nocase
    $s12="write-useraddservicebinary" nocase
    $s13="invoke-serviceabuse" nocase
    $s14="invoke-servicecmd" nocase
    $s15="invoke-servicedisable" nocase
    $s16="invoke-serviceenable" nocase
    $s17="invoke-servicestart" nocase
    $s18="invoke-servicestop" nocase
    $s19="invoke-serviceuseradd" nocase
    $s20="install-servicebinary" nocase
    $s21="get-modifiablescheduledtaskfile" nocase
    $s22="get-modifiableregistryautorun" nocase
    $s23="get-serviceexeperms" nocase
    $s24="get-serviceperms" nocase
    $s25="get-serviceunquoted" nocase
    $s26="new-elevatedpersistenceoption" nocase
    $s27="new-userpersistenceoption" nocase

	condition:
		any of them
}

rule Service_Access_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect persistence"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s1="CloseServiceHandle" nocase
    $s2="OpenSCManagerA"
    $s3="CreateServiceA"
    $s4="OpenServiceA"
    $s5="StartServiceA"
    $s6="DeleteService"
    $s7="OpenServiceA"
    $s8="ServicesActive"
	condition:
		any of them
}

rule cryptography_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect risky operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="System.Security.Cryptography." nocase
    $s2="ConvertTo-Rc4ByteStream"
    $s3="System.Security.Cryptography.HMACSHA256"
	condition:
		any of them
}

rule http_https_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect HTTP operations"
    reference1  = "https://www.microsoft.com/security/blog/2021/03/25/analyzing-attacks-taking-advantage-of-the-exchange-server-vulnerabilities/"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="Content-Type"
    $s2="x-Authorization"
    $s3="application/x-www-form-urlencoded"
    $s4="'http://'"
    $s4_1="'http[:]//"
    $s5="'https://'"
    $s6="Tls12"
    $s7="ServerCertificateValidationCallback"
    $s8="Net.WebClient"
    $s8_1="Net.WebC`lient"
    $s8_2="net-webclient" nocase
    $s9="GetSystemWebProxy"
    $s10="downloadstring"
	condition:
		any of them
}

rule screen_capture_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect screen capture operations"
    reference1  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="get-timedscreenshot" nocase
	condition:
		any of them
}

rule audio_capture_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect screen capture operations"
    reference1  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="Get-MicrophoneAudio"
	condition:
		any of them
}

rule external_command_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/10"
    description = "Detect cmd command operations"
    reference1  = "https://www.microsoft.com/security/blog/2021/03/25/analyzing-attacks-taking-advantage-of-the-exchange-server-vulnerabilities/"
    filetype    = "ps1"
	strings:
    $s1="cmd /c"
	condition:
		any of them
}

rule suspicious_http_https_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect HTTP operations"
    reference1  = "https://www.microsoft.com/security/blog/2021/03/25/analyzing-attacks-taking-advantage-of-the-exchange-server-vulnerabilities/"
    filetype    = "ps1"
	strings:
    $s4_1="'http[:]//"
    $s8_1="Net.WebC`lient"
	condition:
		any of them
}

rule DownloadData_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect HTTP operations"
    reference1  = "https://www.microsoft.com/security/blog/2021/03/25/analyzing-attacks-taking-advantage-of-the-exchange-server-vulnerabilities/"
    filetype    = "ps1"
	strings:
    $s4_1="DownloadData"
	condition:
		any of them
}


rule random_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect HTTP operations"
    reference1  = "https://www.microsoft.com/security/blog/2021/03/25/analyzing-attacks-taking-advantage-of-the-exchange-server-vulnerabilities/"
    filetype    = "ps1"
	strings:
    $s4_1="'Get-Random"
	condition:
		any of them
}

rule suspicious_string_manipulation_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect HTTP operations"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s1="char("
    $s2="[system.String]::Join"
    $s3="[System.Convert]::ToInt32"
    $s4="[Convert]::ToInt16"
    $s5="ToUnicode"
    $s6="System.Text.StringBuilder"
    $s7=".substring"
    $s8="-replace"
    $s9=".replace"
    $s10=".split("
    $s11="-join"
    $s12="[Convert]::ToByte"
    $s13="texttoexe"
    $s14="[System.Text.Encoding]::ASCII.GetString([System.Convert]"
	condition:
		any of them
}


rule compression_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect HTTP operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="IO.Compression.DeflateStream"
    $s2="IO.Compression.CompressionMode]"
    $s3="Decompress"
    $s4="gzipstream" nocase
    $s5="IO.Compression.ZipFile"
    $s6="System.IO.Compression.FileSystem"
	condition:
		any of them
}


rule base64_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect HTTP operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="frombase64string" nocase
    $s2="==\""
    $s3="=\""
    $s4="base64.b64decode" nocase
    $s5="base64tostring" nocase
    $s6="stringtobase64" nocase
	condition:
		any of them
}


rule DLL_Load_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect HTTP operations"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s1="GetModuleHandle"
    $s2="IMAGE_EXPORT_DIRECTORY"
    $s3="DllCharacteristics"
    $s4="IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"
	condition:
		any of them
}

rule EXE_Load_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect HTTP operations"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s1="IsWow64Process"
	condition:
		any of them
}

rule redirect_output_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect HTTP operations"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s1="Out-Null"
	condition:
		any of them
}

rule GetBytes_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect HTTP operations"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s1=".GetBytes"
	condition:
		any of them
}

rule Process_Termination_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect HTTP operations"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s1="kill" nocase
	condition:
		any of them
}

rule WMI_usage_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/5/9"
    description = "Detect HTTP operations"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s1="Get-WmiObject"
    $s2="invoke-powershellwmi" nocase
    $s3="invoke-wmicommand" nocase
	condition:
		any of them
}




rule useragent_spoofing_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect HTTP operations"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s1="User-Agent"
	condition:
		any of them
}

rule number_manipulation_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect HTTP operations"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s1="[Math]"
	condition:
		any of them
}


rule external_file_read_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect HTTP operations"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s1="readtoend"
	condition:
		any of them
}


rule external_file_access_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect HTTP operations"
    reference1  = "placeholder"
    reference2  = "https://github.com/secprentice/PowerShellBlacklist"
    filetype    = "ps1"
	strings:
    $s1="[System.IO.File]"
    $s2="AppendAllText"
    $s3="GetTempFileName"
    $s4="GetRandomFileName"
    $s5="WriteAllText"
    $s6="out-chm" nocase
    $s7="out-excel" nocase
    $s8="out-hta" nocase
    $s9="out-java" nocase
    $s10="out-minidump" nocase
    $s11="out-shortcut" nocase
    $s12="out-word" nocase
    $s13="get-modifiablepath" nocase
    $s14="get-unattendedinstallfiles" nocase
	condition:
		any of them
}





rule Remove_Item_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/29"
    description = "Detect Remove-Item usage: can delete many different types of items, including files, folders, registry keys, variables, aliases, and functions"
    reference1  = "https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-item?view=powershell-7.1"
    filetype    = "ps1"
	strings:
    $s1="ForEach-Object"
	condition:
		any of them
}


rule looping_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect HTTP operations"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s1="ForEach-Object"
	condition:
		any of them
}

rule Get_Random_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect use of randomness"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s1="Get-Random"
	condition:
		any of them
}


rule bitwise_operations_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect bitwise operations"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s1="band"
    $s2="bor"
    $s3="bxor"
    $s4="bnot"
    $s5="shl"
    $s6="shr"
	condition:
		any of them
}

rule Sleep_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/29"
    description = "Detect use of randomness"
    reference1  = "placeholder"
    filetype    = "ps1"
	strings:
    $s1="Start-Sleep"
	condition:
		any of them
}

rule job_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/29"
    description = "Detect background jobs"
    reference1  = "https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/start-job?view=powershell-7.1"
    filetype    = "ps1"
	strings:
    $s1="start-job"
    $s2="wait-job"
    $s3="Receive-Job"
	condition:
		any of them
}

rule hosting_domains_fileless_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/30"
    description = "Detect domains where text can be stored in raw form for use in fileless attacks"
    reference1  = ""
    filetype    = "ps1"
	strings:
    $s1="raw.githubusercontent.com"
    $s2="pastebin.com"
	condition:
		any of them
}



rule encoded_command_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/6"
    description = "Detect encoded commands"
    filetype    = "ps1"
	strings:
    $s1="-encodedCommand"
    $s2="-EncodedCommand"
    $s3="-encodedcommand"
	condition:
		any of them
}


rule suspicious_encodedCommand_ps1
{
  meta:
    author      = "Ryan Boyle"
    date        = "2021/4/10"
    description = "Detect suspicious encoded commands"
    reference1  = "https://www.microsoft.com/security/blog/2021/03/25/analyzing-attacks-taking-advantage-of-the-exchange-server-vulnerabilities/"
    filetype    = "ps1"
	strings:
    $s1="-encodedCommand"
    $s2="-EncodedCommand"
    $s3="-encodedcommand"
    $d0=/-(e|E)((`|)(n|N)|)((`|)(c|C)|)((`|)(o|O)|)((`|)(d|D)|)((`|)(e|E)|)((`|)(d|D)|)((`|)(c|C)|)((`|)(o|O)|)((`|)(m|M)|)((`|)(m|M)|)((`|)(a|A)|)((`|)(n|N)|)((`|)(d|D)|)/

	condition:
		0 of ($s*) and any of ($d*)
}