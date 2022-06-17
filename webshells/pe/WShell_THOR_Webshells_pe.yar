/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


//Rules reorganized/sorted by Sort_Rules on 2022-06-16



rule Unpack_Injectt {
	meta:
		description = "Webshells Auto-generated - file Injectt.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8a5d2158a566c87edc999771e12d42c5"
	strings:
		$s2 = "%s -Run                              -->To Install And Run The Service"
		$s3 = "%s -Uninstall                        -->To Uninstall The Service"
		$s4 = "(STANDARD_RIGHTS_REQUIRED |SC_MANAGER_CONNECT |SC_MANAGER_CREATE_SERVICE |SC_MAN"
	condition:
		all of them
}


rule Debug_BDoor {
	meta:
		description = "Webshells Auto-generated - file BDoor.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "e4e8e31dd44beb9320922c5f49739955"
	strings:
		$s1 = "\\BDoor\\"
		$s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
	condition:
		all of them
}


rule bin_Client {
	meta:
		description = "Webshells Auto-generated - file Client.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5f91a5b46d155cacf0cc6673a2a5461b"
	strings:
		$s0 = "Recieved respond from server!!"
		$s4 = "packet door client"
		$s5 = "input source port(whatever you want):"
		$s7 = "Packet sent,waiting for reply..."
	condition:
		all of them
}


rule ZXshell2_0_rar_Folder_ZXshell {
	meta:
		description = "Webshells Auto-generated - file ZXshell.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "246ce44502d2f6002d720d350e26c288"
	strings:
		$s0 = "WPreviewPagesn"
		$s1 = "DA!OLUTELY N"
	condition:
		all of them
}


rule RkNTLoad {
	meta:
		description = "Webshells Auto-generated - file RkNTLoad.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "262317c95ced56224f136ba532b8b34f"
	strings:
		$s1 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
		$s2 = "5pur+virtu!"
		$s3 = "ugh spac#n"
		$s4 = "xcEx3WriL4"
		$s5 = "runtime error"
		$s6 = "loseHWait.Sr."
		$s7 = "essageBoxAw"
		$s8 = "$Id: UPX 1.07 Copyright (C) 1996-2001 the UPX Team. All Rights Reserved. $"
	condition:
		all of them
}


rule binder2_binder2 {
	meta:
		description = "Webshells Auto-generated - file binder2.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d594e90ad23ae0bc0b65b59189c12f11"
	strings:
		$s0 = "IsCharAlphaNumericA"
		$s2 = "WideCharToM"
		$s4 = "g 5pur+virtu!"
		$s5 = "\\syslog.en"
		$s6 = "heap7'7oqk?not="
		$s8 = "- Kablto in"
	condition:
		all of them
}


rule sendmail {
	meta:
		description = "Webshells Auto-generated - file sendmail.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "75b86f4a21d8adefaf34b3a94629bd17"
	strings:
		$s3 = "_NextPyC808"
		$s6 = "Copyright (C) 2000, Diamond Computer Systems Pty. Ltd. (www.diamondcs.com.au)"
	condition:
		all of them
}


rule hkshell_hkshell {
	meta:
		description = "Webshells Auto-generated - file hkshell.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "168cab58cee59dc4706b3be988312580"
	strings:
		$s1 = "PrSessKERNELU"
		$s2 = "Cur3ntV7sion"
		$s3 = "Explorer8"
	condition:
		all of them
}


rule Unpack_TBack {
	meta:
		description = "Webshells Auto-generated - file TBack.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a9d1007823bf96fb163ab38726b48464"
	strings:
		$s5 = "\\final\\new\\lcc\\public.dll"
	condition:
		all of them
}


rule DarkSpy105 {
	meta:
		description = "Webshells Auto-generated - file DarkSpy105.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f0b85e7bec90dba829a3ede1ab7d8722"
	strings:
		$s7 = "Sorry,DarkSpy got an unknown exception,please re-run it,thanks!"
	condition:
		all of them
}


rule EditServer_Webshell {
	meta:
		description = "Webshells Auto-generated - file EditServer.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f945de25e0eba3bdaf1455b3a62b9832"
	strings:
		$s2 = "Server %s Have Been Configured"
		$s5 = "The Server Password Exceeds 32 Characters"
		$s8 = "9--Set Procecess Name To Inject DLL"
	condition:
		all of them
}


rule svchostdll {
	meta:
		description = "Webshells Auto-generated - file svchostdll.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0f6756c8cb0b454c452055f189e4c3f4"
	strings:
		$s0 = "InstallService"
		$s1 = "RundllInstallA"
		$s2 = "UninstallService"
		$s3 = "&G3 Users In RegistryD"
		$s4 = "OL_SHUTDOWN;I"
		$s5 = "SvcHostDLL.dll"
		$s6 = "RundllUninstallA"
		$s7 = "InternetOpenA"
		$s8 = "Check Cloneomplete"
	condition:
		all of them
}


rule vanquish {
	meta:
		description = "Webshells Auto-generated - file vanquish.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "684450adde37a93e8bb362994efc898c"
	strings:
		$s3 = "You cannot delete protected files/folders! Instead, your attempt has been logged"
		$s8 = "?VCreateProcessA@@YGHPBDPADPAU_SECURITY_ATTRIBUTES@@2HKPAX0PAU_STARTUPINFOA@@PAU"
		$s9 = "?VFindFirstFileExW@@YGPAXPBGW4_FINDEX_INFO_LEVELS@@PAXW4_FINDEX_SEARCH_OPS@@2K@Z"
	condition:
		all of them
}


rule winshell {
	meta:
		description = "Webshells Auto-generated - file winshell.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3144410a37dd4c29d004a814a294ea26"
	strings:
		$s0 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
		$s1 = "WinShell Service"
		$s2 = "__GLOBAL_HEAP_SELECTED"
		$s3 = "__MSVCRT_HEAP_SELECT"
		$s4 = "Provide Windows CmdShell Service"
		$s5 = "URLDownloadToFileA"
		$s6 = "RegisterServiceProcess"
		$s7 = "GetModuleBaseNameA"
		$s8 = "WinShell v5.0 (C)2002 janker.org"
	condition:
		all of them
}


rule HYTop2006_rar_Folder_2006Z {
	meta:
		description = "Webshells Auto-generated - file 2006Z.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "fd1b6129abd4ab177fed135e3b665488"
	strings:
		$s1 = "wangyong,czy,allen,lcx,Marcos,kEvin1986,myth"
		$s8 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x"
	condition:
		all of them
}


rule BIN_Client {
	meta:
		description = "Webshells Auto-generated - file Client.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "9f0a74ec81bc2f26f16c5c172b80eca7"
	strings:
		$s0 = "=====Remote Shell Closed====="
		$s2 = "All Files(*.*)|*.*||"
		$s6 = "WSAStartup Error!"
		$s7 = "SHGetFileInfoA"
		$s8 = "CreateThread False!"
		$s9 = "Port Number Error"
	condition:
		4 of them
}


rule shelltools_g0t_root_uptime {
	meta:
		description = "Webshells Auto-generated - file uptime.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d1f56102bc5d3e2e37ab3ffa392073b9"
	strings:
		$s0 = "JDiamondCSlC~"
		$s1 = "CharactQA"
		$s2 = "$Info: This file is packed with the UPX executable packer $"
		$s5 = "HandlereateConso"
		$s7 = "ION\\System\\FloatingPo"
	condition:
		all of them
}


rule DllInjection {
	meta:
		description = "Webshells Auto-generated - file DllInjection.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a7b92283a5102886ab8aee2bc5c8d718"
	strings:
		$s0 = "\\BDoor\\DllInjecti"
	condition:
		all of them
}


rule Mithril_v1_45_Mithril {
	meta:
		description = "Webshells Auto-generated - file Mithril.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f1484f882dc381dde6eaa0b80ef64a07"
	strings:
		$s2 = "cress.exe"
		$s7 = "\\Debug\\Mithril."
	condition:
		all of them
}


rule hkshell_hkrmv {
	meta:
		description = "Webshells Auto-generated - file hkrmv.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "bd3a0b7a6b5536f8d96f50956560e9bf"
	strings:
		$s5 = "/THUMBPOSITION7"
		$s6 = "\\EvilBlade\\"
	condition:
		all of them
}


rule bdcli100 {
	meta:
		description = "Webshells Auto-generated - file bdcli100.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b12163ac53789fb4f62e4f17a8c2e028"
	strings:
		$s5 = "unable to connect to "
		$s8 = "backdoor is corrupted on "
	condition:
		all of them
}


rule HYTop2006_rar_Folder_2006X2 {
	meta:
		description = "Webshells Auto-generated - file 2006X2.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cc5bf9fc56d404ebbc492855393d7620"
	strings:
		$s2 = "Powered By "
		$s3 = " \" onClick=\"this.form.sharp.name=this.form.password.value;this.form.action=this."
	condition:
		all of them
}


rule rdrbs084 {
	meta:
		description = "Webshells Auto-generated - file rdrbs084.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "ed30327b255816bdd7590bf891aa0020"
	strings:
		$s0 = "Create mapped port. You have to specify domain when using HTTP type."
		$s8 = "<LOCAL PORT> <MAPPING SERVER> <MAPPING SERVER PORT> <TARGET SERVER> <TARGET"
	condition:
		all of them
}


rule HYTop_CaseSwitch_2005 {
	meta:
		description = "Webshells Auto-generated - file 2005.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8bf667ee9e21366bc0bd3491cb614f41"
	strings:
		$s1 = "MSComDlg.CommonDialog"
		$s2 = "CommonDialog1"
		$s3 = "__vbaExceptHandler"
		$s4 = "EVENT_SINK_Release"
		$s5 = "EVENT_SINK_AddRef"
		$s6 = "By Marcos"
		$s7 = "EVENT_SINK_QueryInterface"
		$s8 = "MethCallEngine"
	condition:
		all of them
}


rule byshell063_ntboot {
	meta:
		description = "Webshells Auto-generated - file ntboot.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "99b5f49db6d6d9a9faeffb29fd8e6d8c"
	strings:
		$s0 = "SYSTEM\\CurrentControlSet\\Services\\NtBoot"
		$s1 = "Failure ... Access is Denied !"
		$s2 = "Dumping Description to Registry..."
		$s3 = "Opening Service .... Failure !"
	condition:
		all of them
}


rule HYTop2006_rar_Folder_2006X {
	meta:
		description = "Webshells Auto-generated - file 2006X.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cf3ee0d869dd36e775dfcaa788db8e4b"
	strings:
		$s1 = "<input name=\"password\" type=\"password\" id=\"password\""
		$s6 = "name=\"theAction\" type=\"text\" id=\"theAction\""
	condition:
		all of them
}


rule shelltools_g0t_root_resolve {
	meta:
		description = "Webshells Auto-generated - file resolve.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "69bf9aa296238610a0e05f99b5540297"
	strings:
		$s0 = "3^n6B(Ed3"
		$s1 = "^uldn'Vt(x"
		$s2 = "\\= uPKfp"
		$s3 = "'r.axV<ad"
		$s4 = "p,modoi$=sr("
		$s5 = "DiamondC8S t"
		$s6 = "`lQ9fX<ZvJW"
	condition:
		all of them
}


rule byloader {
	meta:
		description = "Webshells Auto-generated - file byloader.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0f0d6dc26055653f5844ded906ce52df"
	strings:
		$s0 = "SYSTEM\\CurrentControlSet\\Services\\NtfsChk"
		$s1 = "Failure ... Access is Denied !"
		$s2 = "NTFS Disk Driver Checking Service"
		$s3 = "Dumping Description to Registry..."
		$s4 = "Opening Service .... Failure !"
	condition:
		all of them
}


rule shelltools_g0t_root_Fport {
	meta:
		description = "Webshells Auto-generated - file Fport.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "dbb75488aa2fa22ba6950aead1ef30d5"
	strings:
		$s4 = "Copyright 2000 by Foundstone, Inc."
		$s5 = "You must have administrator privileges to run fport - exiting..."
	condition:
		all of them
}


rule PasswordReminder {
	meta:
		description = "Webshells Auto-generated - file PasswordReminder.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "ea49d754dc609e8bfa4c0f95d14ef9bf"
	strings:
		$s3 = "The encoded password is found at 0x%8.8lx and has a length of %d."
	condition:
		all of them
}


rule Pack_InjectT {
	meta:
		description = "Webshells Auto-generated - file InjectT.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "983b74ccd57f6195a0584cdfb27d55e8"
	strings:
		$s3 = "ail To Open Registry"
		$s4 = "32fDssignim"
		$s5 = "vide Internet S"
		$s6 = "d]Software\\M"
		$s7 = "TInject.Dll"
	condition:
		all of them
}


rule rknt_zip_Folder_RkNT {
	meta:
		description = "Webshells Auto-generated - file RkNT.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5f97386dfde148942b7584aeb6512b85"
	strings:
		$s0 = "PathStripPathA"
		$s1 = "`cLGet!Addr%"
		$s2 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
		$s3 = "oQToOemBuff* <="
		$s4 = "ionCdunAsw[Us'"
		$s6 = "CreateProcessW: %S"
		$s7 = "ImageDirectoryEntryToData"
	condition:
		all of them
}


rule dbgntboot {
	meta:
		description = "Webshells Auto-generated - file dbgntboot.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "4d87543d4d7f73c1529c9f8066b475ab"
	strings:
		$s2 = "now DOS is working at mode %d,faketype %d,against %s,has worked %d minutes,by sp"
		$s3 = "sth junk the M$ Wind0wZ retur"
	condition:
		all of them
}


rule hxdef100 {
	meta:
		description = "Webshells Auto-generated - file hxdef100.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "55cc1769cef44910bd91b7b73dee1f6c"
	strings:
		$s0 = "RtlAnsiStringToUnicodeString"
		$s8 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\"
		$s9 = "\\\\.\\mailslot\\hxdef-rk100sABCDEFGH"
	condition:
		all of them
}


rule rdrbs100 {
	meta:
		description = "Webshells Auto-generated - file rdrbs100.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "7c752bcd6da796d80a6830c61a632bff"
	strings:
		$s3 = "Server address must be IP in A.B.C.D format."
		$s4 = " mapped ports in the list. Currently "
	condition:
		all of them
}


rule Mithril_Mithril {
	meta:
		description = "Webshells Auto-generated - file Mithril.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "017191562d72ab0ca551eb89256650bd"
	strings:
		$s0 = "OpenProcess error!"
		$s1 = "WriteProcessMemory error!"
		$s4 = "GetProcAddress error!"
		$s5 = "HHt`HHt\\"
		$s6 = "Cmaudi0"
		$s7 = "CreateRemoteThread error!"
		$s8 = "Kernel32"
		$s9 = "VirtualAllocEx error!"
	condition:
		all of them
}


rule hxdef100_2 {
	meta:
		description = "Webshells Auto-generated - file hxdef100.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1b393e2e13b9c57fb501b7cd7ad96b25"
	strings:
		$s0 = "\\\\.\\mailslot\\hxdef-rkc000"
		$s2 = "Shared Components\\On Access Scanner\\BehaviourBlo"
		$s6 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\"
	condition:
		all of them
}


rule Release_dllTest {
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "76a59fc3242a2819307bb9d593bef2e0"
	strings:
		$s0 = ";;;Y;`;d;h;l;p;t;x;|;"
		$s1 = "0 0&00060K0R0X0f0l0q0w0"
		$s2 = ": :$:(:,:0:4:8:D:`=d="
		$s3 = "4@5P5T5\\5T7\\7d7l7t7|7"
		$s4 = "1,121>1C1K1Q1X1^1e1k1s1y1"
		$s5 = "9 9$9(9,9P9X9\\9`9d9h9l9p9t9x9|9"
		$s6 = "0)0O0\\0a0o0\"1E1P1q1"
		$s7 = "<.<I<d<h<l<p<t<x<|<"
		$s8 = "3&31383>3F3Q3X3`3f3w3|3"
		$s9 = "8@;D;H;L;P;T;X;\\;a;9=W=z="
	condition:
		all of them
}


rule hkdoordll {
	meta:
		description = "Webshells Auto-generated - file hkdoordll.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b715c009d47686c0e62d0981efce2552"
	strings:
		$s6 = "Can't uninstall,maybe the backdoor is not installed or,the Password you INPUT is"
	condition:
		all of them
}


rule Mithril_v1_45_dllTest {
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1b9e518aaa62b15079ff6edb412b21e9"
	strings:
		$s3 = "syspath"
		$s4 = "\\Mithril"
		$s5 = "--list the services in the computer"
	condition:
		all of them
}


rule dbgiis6cli {
	meta:
		description = "Webshells Auto-generated - file dbgiis6cli.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3044dceb632b636563f66fee3aaaf8f3"
	strings:
		$s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)"
		$s5 = "###command:(NO more than 100 bytes!)"
	condition:
		all of them
}


rule Debug_cress {
	meta:
		description = "Webshells Auto-generated - file cress.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "36a416186fe010574c9be68002a7286a"
	strings:
		$s0 = "\\Mithril "
		$s4 = "Mithril.exe"
	condition:
		all of them
}


rule adjustcr {
	meta:
		description = "Webshells Auto-generated - file adjustcr.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "17037fa684ef4c90a25ec5674dac2eb6"
	strings:
		$s0 = "$Info: This file is packed with the UPX executable packer $"
		$s2 = "$License: NRV for UPX is distributed under special license $"
		$s6 = "AdjustCR Carr"
		$s7 = "ION\\System\\FloatingPo"
	condition:
		all of them
}


rule EditServer_Webshell_2 {
	meta:
		description = "Webshells Auto-generated - file EditServer.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5c1f25a4d206c83cdfb006b3eb4c09ba"
	strings:
		$s0 = "@HOTMAIL.COM"
		$s1 = "Press Any Ke"
		$s3 = "glish MenuZ"
	condition:
		all of them
}


rule by064cli {
	meta:
		description = "Webshells Auto-generated - file by064cli.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "10e0dff366968b770ae929505d2a9885"
	strings:
		$s7 = "packet dropped,redirecting"
		$s9 = "input the password(the default one is 'by')"
	condition:
		all of them
}


rule Mithril_dllTest {
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a8d25d794d8f08cd4de0c3d6bf389e6d"
	strings:
		$s0 = "please enter the password:"
		$s3 = "\\dllTest.pdb"
	condition:
		all of them
}


rule peek_a_boo {
	meta:
		description = "Webshells Auto-generated - file peek-a-boo.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "aca339f60d41fdcba83773be5d646776"
	strings:
		$s0 = "__vbaHresultCheckObj"
		$s1 = "\\VB\\VB5.OLB"
		$s2 = "capGetDriverDescriptionA"
		$s3 = "__vbaExceptHandler"
		$s4 = "EVENT_SINK_Release"
		$s8 = "__vbaErrorOverflow"
	condition:
		all of them
}


rule Debug_dllTest_2 {
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1b9e518aaa62b15079ff6edb412b21e9"
	strings:
		$s4 = "\\Debug\\dllTest.pdb"
		$s5 = "--list the services in the computer"
	condition:
		all of them
}


rule shelltools_g0t_root_HideRun {
	meta:
		description = "Webshells Auto-generated - file HideRun.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "45436d9bfd8ff94b71eeaeb280025afe"
	strings:
		$s0 = "Usage -- hiderun [AppName]"
		$s7 = "PVAX SW, Alexey A. Popoff, Moscow, 1997."
	condition:
		all of them
}


rule regshell {
	meta:
		description = "Webshells Auto-generated - file regshell.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "db2fdc821ca6091bab3ebd0d8bc46ded"
	strings:
		$s0 = "Changes the base hive to HKEY_CURRENT_USER."
		$s4 = "Displays a list of values and sub-keys in a registry Hive."
		$s5 = "Enter a menu selection number (1 - 3) or 99 to Exit: "
	condition:
		all of them
}


rule screencap {
	meta:
		description = "Webshells Auto-generated - file screencap.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "51139091dea7a9418a50f2712ea72aa6"
	strings:
		$s0 = "GetDIBColorTable"
		$s1 = "Screen.bmp"
		$s2 = "CreateDCA"
	condition:
		all of them
}


rule ZXshell2_0_rar_Folder_zxrecv {
	meta:
		description = "Webshells Auto-generated - file zxrecv.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5d3d12a39f41d51341ef4cb7ce69d30f"
	strings:
		$s0 = "RyFlushBuff"
		$s1 = "teToWideChar^FiYP"
		$s2 = "mdesc+8F D"
		$s3 = "\\von76std"
		$s4 = "5pur+virtul"
		$s5 = "- Kablto io"
		$s6 = "ac#f{lowi8a"
	condition:
		all of them
}


rule httpdoor {
	meta:
		description = "Webshells Auto-generated - file httpdoor.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "6097ea963455a09474471a9864593dc3"
	strings:
		$s4 = "''''''''''''''''''DaJKHPam"
		$s5 = "o,WideCharR]!n]"
		$s6 = "HAutoComplete"
		$s7 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:sch"
	condition:
		all of them
}


rule _root_040_zip_Folder_deploy {
	meta:
		description = "Webshells Auto-generated - file deploy.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2c9f9c58999256c73a5ebdb10a9be269"
	strings:
		$s5 = "halon synscan 127.0.0.1 1-65536"
		$s8 = "Obviously you replace the ip address with that of the target."

	condition:
		all of them
}


rule by063cli {
	meta:
		description = "Webshells Auto-generated - file by063cli.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "49ce26eb97fd13b6d92a5e5d169db859"
	strings:
		$s2 = "#popmsghello,are you all right?"
		$s4 = "connect failed,check your network and remote ip."
	condition:
		all of them
}


rule byshell063_ntboot_2 {
	meta:
		description = "Webshells Auto-generated - file ntboot.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cb9eb5a6ff327f4d6c46aacbbe9dda9d"
	strings:
		$s6 = "OK,job was done,cuz we have localsystem & SE_DEBUG_NAME:)"
	condition:
		all of them
}


rule u_uay {
	meta:
		description = "Webshells Auto-generated - file uay.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "abbc7b31a24475e4c5d82fc4c2b8c7c4"
	strings:
		$s1 = "exec \"c:\\WINDOWS\\System32\\freecell.exe"
		$s9 = "SYSTEM\\CurrentControlSet\\Services\\uay.sys\\Security"
	condition:
		1 of them
}


rule bin_wuaus {
	meta:
		description = "Webshells Auto-generated - file wuaus.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "46a365992bec7377b48a2263c49e4e7d"
	strings:
		$s1 = "9(90989@9V9^9f9n9v9"
		$s2 = ":(:,:0:4:8:C:H:N:T:Y:_:e:o:y:"
		$s3 = ";(=@=G=O=T=X=\\="
		$s4 = "TCP Send Error!!"
		$s5 = "1\"1;1X1^1e1m1w1~1"
		$s8 = "=$=)=/=<=Y=_=j=p=z="
	condition:
		all of them
}


rule pwreveal {
	meta:
		description = "Webshells Auto-generated - file pwreveal.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b4e8447826a45b76ca45ba151a97ad50"
	strings:
		$s0 = "*<Blank - no es"
		$s3 = "JDiamondCS "
		$s8 = "sword set> [Leith=0 bytes]"
		$s9 = "ION\\System\\Floating-"
	condition:
		all of them
}


rule shelltools_g0t_root_xwhois {
	meta:
		description = "Webshells Auto-generated - file xwhois.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0bc98bd576c80d921a3460f8be8816b4"
	strings:
		$s1 = "rting! "
		$s2 = "aTypCog("
		$s5 = "Diamond"
		$s6 = "r)r=rQreryr"
	condition:
		all of them
}


rule vanquish_2 {
	meta:
		description = "Webshells Auto-generated - file vanquish.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2dcb9055785a2ee01567f52b5a62b071"
	strings:
		$s2 = "Vanquish - DLL injection failed:"
	condition:
		all of them
}


rule ZXshell2_0_rar_Folder_nc {
	meta:
		description = "Webshells Auto-generated - file nc.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2cd1bf15ae84c5f6917ddb128827ae8b"
	strings:
		$s0 = "WSOCK32.dll"
		$s1 = "?bSUNKNOWNV"
		$s7 = "p@gram Jm6h)"
		$s8 = "ser32.dllCONFP@"
	condition:
		all of them
}


rule portlessinst {
	meta:
		description = "Webshells Auto-generated - file portlessinst.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "74213856fc61475443a91cd84e2a6c2f"
	strings:
		$s2 = "Fail To Open Registry"
		$s3 = "f<-WLEggDr\""
		$s6 = "oMemoryCreateP"
	condition:
		all of them
}


rule SetupBDoor {
	meta:
		description = "Webshells Auto-generated - file SetupBDoor.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "41f89e20398368e742eda4a3b45716b6"
	strings:
		$s1 = "\\BDoor\\SetupBDoor"
	condition:
		all of them
}


rule BIN_Server {
	meta:
		description = "Webshells Auto-generated - file Server.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1d5aa9cbf1429bb5b8bf600335916dcd"
	strings:
		$s0 = "configserver"
		$s1 = "GetLogicalDrives"
		$s2 = "WinExec"
		$s4 = "fxftest"
		$s5 = "upfileok"
		$s7 = "upfileer"
	condition:
		all of them
}


rule HDConfig {
	meta:
		description = "Webshells Auto-generated - file HDConfig.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "7d60e552fdca57642fd30462416347bd"
	strings:
		$s0 = "An encryption key is derived from the password hash. "
		$s3 = "A hash object has been created. "
		$s4 = "Error during CryptCreateHash!"
		$s5 = "A new key container has been created."
		$s6 = "The password has been added to the hash. "
	condition:
		all of them
}

