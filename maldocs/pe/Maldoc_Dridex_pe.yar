
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-12-02
	Identifier: Phishing Gina Harrowell Dez 2015
*/

rule PHISH_02Dez2015_dropped_p0o6543f {
	meta:
		description = "Phishing Wave - file p0o6543f.exe"
		author = "Florian Roth"
		reference = "http://myonlinesecurity.co.uk/purchase-order-124658-gina-harrowell-clinimed-limited-word-doc-or-excel-xls-spreadsheet-malware/"
		date = "2015-12-02"
		hash = "db788d6d3a8ed1a6dc9626852587f475e7671e12fa9c9faa73b7277886f1e210"
	strings:
		$s1 = "netsh.exe" fullword wide
		$s2 = "routemon.exe" fullword wide
		$s3 = "script=" fullword wide /* Goodware String - occured 4 times */
		$s4 = "disconnect" fullword wide /* Goodware String - occured 14 times */
		$s5 = "GetClusterResourceTypeKey" fullword ascii /* Goodware String - occured 17 times */
		$s6 = "QueryInformationJobObject" fullword ascii /* Goodware String - occured 34 times */
		$s7 = "interface" fullword wide /* Goodware String - occured 52 times */
		$s8 = "connect" fullword wide /* Goodware String - occured 61 times */
		$s9 = "FreeConsole" fullword ascii /* Goodware String - occured 91 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

