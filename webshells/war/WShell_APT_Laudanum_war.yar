/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


//Rules reorganized/sorted by Sort_Rules on 2021-04-01



rule jsp_cmd : webshell {
	meta:
		description = "Laudanum Injector Tools - file cmd.war"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "55e4c3dc00cfab7ac16e7cfb53c11b0c01c16d3d"
	strings:
		$s0 = "cmd.jsp}" fullword ascii
		$s1 = "cmd.jspPK" fullword ascii
		$s2 = "WEB-INF/web.xml" fullword ascii /* Goodware String - occured 1 times */
		$s3 = "WEB-INF/web.xmlPK" fullword ascii /* Goodware String - occured 1 times */
		$s4 = "META-INF/MANIFEST.MF" fullword ascii /* Goodware String - occured 12 times */
	condition:
		uint16(0) == 0x4b50 and filesize < 2KB and all of them
}

