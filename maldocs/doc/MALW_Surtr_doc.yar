/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


//Rules reorganized/sorted by Sort_Rules on 2021-03-09



rule SurtrStrings : Surtr Family {	
	meta: 
		author = "Katie Kleemola"
		description = "Strings for Surtr"
		last_updated = "2014-07-16"

	strings:
		$ = "\x00soul\x00"
		$ = "\x00InstallDll.dll\x00"
		$ = "\x00_One.dll\x00"
		$ = "_Fra.dll"
		$ = "CrtRunTime.log"
		$ = "Prod.t"
		$ = "Proe.t"
		$ = "Burn\\"
		$ = "LiveUpdata_Mem\\"

	condition:
		any of them

}

