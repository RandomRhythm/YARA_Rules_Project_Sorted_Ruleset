/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


//Rules reorganized/sorted by Sort_Rules on 2020-09-20


rule installer {
	meta:
		description = "Webshells Auto-generated - file installer.cmd"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a507919ae701cf7e42fa441d3ad95f8f"
	strings:
		$s0 = "Restore Old Vanquish"
		$s4 = "ReInstall Vanquish"
	condition:
		all of them
}

