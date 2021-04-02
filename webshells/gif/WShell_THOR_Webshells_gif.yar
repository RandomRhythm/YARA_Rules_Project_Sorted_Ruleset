/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


//Rules reorganized/sorted by Sort_Rules on 2021-04-01



/* GIF Header webshell */

rule DarkSecurityTeam_Webshell {
	meta:
		description = "Dark Security Team Webshell"
		author = "Florian Roth"
		hash = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"
		score = 50
	strings:
		$s0 = "form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\"&HtmlEncode(Server.MapPath(\".\"))&" ascii
	condition:
		1 of them
}

