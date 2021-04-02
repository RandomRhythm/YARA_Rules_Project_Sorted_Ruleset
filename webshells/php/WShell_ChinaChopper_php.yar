/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/


//Rules reorganized/sorted by Sort_Rules on 2021-04-01



rule webshell_ChinaChopper_php
{
  meta:
    author      = "Ryan Boyle randomrhythm@rhythmengineering.com"
    date        = "2020/10/29"
    description = "Detect China Chopper PHP webshell"
    reference1  = "https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html"
    filetype    = "php"
  strings:
	$ChinaChopperPHP = {3C 3F 70 68 70 20 40 65 76 61 6C 28 24 5F 50 4F 53 54 5B ?? 70 61 73 73 77 6F 72 64 ?? 5D 29 3B 3F 3E}
  condition:
	$ChinaChopperPHP
}

