/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/


//Rules reorganized/sorted by Sort_Rules on 2021-04-01



rule ARIA_SB2
{	meta:
		author = "spelissier"
		description = "Aria SBox 2"
		date = "2020-12"
		reference="http://210.104.33.10/ARIA/doc/ARIA-specification-e.pdf#page=7"
	strings:
		$c0 = { E2 4E 54 FC 94 C2 4A CC 62 0D 6A 46 3C 4D 8B D1 5E FA 64 CB B4 97 BE 2B BC 77 2E 03 D3 19 59 C1 }
	condition:
		$c0
}



rule SipHash_big_endian_constants {
    meta:
		author = "spelissier"
		description = "Look for SipHash constants in big endian"
		date = "2020-07"
		reference = "https://131002.net/siphash/siphash.pdf#page=6"
	strings:
		$c0 = "uespemos"
		$c1 = "modnarod"
		$c2 = "arenegyl"
		$c3 = "setybdet"
	condition:
		2 of them
}
