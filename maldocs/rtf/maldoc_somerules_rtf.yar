/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


//Rules reorganized/sorted by Sort_Rules on 2022-06-16



// This rule have beed improved by Javier Rascon
rule RTF_Shellcode : maldoc
{
    meta:

        author = "RSA-IR – Jared Greenhill"
        date = "01/21/13"
        description = "identifies RTF's with potential shellcode"
            filetype = "RTF"

    strings:
        $rtfmagic={7B 5C 72 74 66}
        /* $scregex=/[39 30]{2,20}/ */
        $scregex=/(90){2,20}/

    condition:

        ($rtfmagic at 0) and ($scregex)
}

