/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/


//Rules reorganized/sorted by Sort_Rules on 2021-04-01



/*
  Description: None
  Priority: 5
  Scope: Against Attachment
  Tags: None
  Created in PhishMe's Triage on September 14, 2015 2:35 PM
*/

rule docx_macro : mail
{
  strings:
    $header="PK" 
    $vbaStrings="word/vbaProject.bin" nocase

  condition:
    $header at 0 and $vbaStrings
}

