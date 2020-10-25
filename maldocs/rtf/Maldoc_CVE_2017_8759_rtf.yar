
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-14
   Identifier: Detects malicious files in releation with CVE-2017-8759
   Reference: https://github.com/Voulnet/CVE-2017-8759-Exploit-sample
*/

private rule RTFFILE {
   meta:
      description = "Detects RTF files"
   condition:
      uint32be(0) == 0x7B5C7274
}



rule CVE_2017_8759_WSDL_in_RTF {
   meta:
      description = "Detects malicious RTF file related CVE-2017-8759"
      author = "Security Doggo @xdxdxdxdoa"
      reference = "https://twitter.com/xdxdxdxdoa/status/908665278199996416"
      date = "2017-09-15"
   strings:
      $doc = "d0cf11e0a1b11ae1"
      $obj = "\\objupdate"
      $wsdl = "7700730064006c003d00" nocase
      $http1 = "68007400740070003a002f002f00" nocase
      $http2 = "680074007400700073003a002f002f00" nocase
      $http3 = "6600740070003a002f002f00" nocase
   condition:
      RTFFILE and $obj and $doc and $wsdl and 1 of ($http*)
}

