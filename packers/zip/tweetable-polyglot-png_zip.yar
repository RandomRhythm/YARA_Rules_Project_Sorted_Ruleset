/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

//Rules reorganized/sorted by Sort_Rules on 2021-04-24


rule TweetablePolyglotPng {
  meta:
    description = "tweetable-polyglot-png: https://github.com/DavidBuchanan314/tweetable-polyglot-png"
    author = "Manfred Kaiser"
  strings:
    $magic1 = { 50 4b 01 02 }
    $magic2 = { 50 4b 03 04 }
    $magic3 = { 50 4b 05 06 }

  condition:
    (
      uint32be(0) == 0x89504E47 or
      uint32be(0) == 0xFFD8FFE0
    ) and
    $magic1 and
    $magic2 and
    $magic3

}

