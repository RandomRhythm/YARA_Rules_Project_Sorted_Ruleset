/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/


//Rules reorganized/sorted by Sort_Rules on 2022-06-16



rule go_language_elf
{
   meta:
      description = "Detection for Go programming language compiled ELF files"
      date = "2021/8/5"
      author = "Ryan Boyle randomrhythm@rhythmengineering.com"
      sampleLinux1= "14e9b5e214572cb13ff87727d680633f5ee238259043357c94302654c546cad2" //WellMess
      sampleLinux2= "0c395715bfeb8f89959be721cd2f614d2edb260614d5a21e90cc4c142f5d83ad/detection" //BotenaGo
      filetype = "elf"
   strings:
      $goLinux1 = "/Go/src/"
      $goLinux2 = "/golang/src/"
      $GOMAXPROCS1 = "Gomax"
      $GOMAXPROCS2 = "GOMAXPRO"
      $ELFheader = { 7F 45 4C 46 }
   condition:
      $ELFheader and 1 of ($goLinux*) and 1 of ($GOMAXPROCS*)
}
