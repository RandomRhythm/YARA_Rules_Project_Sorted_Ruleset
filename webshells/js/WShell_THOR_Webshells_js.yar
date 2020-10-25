/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


//Rules reorganized/sorted by Sort_Rules on 2020-09-20


rule Java_Shell_js {
	meta:
		description = "Semi-Auto-generated  - file Java Shell.js.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "36403bc776eb12e8b7cc0eb47c8aac83"
	strings:
		$s2 = "PySystemState.initialize(System.getProperties(), null, argv);" fullword
		$s3 = "public class JythonShell extends JPanel implements Runnable {" fullword
		$s4 = "public static int DEFAULT_SCROLLBACK = 100"
	condition:
		2 of them
}



rule AJAX_FileUpload_webshell {
	meta:
		description = "AJAX JS/CSS components providing web shell by APT groups"
		author = "F.Roth"
		date = "12.10.2014"
		score = 75
		reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/ajaxfileupload.js"
	strings:
		$a1 = "var frameId = 'jUploadFrame' + id;" ascii
		$a2 = "var form = jQuery('<form  action=\"\" method=\"POST\" name=\"' + formId + '\" id=\"' + formId + '\" enctype=\"multipart/form-data\"></form>');" ascii
		$a3 = "jQuery(\"<div>\").html(data).evalScripts();" ascii
	condition:
		all of them
}

