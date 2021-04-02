/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


//Rules reorganized/sorted by Sort_Rules on 2021-04-01


rule webshell_asp_cmd : webshell {
	meta:
		description = "Web Shell - file cmd.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "895ca846858c315a3ff8daa7c55b3119"
	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
		$s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
		$s3 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
	condition:
		1 of them
}


rule webshell_caidao_shell_ice  : webshell{
	meta:
		description = "Web Shell - file ice.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "6560b436d3d3bb75e2ef3f032151d139"
	strings:
		$s0 = "<%eval request(\"ice\")%>" fullword
	condition:
		all of them
}


rule webshell_asp_shell : webshell {
	meta:
		description = "Web Shell - file shell.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "e63f5a96570e1faf4c7b8ca6df750237"
	strings:
		$s7 = "<input type=\"submit\" name=\"Send\" value=\"GO!\">" fullword
		$s8 = "<TEXTAREA NAME=\"1988\" ROWS=\"18\" COLS=\"78\"></TEXTAREA>" fullword
	condition:
		all of them
}


rule webshell_asp_EFSO_2 {
	meta:
		description = "Web Shell - file EFSO_2.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a341270f9ebd01320a7490c12cb2e64c"
	strings:
		$s0 = "%8@#@&P~,P,PP,MV~4BP^~,NS~m~PXc3,_PWbSPU W~~[u3Fffs~/%@#@&~~,PP~~,M!PmS,4S,mBPNB"
	condition:
		all of them
}


rule webshell_Server_Variables {
	meta:
		description = "Web Shell - file Server Variables.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "47fb8a647e441488b30f92b4d39003d7"
	strings:
		$s7 = "<% For Each Vars In Request.ServerVariables %>" fullword
		$s9 = "Variable Name</B></font></p>" fullword
	condition:
		all of them
}


rule webshell_caidao_shell_mdb {
	meta:
		description = "Web Shell - file mdb.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "fbf3847acef4844f3a0d04230f6b9ff9"
	strings:
		$s1 = "<% execute request(\"ice\")%>a " fullword
	condition:
		all of them
}


rule webshell_asp_ice {
	meta:
		description = "Web Shell - file ice.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d141e011a92f48da72728c35f1934a2b"
	strings:
		$s0 = "D,'PrjknD,J~[,EdnMP[,-4;DS6@#@&VKobx2ldd,'~JhC"
	condition:
		all of them
}


rule webshell_DarkBlade1_3_asp_indexx {
	meta:
		description = "Web Shell - file indexx.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b7f46693648f534c2ca78e3f21685707"
	strings:
		$s3 = "Const strs_toTransform=\"command|Radmin|NTAuThenabled|FilterIp|IISSample|PageCou"
	condition:
		all of them
}


rule webshell_asp_01 {
	meta:
		description = "Web Shell - file 01.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 50
		hash = "61a687b0bea0ef97224c7bd2df118b87"
	strings:
		$s0 = "<%eval request(\"pass\")%>" fullword
	condition:
		all of them
}


rule webshell_asp_404 {
	meta:
		description = "Web Shell - file 404.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d9fa1e8513dbf59fa5d130f389032a2d"
	strings:
		$s0 = "lFyw6pd^DKV^4CDRWmmnO1GVKDl:y& f+2"
	condition:
		all of them
}


rule webshell_cmd_asp_5_1 {
	meta:
		description = "Web Shell - file cmd-asp-5.1.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "8baa99666bf3734cbdfdd10088e0cd9f"
	strings:
		$s9 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword
	condition:
		all of them
}


rule webshell_ASP_aspydrv {
	meta:
		description = "Web Shell - file aspydrv.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "de0a58f7d1e200d0b2c801a94ebce330"
	strings:
		$s3 = "<%=thingy.DriveLetter%> </td><td><tt> <%=thingy.DriveType%> </td><td><tt> <%=thi"
	condition:
		all of them
}


rule webshell_asp_ntdaddy {
	meta:
		description = "Web Shell - file ntdaddy.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "c5e6baa5d140f73b4e16a6cfde671c68"
	strings:
		$s9 =  "if  FP  =  \"RefreshFolder\"  or  "
		$s10 = "request.form(\"cmdOption\")=\"DeleteFolder\"  "
	condition:
		1 of them
}


rule webshell_elmaliseker_2 {
	meta:
		description = "Web Shell - file elmaliseker.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b32d1730d23a660fd6aa8e60c3dc549f"
	strings:
		$s1 = "<td<%if (FSO.GetExtensionName(path & \"\\\" & oFile.Name)=\"lnk\") or (FSO.GetEx"
		$s6 = "<input type=button value=Save onclick=\"EditorCommand('Save')\"> <input type=but"
	condition:
		all of them
}


rule webshell_ASP_RemExp {
	meta:
		description = "Web Shell - file RemExp.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "aa1d8491f4e2894dbdb91eec1abc2244"
	strings:
		$s0 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Reques"
		$s1 = "Private Function ConvertBinary(ByVal SourceNumber, ByVal MaxValuePerIndex, ByVal"
	condition:
		all of them
}


rule webshell_asp_1 {
	meta:
		description = "Web Shell - file 1.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "8991148adf5de3b8322ec5d78cb01bdb"
	strings:
		$s4 = "!22222222222222222222222222222222222222222222222222" fullword
		$s8 = "<%eval request(\"pass\")%>" fullword
	condition:
		all of them
}


rule webshell_ASP_tool {
	meta:
		description = "Web Shell - file tool.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "4ab68d38527d5834e9c1ff64407b34fb"
	strings:
		$s0 = "Response.Write \"<FORM action=\"\"\" & Request.ServerVariables(\"URL\") & \"\"\""
		$s3 = "Response.Write \"<tr><td><font face='arial' size='2'><b>&lt;DIR&gt; <a href='\" "
		$s9 = "Response.Write \"<font face='arial' size='1'><a href=\"\"#\"\" onclick=\"\"javas"
	condition:
		2 of them
}


rule webshell_ASP_zehir4 {
	meta:
		description = "Web Shell - file zehir4.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "7f4e12e159360743ec016273c3b9108c"
	strings:
		$s9 = "Response.Write \"<a href='\"&dosyaPath&\"?status=7&Path=\"&Path&\"/"
	condition:
		all of them
}


rule webshell_mumaasp_com {
	meta:
		description = "Web Shell - file mumaasp.com.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "cce32b2e18f5357c85b6d20f564ebd5d"
	strings:
		$s0 = "&9K_)P82ai,A}I92]R\"q!C:RZ}S6]=PaTTR"
	condition:
		all of them
}


rule webshell_asp_up {
	meta:
		description = "Web Shell - file up.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "f775e721cfe85019fe41c34f47c0d67c"
	strings:
		$s0 = "Pos = InstrB(BoundaryPos,RequestBin,getByteString(\"Content-Dispositio"
		$s1 = "ContentType = getString(MidB(RequestBin,PosBeg,PosEnd-PosBeg))" fullword
	condition:
		1 of them
}


rule webshell_ASP_cmd {
	meta:
		description = "Web Shell - file cmd.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "97af88b478422067f23b001dd06d56a9"
	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
	condition:
		all of them
}


rule webshell_ASP_zehir {
	meta:
		description = "Web Shell - file zehir.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "0061d800aee63ccaf41d2d62ec15985d"
	strings:
		$s9 = "Response.Write \"<font face=wingdings size=3><a href='\"&dosyaPath&\"?status=18&"
	condition:
		all of them
}


rule webshell_redirect {
	meta:
		description = "Web Shell - file redirect.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "97da83c6e3efbba98df270cc70beb8f8"
	strings:
		$s7 = "var flag = \"?txt=\" + (document.getElementById(\"dl\").checked ? \"2\":\"1\" "
	condition:
		all of them
}


rule webshell_asp_1d {
	meta:
		description = "Web Shell - file 1d.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "fad7504ca8a55d4453e552621f81563c"
	strings:
		$s0 = "+9JkskOfKhUxZJPL~\\(mD^W~[,{@#@&EO"
	condition:
		all of them
}


rule webshell_asp_ajn {
	meta:
		description = "Web Shell - file ajn.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "aaafafc5d286f0bff827a931f6378d04"
	strings:
		$s1 = "seal.write \"Set WshShell = CreateObject(\"\"WScript.Shell\"\")\" & vbcrlf" fullword
		$s6 = "seal.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreateOve"
	condition:
		all of them
}


rule webshell_asp_list {
	meta:
		description = "Web Shell - file list.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "1cfa493a165eb4b43e6d4cc0f2eab575"
	strings:
		$s0 = "<INPUT TYPE=\"hidden\" NAME=\"type\" value=\"<%=tipo%>\">" fullword
		$s4 = "Response.Write(\"<h3>FILE: \" & file & \"</h3>\")" fullword
	condition:
		all of them
}


rule webshell_asp_dabao {
	meta:
		description = "Web Shell - file dabao.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "3919b959e3fa7e86d52c2b0a91588d5d"
	strings:
		$s2 = " Echo \"<input type=button name=Submit onclick=\"\"document.location =&#039;\" &"
		$s8 = " Echo \"document.Frm_Pack.FileName.value=\"\"\"\"+year+\"\"-\"\"+(month+1)+\"\"-"
	condition:
		all of them
}


rule webshell_asp_cmdasp {
	meta:
		description = "Web Shell - file cmdasp.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "57b51418a799d2d016be546f399c2e9b"
	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
		$s7 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
	condition:
		all of them
}


rule webshell_Inderxer {
	meta:
		description = "Web Shell - file Inderxer.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "9ea82afb8c7070817d4cdf686abe0300"
	strings:
		$s4 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ"
	condition:
		all of them
}


rule webshell_asp_Rader {
	meta:
		description = "Web Shell - file Rader.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ad1a362e0a24c4475335e3e891a01731"
	strings:
		$s1 = "FONT-WEIGHT: bold; FONT-SIZE: 10px; BACKGROUND: none transparent scroll repeat 0"
		$s3 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 "
	condition:
		all of them
}


rule webshell_ELMALISEKER_Backd00r {
	meta:
		description = "Web Shell - file ELMALISEKER Backd00r.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "3aa403e0a42badb2c23d4a54ef43e2f4"
	strings:
		$s0 = "response.write(\"<tr><td bgcolor=#F8F8FF><input type=submit name=cmdtxtFileOptio"
		$s2 = "if FP = \"RefreshFolder\" or request.form(\"cmdOption\")=\"DeleteFolder\" or req"
	condition:
		all of them
}


rule webshell_caidao_shell_hkmjj {
	meta:
		description = "Web Shell - file hkmjj.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "e7b994fe9f878154ca18b7cde91ad2d0"
	strings:
		$s6 = "codeds=\"Li#uhtxhvw+%{{%,#@%{%#wkhq#hydo#uhtxhvw+%knpmm%,#hqg#li\"  " fullword
	condition:
		all of them
}


rule webshell_asp_Ajan {
	meta:
		description = "Web Shell - file Ajan.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b6f468252407efc2318639da22b08af0"
	strings:
		$s3 = "entrika.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreate"
	condition:
		all of them
}



rule webshell_webshells_new_con2 {
	meta:
		description = "Web shells - generated from file con2.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "d3584159ab299d546bd77c9654932ae3"
	strings:
		$s7 = ",htaPrewoP(ecalper=htaPrewoP:fI dnE:0=KOtidE:1 - eulaVtni = eulaVtni:nehT 1 => e"
		$s10 = "j \"<Form action='\"&URL&\"?Action2=Post' method='post' name='EditForm'><input n"
	condition:
		1 of them
}


rule webshell_webshells_new_aaa {
	meta:
		description = "Web shells - generated from file aaa.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "68483788ab171a155db5266310c852b2"
	strings:
		$s0 = "Function fvm(jwv):If jwv=\"\"Then:fvm=jwv:Exit Function:End If:Dim tt,sru:tt=\""
		$s5 = "<option value=\"\"DROP TABLE [jnc];exec mast\"&kvp&\"er..xp_regwrite 'HKEY_LOCAL"
		$s17 = "if qpv=\"\" then qpv=\"x:\\Program Files\\MySQL\\MySQL Server 5.0\\my.ini\"&br&"
	condition:
		1 of them
}


rule webshell_Expdoor_com_ASP {
	meta:
		description = "Web shells - generated from file Expdoor.com ASP.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "caef01bb8906d909f24d1fa109ea18a7"
	strings:
		$s4 = "\">www.Expdoor.com</a>" fullword
		$s5 = "    <input name=\"FileName\" type=\"text\" value=\"Asp_ver.Asp\" size=\"20\" max"
		$s10 = "set file=fs.OpenTextFile(server.MapPath(FileName),8,True)  '" fullword
		$s14 = "set fs=server.CreateObject(\"Scripting.FileSystemObject\")   '" fullword
		$s16 = "<TITLE>Expdoor.com ASP" fullword
	condition:
		2 of them
}


rule webshell_bypass_iisuser_p {
	meta:
		description = "Web shells - generated from file bypass-iisuser-p.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "924d294400a64fa888a79316fb3ccd90"
	strings:
		$s0 = "<%Eval(Request(chr(112))):Set fso=CreateObject"
	condition:
		all of them
}


rule webshell_webshells_new_radhat {
	meta:
		description = "Web shells - generated from file radhat.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "72cb5ef226834ed791144abaa0acdfd4"
	strings:
		$s1 = "sod=Array(\"D\",\"7\",\"S"
	condition:
		all of them
}


rule webshell_webshells_new_asp1 {
	meta:
		description = "Web shells - generated from file asp1.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "b63e708cd58ae1ec85cf784060b69cad"
	strings:
		$s0 = " http://www.baidu.com/fuck.asp?a=)0(tseuqer%20lave " fullword
		$s2 = " <% a=request(chr(97)) ExecuteGlobal(StrReverse(a)) %>" fullword
	condition:
		1 of them
}


rule webshell_webshells_new_Asp {
	meta:
		description = "Web shells - generated from file Asp.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "32c87744ea404d0ea0debd55915010b7"
	strings:
		$s1 = "Execute MorfiCoder(\")/*/z/*/(tseuqer lave\")" fullword
		$s2 = "Function MorfiCoder(Code)" fullword
		$s3 = "MorfiCoder=Replace(Replace(StrReverse(Code),\"/*/\",\"\"\"\"),\"\\*\\\",vbCrlf)" fullword
	condition:
		1 of them
}


rule Tool_asp {
	meta:
		description = "Semi-Auto-generated  - file Tool.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8febea6ca6051ae5e2ad4c78f4b9c1f2"
	strings:
		$s0 = "mailto:rhfactor@antisocial.com"
		$s2 = "?raiz=root"
		$s3 = "DIGO CORROMPIDO<BR>CORRUPT CODE"
		$s4 = "key = \"5DCADAC1902E59F7273E1902E5AD8414B1902E5ABF3E661902E5B554FC41902E53205CA0"
	condition:
		2 of them
}


rule NT_Addy_asp {
	meta:
		description = "Semi-Auto-generated  - file NT Addy.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2e0d1bae844c9a8e6e351297d77a1fec"
	strings:
		$s0 = "NTDaddy v1.9 by obzerve of fux0r inc"
		$s2 = "<ERROR: THIS IS NOT A TEXT FILE>"
		$s4 = "RAW D.O.S. COMMAND INTERFACE"
	condition:
		1 of them
}


rule RemExp_asp {
	meta:
		description = "Semi-Auto-generated  - file RemExp.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "aa1d8491f4e2894dbdb91eec1abc2244"
	strings:
		$s0 = "<title>Remote Explorer</title>"
		$s3 = " FSO.CopyFile Request.QueryString(\"FolderPath\") & Request.QueryString(\"CopyFi"
		$s4 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f"
	condition:
		2 of them
}


rule klasvayv_asp {
	meta:
		description = "Semi-Auto-generated  - file klasvayv.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2b3e64bf8462fc3d008a3d1012da64ef"
	strings:
		$s1 = "set aktifklas=request.querystring(\"aktifklas\")"
		$s2 = "action=\"klasvayv.asp?klasorac=1&aktifklas=<%=aktifklas%>&klas=<%=aktifklas%>"
		$s3 = "<font color=\"#858585\">www.aventgrup.net"
		$s4 = "style=\"BACKGROUND-COLOR: #95B4CC; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT"
	condition:
		1 of them
}


rule CmdAsp_asp {
	meta:
		description = "Semi-Auto-generated  - file CmdAsp.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "64f24f09ec6efaa904e2492dffc518b9"
	strings:
		$s0 = "CmdAsp.asp"
		$s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
		$s2 = "-- Use a poor man's pipe ... a temp file --"
		$s3 = "maceo @ dogmile.com"
	condition:
		2 of them
}


rule Reader_asp {
	meta:
		description = "Semi-Auto-generated  - file Reader.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "ad1a362e0a24c4475335e3e891a01731"
	strings:
		$s1 = "Mehdi & HolyDemon"
		$s2 = "www.infilak."
		$s3 = "'*T@*r@#@&mms^PdbYbVuBcAAA==^#~@%><form method=post name=inf><table width=\"75%"
	condition:
		2 of them
}


rule elmaliseker_asp {
	meta:
		description = "Semi-Auto-generated  - file elmaliseker.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b32d1730d23a660fd6aa8e60c3dc549f"
	strings:
		$s0 = "if Int((1-0+1)*Rnd+0)=0 then makeEmail=makeText(8) & \"@\" & makeText(8) & \".\""
		$s1 = "<form name=frmCMD method=post action=\"<%=gURL%>\">"
		$s2 = "dim zombie_array,special_array"
		$s3 = "http://vnhacker.org"
	condition:
		1 of them
}


rule indexer_asp {
	meta:
		description = "Semi-Auto-generated  - file indexer.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "9ea82afb8c7070817d4cdf686abe0300"
	strings:
		$s0 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ"
		$s2 = "D7nD7l.km4snk`JzKnd{n_ejq;bd{KbPur#kQ8AAA==^#~@%>></td><td><input type=\"submit"
	condition:
		1 of them
}


rule kacak_asp {
	meta:
		description = "Semi-Auto-generated  - file kacak.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "907d95d46785db21331a0324972dda8c"
	strings:
		$s0 = "Kacak FSO 1.0"
		$s1 = "if request.querystring(\"TGH\") = \"1\" then"
		$s3 = "<font color=\"#858585\">BuqX</font></a></font><font face=\"Verdana\" style="
		$s4 = "mailto:BuqX@hotmail.com"
	condition:
		1 of them
}


rule cmd_asp_5_1_asp {
	meta:
		description = "Semi-Auto-generated  - file cmd-asp-5.1.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8baa99666bf3734cbdfdd10088e0cd9f"
	strings:
		$s0 = "Call oS.Run(\"win.com cmd.exe /c del \"& szTF,0,True)" fullword
		$s3 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword
	condition:
		1 of them
}


rule EFSO_2_asp {
	meta:
		description = "Semi-Auto-generated  - file EFSO_2.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b5fde9682fd63415ae211d53c6bfaa4d"
	strings:
		$s0 = "Ejder was HERE"
		$s1 = "*~PU*&BP[_)f!8c2F*@#@&~,P~P,~P&q~8BPmS~9~~lB~X`V,_,F&*~,jcW~~[_c3TRFFzq@#@&PP,~~"
	condition:
		2 of them
}


rule Zehir_4_asp {
	meta:
		description = "Semi-Auto-generated  - file Zehir 4.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "7f4e12e159360743ec016273c3b9108c"
	strings:
		$s2 = "</a><a href='\"&dosyapath&\"?status=10&dPath=\"&f1.path&\"&path=\"&path&\"&Time="
		$s4 = "<input type=submit value=\"Test Et!\" onclick=\""
	condition:
		1 of them
}


rule aspydrv_asp {
	meta:
		description = "Semi-Auto-generated  - file aspydrv.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "1c01f8a88baee39aa1cebec644bbcb99"
		score = 60
	strings:
		$s0 = "If mcolFormElem.Exists(LCase(sIndex)) Then Form = mcolFormElem.Item(LCase(sIndex))"
		$s1 = "password"
		$s2 = "session(\"shagman\")="
	condition:
		2 of them
}


rule Ajan_asp {
	meta:
		description = "Semi-Auto-generated  - file Ajan.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b6f468252407efc2318639da22b08af0"
	strings:
		$s1 = "c:\\downloaded.zip"
		$s2 = "Set entrika = entrika.CreateTextFile(\"c:\\net.vbs\", True)" fullword
		$s3 = "http://www35.websamba.com/cybervurgun/"
	condition:
		1 of them
}



/* PHP Webshell Update - August 2014 - deducted from https://github.com/JohnTroony/php-webshells */

rule WebShell_RemExp_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file RemExp.asp.php.txt"
		author = "Florian Roth"
		hash = "d9919dcf94a70d5180650de8b81669fa1c10c5a2"
	strings:
		$s0 = "lsExt = Right(FileName, Len(FileName) - liCount)" fullword
		$s7 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f"
		$s13 = "Response.Write Drive.ShareName & \" [share]\"" fullword
		$s19 = "If Request.QueryString(\"CopyFile\") <> \"\" Then" fullword
		$s20 = "<td width=\"40%\" height=\"20\" bgcolor=\"silver\">  Name</td>" fullword
	condition:
		all of them
}


rule WebShell_indexer_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file indexer.asp.php.txt"
		author = "Florian Roth"
		hash = "e9a7aa5eb1fb228117dc85298c7d3ecd8e288a2d"
	strings:
		$s0 = "<meta http-equiv=\"Content-Language\" content=\"tr\">" fullword
		$s1 = "<title>WwW.SaNaLTeRoR.OrG - inDEXER And ReaDer</title>" fullword
		$s2 = "<form action=\"?Gonder\" method=\"post\">" fullword
		$s4 = "<form action=\"?oku\" method=\"post\">" fullword
		$s7 = "var message=\"SaNaLTeRoR - " fullword
		$s8 = "nDexEr - Reader\"" fullword
	condition:
		3 of them
}


rule WebShell_reader_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file reader.asp.php.txt"
		author = "Florian Roth"
		hash = "70656f3495e2b3ad391a77d5208eec0fb9e2d931"
	strings:
		$s5 = "ster\" name=submit> </Font> &nbsp; &nbsp; &nbsp; <a href=mailto:mailbomb@hotmail"
		$s12 = " HACKING " fullword
		$s16 = "FONT-WEIGHT: bold; BACKGROUND: #ffffff url('images/cellpic1.gif'); TEXT-INDENT: "
		$s20 = "PADDING-RIGHT: 8px; PADDING-LEFT: 8px; FONT-WEIGHT: bold; FONT-SIZE: 11px; BACKG"
	condition:
		3 of them
}


rule WebShell_CmdAsp_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file CmdAsp.asp.php.txt"
		author = "Florian Roth"
		hash = "cb18e1ac11e37e236e244b96c2af2d313feda696"
	strings:
		$s1 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword
		$s4 = "' Author: Maceo <maceo @ dogmile.com>" fullword
		$s5 = "' -- Use a poor man's pipe ... a temp file -- '" fullword
		$s6 = "' --------------------o0o--------------------" fullword
		$s8 = "' File: CmdAsp.asp" fullword
		$s11 = "<-- CmdAsp.asp -->" fullword
		$s14 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
		$s16 = "Set oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword
		$s19 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
	condition:
		4 of them
}


rule WebShell_php_webshells_aspydrv {
	meta:
		description = "PHP Webshells Github Archive - file aspydrv.php"
		author = "Florian Roth"
		hash = "3d8996b625025dc549d73cdb3e5fa678ab35d32a"
	strings:
		$s0 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files"
		$s1 = "nPos = InstrB(nPosEnd, biData, CByteString(\"Content-Type:\"))" fullword
		$s3 = "Document.frmSQL.mPage.value = Document.frmSQL.mPage.value - 1" fullword
		$s17 = "If request.querystring(\"getDRVs\")=\"@\" then" fullword
		$s20 = "' ---Copy Too Folder routine Start" fullword
	condition:
		3 of them
}


rule WebShell_webshells_zehir4 {
	meta:
		description = "Webshells Github Archive - file zehir4"
		author = "Florian Roth"
		hash = "788928ae87551f286d189e163e55410acbb90a64"
		score = 55
	strings:
		$s0 = "frames.byZehir.document.execCommand(command, false, option);" fullword
		$s8 = "response.Write \"<title>ZehirIV --> Powered By Zehir &lt;zehirhacker@hotmail.com"
	condition:
		1 of them
}


rule WebShell_zehir4_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file zehir4.asp.php.txt"
		author = "Florian Roth"
		hash = "1d9b78b5b14b821139541cc0deb4cbbd994ce157"
	strings:
		$s4 = "response.Write \"<title>zehir3 --> powered by zehir &lt;zehirhacker@hotmail.com&"
		$s11 = "frames.byZehir.document.execCommand("
		$s15 = "frames.byZehir.document.execCommand(co"
	condition:
		2 of them
}


rule WebShell__PH_Vayv_PHVayv_PH_Vayv_klasvayv_asp_php {
	meta:
		description = "PHP Webshells Github Archive - from files PH Vayv.php, PHVayv.php, PH_Vayv.php, klasvayv.asp.php.txt"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "b51962a1ffa460ec793317571fc2f46042fd13ee"
		hash1 = "408ac9ca3d435c0f78bda370b33e84ba25afc357"
		hash2 = "4003ae289e3ae036755976f8d2407c9381ff5653"
		hash3 = "4f83bc2836601225a115b5ad54496428a507a361"
	strings:
		$s1 = "<font color=\"#000000\">Sil</font></a></font></td>" fullword
		$s5 = "<td width=\"122\" height=\"17\" bgcolor=\"#9F9F9F\">" fullword
		$s6 = "onfocus=\"if (this.value == 'Kullan" fullword
		$s16 = "<img border=\"0\" src=\"http://www.aventgrup.net/arsiv/klasvayv/1.0/2.gif\">"
	condition:
		2 of them
}


rule HYTop_DevPack_fso {
	meta:
		description = "Webshells Auto-generated - file fso.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b37f3cde1a08890bd822a182c3a881f6"
	strings:
		$s0 = "<!-- PageFSO Below -->"
		$s1 = "theFile.writeLine(\"<script language=\"\"vbscript\"\" runat=server>if request(\"\"\"&cli"
	condition:
		all of them
}


rule HYTop_DevPack_config {
	meta:
		description = "Webshells Auto-generated - file config.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b41d0e64e64a685178a3155195921d61"
	strings:
		$s0 = "const adminPassword=\""
		$s2 = "const userPassword=\""
		$s3 = "const mVersion="
	condition:
		all of them
}


rule FSO_s_zehir4 {
	meta:
		description = "Webshells Auto-generated - file zehir4.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5b496a61363d304532bcf52ee21f5d55"
	strings:
		$s5 = " byMesaj "
	condition:
		all of them
}


rule FSO_s_reader {
	meta:
		description = "Webshells Auto-generated - file reader.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b598c8b662f2a1f6cc61f291fb0a6fa2"
	strings:
		$s2 = "mailto:mailbomb@hotmail."
	condition:
		all of them
}


rule ASP_CmdAsp {
	meta:
		description = "Webshells Auto-generated - file CmdAsp.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "79d4f3425f7a89befb0ef3bafe5e332f"
	strings:
		$s2 = "' -- Read the output from our command and remove the temp file -- '"
		$s6 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
		$s9 = "' -- create the COM objects that we will be using -- '"
	condition:
		all of them
}


rule HYTop_DevPack_server {
	meta:
		description = "Webshells Auto-generated - file server.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1d38526a215df13c7373da4635541b43"
	strings:
		$s0 = "<!-- PageServer Below -->"
	condition:
		all of them
}


rule admin_ad {
	meta:
		description = "Webshells Auto-generated - file admin-ad.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "e6819b8f8ff2f1073f7d46a0b192f43b"
	strings:
		$s6 = "<td align=\"center\"> <input name=\"cmd\" type=\"text\" id=\"cmd\" siz"
		$s7 = "Response.write\"<a href='\"&url&\"?path=\"&Request(\"oldpath\")&\"&attrib=\"&attrib&\"'><"
	condition:
		all of them
}


rule sig_2005Gray {
	meta:
		description = "Webshells Auto-generated - file 2005Gray.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "75dbe3d3b70a5678225d3e2d78b604cc"
	strings:
		$s0 = "SCROLLBAR-FACE-COLOR: #e8e7e7;"
		$s4 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
		$s8 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"
		$s9 = "SCROLLBAR-3DLIGHT-COLOR: #cccccc;"
	condition:
		all of them
}


rule FSO_s_cmd {
	meta:
		description = "Webshells Auto-generated - file cmd.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cbe8e365d41dd3cd8e462ca434cf385f"
	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>"
		$s1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
	condition:
		all of them
}


rule FSO_s_indexer {
	meta:
		description = "Webshells Auto-generated - file indexer.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "135fc50f85228691b401848caef3be9e"
	strings:
		$s3 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input type=\"r"
	condition:
		all of them
}


rule HYTop_DevPack_2005Red {
	meta:
		description = "Webshells Auto-generated - file 2005Red.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d8ccda2214b3f6eabd4502a050eb8fe8"
	strings:
		$s0 = "scrollbar-darkshadow-color:#FF9DBB;"
		$s3 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
		$s9 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"
	condition:
		all of them
}


rule elmaliseker {
	meta:
		description = "Webshells Auto-generated - file elmaliseker.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "ccf48af0c8c09bbd038e610a49c9862e"
	strings:
		$s0 = "javascript:Command('Download'"
		$s5 = "zombie_array=array("
	condition:
		all of them
}


rule FSO_s_RemExp {
	meta:
		description = "Webshells Auto-generated - file RemExp.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b69670ecdbb40012c73686cd22696eeb"
	strings:
		$s1 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Request.Ser"
		$s5 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f=<%=F"
		$s6 = "<td bgcolor=\"<%=BgColor%>\" align=\"right\"><%=Attributes(SubFolder.Attributes)%></"
	condition:
		all of them
}


rule FSO_s_tool {
	meta:
		description = "Webshells Auto-generated - file tool.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3a1e1e889fdd974a130a6a767b42655b"
	strings:
		$s7 = "\"\"%windir%\\\\calc.exe\"\")"
	condition:
		all of them
}


rule FSO_s_ntdaddy {
	meta:
		description = "Webshells Auto-generated - file ntdaddy.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f6262f3ad9f73b8d3e7d9ea5ec07a357"
	strings:
		$s1 = "<input type=\"text\" name=\".CMD\" size=\"45\" value=\"<%= szCMD %>\"> <input type=\"s"
	condition:
		all of them
}


rule HYTop_DevPack_upload {
	meta:
		description = "Webshells Auto-generated - file upload.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b09852bda534627949f0259828c967de"
	strings:
		$s0 = "<!-- PageUpload Below -->"
	condition:
		all of them
}


rule FSO_s_RemExp_2 {
	meta:
		description = "Webshells Auto-generated - file RemExp.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b69670ecdbb40012c73686cd22696eeb"
	strings:
		$s2 = " Then Response.Write \""
		$s3 = "<a href= \"<%=Request.ServerVariables(\"script_name\")%>"
	condition:
		all of them
}


rule commands {
	meta:
		description = "Webshells Auto-generated - file commands.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "174486fe844cb388e2ae3494ac2d1ec2"
	strings:
		$s1 = "If CheckRecord(\"SELECT COUNT(ID) FROM VictimDetail WHERE VictimID = \" & VictimID"
		$s2 = "proxyArr = Array (\"HTTP_X_FORWARDED_FOR\",\"HTTP_VIA\",\"HTTP_CACHE_CONTROL\",\"HTTP_F"
	condition:
		all of them
}


rule FSO_s_EFSO_2 {
	meta:
		description = "Webshells Auto-generated - file EFSO_2.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a341270f9ebd01320a7490c12cb2e64c"
	strings:
		$s0 = ";!+/DRknD7+.\\mDrC(V+kcJznndm\\f|nzKuJb'r@!&0KUY@*Jb@#@&Xl\"dKVcJ\\CslU,),@!0KxD~mKV"
		$s4 = "\\co!VV2CDtSJ'E*#@#@&mKx/DP14lM/nY{JC81N+6LtbL3^hUWa;M/OE-AXX\"b~/fAs!u&9|J\\grKp\"j"
	condition:
		all of them
}


rule HYTop_AppPack_2005 {
	meta:
		description = "Webshells Auto-generated - file 2005.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "63d9fd24fa4d22a41fc5522fc7050f9f"
	strings:
		$s6 = "\" onclick=\"this.form.sqlStr.value='e:\\hytop.mdb"
	condition:
		all of them
}


rule xssshell {
	meta:
		description = "Webshells Auto-generated - file xssshell.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8fc0ffc5e5fbe85f7706ffc45b3f79b4"
	strings:
		$s1 = "if( !getRequest(COMMANDS_URL + \"?v=\" + VICTIM + \"&r=\" + generateID(), \"pushComma"
	condition:
		all of them
}


rule xssshell_db {
	meta:
		description = "Webshells Auto-generated - file db.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "cb62e2ec40addd4b9930a9e270f5b318"
	strings:
		$s8 = "'// By Ferruh Mavituna | http://ferruh.mavituna.com"
	condition:
		all of them
}


rule xssshell_default {
	meta:
		description = "Webshells Auto-generated - file default.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d156782ae5e0b3724de3227b42fcaf2f"
	strings:
		$s3 = "If ProxyData <> \"\" Then ProxyData = Replace(ProxyData, DATA_SEPERATOR, \"<br />\")"
	condition:
		all of them
}


rule fmlibraryv3 {
	meta:
		description = "Webshells Auto-generated - file fmlibraryv3.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "c34c248fed6d5a20d8203924a2088acc"
	strings:
		$s3 = "ExeNewRs.CommandText = \"UPDATE \" & tablename & \" SET \" & ExeNewRsValues & \" WHER"
	condition:
		all of them
}


rule connector {
	meta:
		description = "Webshells Auto-generated - file connector.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3ba1827fca7be37c8296cd60be9dc884"
	strings:
		$s2 = "If ( AttackID = BROADCAST_ATTACK )"
		$s4 = "Add UNIQUE ID for victims / zombies"
	condition:
		all of them
}


rule xssshell_save {
	meta:
		description = "Webshells Auto-generated - file save.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "865da1b3974e940936fe38e8e1964980"
	strings:
		$s4 = "RawCommand = Command & COMMAND_SEPERATOR & Param & COMMAND_SEPERATOR & AttackID"
		$s5 = "VictimID = fm_NStr(Victims(i))"
	condition:
		all of them
}


rule FSO_s_ajan {
	meta:
		description = "Webshells Auto-generated - file ajan.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "22194f8c44524f80254e1b5aec67b03e"
	strings:
		$s4 = "entrika.write \"BinaryStream.SaveToFile"
	condition:
		all of them
}


rule FSO_s_zehir4_2 {
	meta:
		description = "Webshells Auto-generated - file zehir4.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "5b496a61363d304532bcf52ee21f5d55"
	strings:
		$s4 = "\"Program Files\\Serv-u\\Serv"
	condition:
		all of them
}


rule FSO_s_indexer_2 {
	meta:
		description = "Webshells Auto-generated - file indexer.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "135fc50f85228691b401848caef3be9e"
	strings:
		$s5 = "<td>Nerden :<td><input type=\"text\" name=\"nerden\" size=25 value=index.html></td>"
	condition:
		all of them
}


rule HYTop_DevPack_2005 {
	meta:
		description = "Webshells Auto-generated - file 2005.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "63d9fd24fa4d22a41fc5522fc7050f9f"
	strings:
		$s7 = "theHref=encodeForUrl(mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\")"
		$s8 = "scrollbar-darkshadow-color:#9C9CD3;"
		$s9 = "scrollbar-face-color:#E4E4F3;"
	condition:
		all of them
}


rule icyfox007v1_10_rar_Folder_asp {
	meta:
		description = "Webshells Auto-generated - file asp.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2c412400b146b7b98d6e7755f7159bb9"
	strings:
		$s0 = "<SCRIPT RUNAT=SERVER LANGUAGE=JAVASCRIPT>eval(Request.form('#')+'')</SCRIPT>"
	condition:
		all of them
}


rule FSO_s_EFSO_2_2 {
	meta:
		description = "Webshells Auto-generated - file EFSO_2.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a341270f9ebd01320a7490c12cb2e64c"
	strings:
		$s0 = ";!+/DRknD7+.\\mDrC(V+kcJznndm\\f|nzKuJb'r@!&0KUY@*Jb@#@&Xl\"dKVcJ\\CslU,),@!0KxD~mKV"
		$s4 = "\\co!VV2CDtSJ'E*#@#@&mKx/DP14lM/nY{JC81N+6LtbL3^hUWa;M/OE-AXX\"b~/fAs!u&9|J\\grKp\"j"
	condition:
		all of them
}


rule down_rar_Folder_down {
	meta:
		description = "Webshells Auto-generated - file down.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "db47d7a12b3584a2e340567178886e71"
	strings:
		$s0 = "response.write \"<font color=blue size=2>NetBios Name: \\\\\"  & Snet.ComputerName &"
	condition:
		all of them
}


rule cmdShell {
	meta:
		description = "Webshells Auto-generated - file cmdShell.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8a9fef43209b5d2d4b81dfbb45182036"
	strings:
		$s1 = "if cmdPath=\"wscriptShell\" then"
	condition:
		all of them
}


rule HYTop2006_rar_Folder_2006 {
	meta:
		description = "Webshells Auto-generated - file 2006.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "c19d6f4e069188f19b08fa94d44bc283"
	strings:
		$s6 = "strBackDoor = strBackDoor "
	condition:
		all of them
}


rule FSO_s_ajan_2 {
	meta:
		description = "Webshells Auto-generated - file ajan.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "22194f8c44524f80254e1b5aec67b03e"
	strings:
		$s2 = "\"Set WshShell = CreateObject(\"\"WScript.Shell\"\")"
		$s3 = "/file.zip"
	condition:
		all of them
}



rule Webshell_Insomnia {
	meta:
		description = "Insomnia Webshell - file InsomniaShell.aspx"
		author = "Florian Roth"
		reference = "http://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/"
		date = "2014/12/09"
		hash = "e0cfb2ffaa1491aeaf7d3b4ee840f72d42919d22"
		score = 80
	strings:
		$s0 = "Response.Write(\"- Failed to create named pipe:\");" fullword ascii
		$s1 = "Response.Output.Write(\"+ Sending {0}<br>\", command);" fullword ascii
		$s2 = "String command = \"exec master..xp_cmdshell 'dir > \\\\\\\\127.0.0.1" ascii
		$s3 = "Response.Write(\"- Error Getting User Info<br>\");" fullword ascii
		$s4 = "string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes," fullword ascii
		$s5 = "[DllImport(\"Advapi32.dll\", SetLastError = true)]" fullword ascii
		$s9 = "username = DumpAccountSid(tokUser.User.Sid);" fullword ascii
		$s14 = "//Response.Output.Write(\"Opened process PID: {0} : {1}<br>\", p" ascii
	condition:
		3 of them
}



rule Webshell_zehir {
	meta:
		description = "Detects Webshell - rule generated from from files elmaliseker.asp, zehir.asp, zehir.txt, zehir4.asp, zehir4.txt"
		author = "Florian Roth"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "16e1e886576d0c70af0f96e3ccedfd2e72b8b7640f817c08a82b95ff5d4b1218"
		hash2 = "0c5f8a2ed62d10986a2dd39f52886c0900a18c03d6d279207b8de8e2ed14adf6"
		hash3 = "cb9d5427a83a0fc887e49f07f20849985bd2c3850f272ae1e059a08ac411ff66"
		hash4 = "b57bf397984545f419045391b56dcaf7b0bed8b6ee331b5c46cee35c92ffa13d"
		hash5 = "febf37a9e8ba8ece863f506ae32ad398115106cc849a9954cbc0277474cdba5c"
	strings:
		$s1 = "for (i=1; i<=frmUpload.max.value; i++) str+='File '+i+': <input type=file name=file'+i+'><br>';" fullword ascii
		$s2 = "if (frmUpload.max.value<=0) frmUpload.max.value=1;" fullword ascii
	condition:
		filesize < 200KB and 1 of them
}

