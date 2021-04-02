/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


//Rules reorganized/sorted by Sort_Rules on 2021-04-01



rule ASPXspy2 {
	meta:
		description = "Web shell - file ASPXspy2.aspx"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/24"
		hash = "5642387d92139bfe9ae11bfef6bfe0081dcea197"
	strings:
		$s0 = "string iVDT=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin" ascii
		$s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
		$s3 = "Process[] p=Process.GetProcesses();" fullword ascii
		$s4 = "Response.Cookies.Add(new HttpCookie(vbhLn,Password));" fullword ascii
		$s5 = "[DllImport(\"kernel32.dll\",EntryPoint=\"GetDriveTypeA\")]" fullword ascii
		$s6 = "<p>ConnString : <asp:TextBox id=\"MasR\" style=\"width:70%;margin:0 8px;\" CssCl" ascii
		$s7 = "ServiceController[] kQmRu=System.ServiceProcess.ServiceController.GetServices();" fullword ascii
		$s8 = "Copyright &copy; 2009 Bin -- <a href=\"http://www.rootkit.net.cn\" target=\"_bla" ascii
		$s10 = "Response.AddHeader(\"Content-Disposition\",\"attachment;filename=\"+HttpUtility." ascii
		$s11 = "nxeDR.Command+=new CommandEventHandler(this.iVk);" fullword ascii
		$s12 = "<%@ import Namespace=\"System.ServiceProcess\"%>" fullword ascii
		$s13 = "foreach(string innerSubKey in sk.GetSubKeyNames())" fullword ascii
		$s17 = "Response.Redirect(\"http://www.rootkit.net.cn\");" fullword ascii
		$s20 = "else if(Reg_Path.StartsWith(\"HKEY_USERS\"))" fullword ascii
	condition:
		6 of them
}

