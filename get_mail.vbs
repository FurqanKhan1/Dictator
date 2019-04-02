Sub Main()
    	Dim SavePath
	Dim Subject
	Dim FileExtension
	'Dim counter as integer
	SavePath = "C:\IN\"
	Subject = "'Transfer File'"
	FileExtension = "ARmessage"

	Set objOutlook = CreateObject("Outlook.Application")
	Set objNamespace = objOutlook.GetNamespace("MAPI")
	Set objFolder = objNamespace.GetDefaultFolder(6) 'Inbox

	Set colItems = objFolder.Items
	'Set counter=0
	For Each objMessage In colItems
		WScript.Echo objMessage.Body
		Exit For

    		
	Next
End Sub

Main()
