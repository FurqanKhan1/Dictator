Sub Main()
    Dim SavePath
    Dim Subject
    Dim FileExtension
    Dim counter
           Dim objFileToWrite
    Dim list
    Set list = CreateObject("System.Collections.ArrayList")
    Set objOutlook = CreateObject("Outlook.Application")
    Set objNamespace = objOutlook.GetNamespace("MAPI")
    Set objFolder = objNamespace.GetDefaultFolder(6)
    Set colItems = objFolder.Items
    counter=0
    For Each objMessage In colItems
        Dim sub_str
        sub_str = Mid(objMessage.Body,1,150)
        sub_str=sub_str & "**###**###"
        list.Add "Subject : " & objMessage.Subject & "Body : " & sub_str
    Next
    list.Reverse
    Set objFileToWrite = CreateObject("Scripting.FileSystemObject").OpenTextFile("D:\emails.txt",8,true)     
    For Each subj In list
        'WScript.Echo subj
        objFileToWrite.WriteLine(subj)
        counter=counter+1
        If counter > 10 Then
                Exit For 
        End If
    Next

   objFileToWrite.Close
   Set objFileToWrite = Nothing
 
End Sub
Main()
