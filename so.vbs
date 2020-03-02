function send_email()
   Set objOutlook = CreateObject("Outlook.Application")
   Set objMail = objOutlook.CreateItem(0)
   objMail.Display   'To display message
   objMail.To = ""
   objMail.cc = ""
   objMail.Subject = "Confidential"
   objMail.Body = "This is with regards to my resignation ..."
   objMail.Send  
   Set objMail = Nothing
   Set objOutlook = Nothing
end function

send_email()
