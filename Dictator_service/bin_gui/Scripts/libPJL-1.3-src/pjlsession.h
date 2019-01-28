/* PJL session class 
 * The main object !
 * $Id: pjlsession.h,v 1.6 2005/04/21 07:37:28 fx Exp fx $ 
 */
#ifndef __PJLSESSION_H__
#define __PJLSESSION_H__

#include "tcpcon.h"
#include "pjllists.h"
#include "fxstrings.h"


#define DEFAULT_CTIMEOUT		20
#define DEFAULT_FTIMEOUT		2


class PJLsession: public BaseExceptions {
	public:
		// environment variable list object
		PJLenv		env;
		// volume list 
		PJLvol		vol;
		// directory listing
		PJLfile		dir;
		// file transfer
		Rawmem		filebuffer;

		// timeouts
		unsigned int	ctimeout;
		unsigned int	ftimeout;

		// contructor
		PJLsession();
		// destructor
		~PJLsession();

		// initiate() method initiates a connection to 
		// a PJL device. 
		void initiate(char *host, unsigned int port);
		// closes the connection
		void close(void);
		// simply returns connection.is_connected
		bool connected(void);

		// sets USTATUS variable
		void write_ustatus(char *str);
		// disables the PJL security password 
		// method returns true for successfull disabling the password
		// or false for failed action (password was wrong)
		bool disable_pjl_password(unsigned int pass);
		// disables the PJL security password - but does not
		// validate the result. Discards whatever is send as answer
		// Designed for brute force attack.
		void blind_disable_pjl_password(unsigned int pass);
		// returns the status of PJL security
		bool chk_pjl_password(void);
		// reads the printer environment variables 
		// via the INFO VARIABLES PJL command and stores them
		// in env 
		void read_env(void);
		// writes changed env variables back
		void env_commit_changes(void);
		
		// reads and stores the Devices ID
		void read_device_id(void);
		// sets the ready message on device
		void write_ready_message(char *m);
		// sets an error message on device
		void write_failure_message(char *m);

		// reads the volume information from device
		void read_volumes(void);
		// reads an directory into the dir list
		// this method expects an absolute directory 
		// path like 0:\\webserver\\bla
		// it also updates pwd (which can be see by get_pwd()
		void read_dir(char *str);
		// returns the existence of a file or directory (return
		// type is one of PJLFS_* or -1 for not found
		int stat(char *str);
		// deletes a file of the filesystem 
		void delete_file(char *str);
		// creates a directory at the given location
		void create_dir(char *str);
		// receives a file from device 
		Rawmem *recv_file(char *str, unsigned int expsize);
		void recv_file(char *str, unsigned int expsize, char *filename);
		// sends a file to location *str on devie
		void send_file(char *str);
		void send_file(char *str, char *filename);
		// appends to an existing file or creates it 
		void append_file(char *str);
		// sends a file as firmware update. Firmware code is expected 
		// to be in filebuffer
		void upload_firmware(void);
		// sends a file as rfu file (which already includes the PJL commands)
		void upload_RFU_firmware(char *rfu_file);
		// initializes (formats) the devices file system on volume *vol
		void format_fs(char *vol);

		// --- there functions don't work correctly ---

		// changes the printer name to *str 
		void change_printer_name(char *str);
		// causes the printer to print a selftest page according to the value in 
		// sttype 
		// 	1- PCL Selftest
		//	2- Continuous Self-Test
		//	3- PCL Typeface list
		//	4- PCL demo page
		// 	5- PostScript Config Page
		//	6- PsotScript Typeface List
		//	7- PostScript Demo Page
		void print_selftest(unsigned int sttype);
		

		// returns the current working directory
		String *get_pwd(void);
		// returns the device id 
		String *get_device_id(void);


		// empties the recv buffer for an expected amount of bytes
		void force_recv_clear(unsigned int n, unsigned int timeout);

		class ExPJLerror{};

	private:
		// connection object
		TCPcon		connection;
		String		device_id;
		String		pwd;
};


#endif //__PJLSESSION_H__
