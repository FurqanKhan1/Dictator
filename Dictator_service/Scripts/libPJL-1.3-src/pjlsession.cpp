/* 
 * PJLsession class 
 *
 * $Id: pjlsession.cpp,v 1.8 2005/04/21 07:37:28 fx Exp fx $
 */
#include <iostream>
using namespace std;

#include <stdio.h>
#include <stdlib.h>

#ifndef UNIX
// Windows header files
#include <direct.h>			// _getcwd() ...
#include <io.h>				// _open()
#include <fcntl.h>			//  -"-
#include <sys/types.h>			//  -"-
#include <sys/stat.h>			//  -"-
#else 
// UNIX header files
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>			// open(), close(), write()
#include <sys/stat.h>
#include <fcntl.h>
#endif //UNIX


#include "pjlsession.h"
#include "pjllists.h"
#include "commands.h"


PJLsession::PJLsession() {
	// nothing so far
	ctimeout=DEFAULT_CTIMEOUT;
	ftimeout=DEFAULT_FTIMEOUT;
}


PJLsession::~PJLsession() {
	// nothing so far
}


void PJLsession::initiate(char *host, unsigned int port) {
	connection.set_host(host);
	connection.set_port(port);
	connection.startconnection();
}


void PJLsession::read_env(void) {
	String			ts;
	unsigned int	i;
	unsigned int	hack_i=0;
	String			sline;
	String			var,val;
	PJLenvPrim		*e=NULL;

	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append(PJL_INFO_VAR);
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();

	connection.recvuntilstr(PJL_ENDSEQ,ctimeout);
	ts.set(connection.get(),connection.length());
	connection.clear();

	if (ts.stoken("@PJL INFO VARIABLES",0)==NULL) {
#ifdef _DEBUG
		cerr << "PJLsession::read_env(): did not receive command echo" << endl;
#endif //_DEBUG
		throw ExPJLerror();
	}

	env.clear();
	i=1;
	while (ts.stoken("\r\n",i)!=NULL) {
		sline=ts.stoken("\r\n",i);
		sline.chomp();
		if (sline.token('=',0)!=NULL) {
			String		language;

			// new variable=value set
			var=sline.token('=',0);
			// check to see if the variable is like "LPARM:PCL XYZ=BLA"
			if (var.token(' ',1)!=NULL) {
				language=var.token(' ',0);
				var.set(var.token(' ',1));
			} else {
				language="";
			}

			e = new PJLenvPrim;
			e->set_var(var.get());
			val=sline.token('=',1);
			e->set_val(val.token(' ',0));

			// set language always - make sure it's initialized 
			// correctly above
			//	REMOVED: if (language.length()>0) 
			e->set_lang(language.get());
			
			if (sline.findstr("ENUMERATED]"))
				e->set_range(false);
			else 
				e->set_range(true);
			e->set_changed(false);

			env.add_end(e);
			hack_i++;

		} else {
			// Not unique: if ((e = env.element(var.get()))==NULL) {
			if ((e = env.element(hack_i-1))==NULL) {
				cerr << "PJLsession::read_env(): '" << sline.get() << 
					"' before variable=value set" << endl;
			} else {
				//cerr << "DEBUG[fx]: e is >>" << e->get_var()->get() << "<<\n";
				if (sline.token('\t',1)!=NULL) {
					e->option_add(sline.token('\t',1));
				}
			}
		}
		i++;
	}
}


void PJLsession::env_commit_changes(void) {
	for (unsigned int i=0; i<env.count(); i++) {
		if (env.element(i)->get_changed()) {
			connection.clear();
			connection.sendbuf.set(PJL_START);
			connection.sendbuf.append(PJL_DEFAULT);
			if (env.element(i)->get_lang()->length()>0) {
				connection.sendbuf.append(env.element(i)->get_lang()->get());
				connection.sendbuf.append(" ");
			}
			connection.sendbuf.append(env.element(i)->get_var()->get());
			connection.sendbuf.append("=");
			connection.sendbuf.append(env.element(i)->get_val()->get());
			connection.sendbuf.append("\r\n");
			connection.sendbuf.append(PJL_FINISH);
			connection.senddata();
			env.element(i)->set_changed(false);
		}
	}
}



void PJLsession::read_device_id(void) {
	String		ts;
	char		*tx;

	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append(PJL_INFO_ID);
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();

	connection.recvuntilstr(PJL_ENDSEQ,ctimeout);
	ts.set(connection.get(),connection.length());
	connection.clear();

	if (ts.stoken("@PJL INFO ID",0)==NULL) {
#ifdef _DEBUG
		cerr << "PJLsession::read_devive_id(): did not receive command echo" << endl;
#endif //_DEBUG
		throw ExPJLerror();
	}
	
	if ((tx=ts.token('"',1))!=NULL) {
		device_id=tx;
	}
}


bool PJLsession::disable_pjl_password(unsigned int pass) {
	String			ts;
	char			numb[50];

	if ((pass==0)||(pass>65535)) throw ExInvalid();
#ifndef UNIX
	_snprintf(numb,49,"%u",pass);
#else
	snprintf(numb,49,"%u",pass);
#endif //UNIX
	
	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append("\r\n");
	connection.sendbuf.append("@PJL JOB PASSWORD=");
	connection.sendbuf.append(numb);
	connection.sendbuf.append("\r\n@PJL DEFAULT PASSWORD=0 \r\n");
	connection.sendbuf.append("@PJL DINQUIRE PASSWORD\r\n");
	connection.sendbuf.append("@PJL EOJ\r\n");
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();

	connection.recvuntilstr(PJL_ENDSEQ,ctimeout);
	ts.set(connection.get(),connection.length());
	connection.clear();

	if (ts.findstr("@PJL DINQUIRE PASSWORD")==NULL) {
#ifdef _DEBUG
		cerr << "PJLsession::disable_pjl_password(): did not receive command echo" << endl;
#endif //_DEBUG
		throw ExPJLerror();
	}
	
	if (ts.findstr("DISABLED")!=NULL) {
		return true;
	}
	if (ts.findstr("ENABLED")!=NULL) {
		return false;
	}

#ifdef _DEBUG
	cerr << "PJLsession::disable_pjl_password(): DINQUIRE didn't return result" << endl;
#endif //_DEBUG
	throw ExPJLerror();

}


void PJLsession::blind_disable_pjl_password(unsigned int pass) {
	String			ts;
	char			numb[50];

	if ((pass==0)||(pass>65535)) throw ExInvalid();
#ifndef UNIX
	_snprintf(numb,49,"%u",pass);
#else
	snprintf(numb,49,"%u",pass);
#endif //UNIX

	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append("\r\n");
	connection.sendbuf.append("@PJL JOB PASSWORD=");
	connection.sendbuf.append(numb);
	connection.sendbuf.append("\r\n@PJL DEFAULT PASSWORD=0 \r\n");
	connection.sendbuf.append("@PJL EOJ\r\n");
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();

	// TEST !!!
	// connection.recvatleast(9,ctimeout);
	// end TEST

	connection.sendbuf.clear();
}


void PJLsession::force_recv_clear(unsigned int n, unsigned int timeout) {
	connection.recvatleast(n,timeout);
	connection.recvbuf.clear();
}


bool PJLsession::chk_pjl_password(void) {
	String			ts;
	
	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append("\r\n");
	connection.sendbuf.append("@PJL DINQUIRE PASSWORD\r\n");
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();

	connection.recvuntilstr(PJL_ENDSEQ,ctimeout);
	ts.set(connection.get(),connection.length());
	connection.clear();

	if (ts.findstr("@PJL DINQUIRE PASSWORD")==NULL) {
#ifdef _DEBUG
		cerr << "PJLsession::chk_pjl_password(): did not receive command echo" << endl;
#endif //_DEBUG
		throw ExPJLerror();
	}
	
	if (ts.findstr("DISABLED")!=NULL) {
		return true;
	}
	if (ts.findstr("ENABLED")!=NULL) {
		return false;
	}

#ifdef _DEBUG
	cerr << "PJLsession::chk_pjl_password(): DINQUIRE didn't return result" << endl;
#endif //_DEBUG
	throw ExPJLerror();

}


void PJLsession::write_ustatus(char *str) {
	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append(PJL_USTATUS);
	connection.sendbuf.append(str);
	connection.sendbuf.append("\r\n");
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();
	connection.clear();
}


void PJLsession::write_ready_message(char *m) {
	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append(PJL_RDYMSG);
	connection.sendbuf.append("\"");
	connection.sendbuf.append(m);
	connection.sendbuf.append("\"\r\n");
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();
	connection.clear();
}


void PJLsession::write_failure_message(char *m)  {
	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append(PJL_OPMSG);
	connection.sendbuf.append("\"");
	connection.sendbuf.append(m);
	connection.sendbuf.append("\"\r\n");
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();
	connection.clear();
}


void PJLsession::read_volumes(void) {
	String			ts;
	String			sline;
	unsigned int	i=2;
	PJLvolPrim		*e;

	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append(PJL_INFO_FILESYS);
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();

	connection.recvuntilstr(PJL_ENDSEQ,ctimeout);
	ts.set(connection.get(),connection.length());
	connection.clear();

	if (ts.stoken("@PJL INFO FILESYS",0)==NULL) {
#ifdef _DEBUG
		cerr << "PJLsession::read_volumes(): did not receive command echo" << endl;
#endif //_DEBUG
		throw ExPJLerror();
	}

	vol.clear();
	while (ts.stoken("\r\n",i)!=NULL) {
		sline=ts.stoken("\r\n",i);
		sline.chomp();
		if (sline=="\x0c") break;
		sline.multispace2tab();
		if (sline.token('\t',6)!=NULL) {
			e=new PJLvolPrim;
			e->set_volume(sline.token('\t',1));
			e->set_size(sline.token('\t',2));
			e->set_free(sline.token('\t',3));
			e->set_location(sline.token('\t',4));
			e->set_label(sline.token('\t',5));
			e->set_status(sline.token('\t',6));
			vol.add_end(e);
		} else {
			cerr << "PJLsession::read_volumes(): not enough tab-tokens"
				<< " in volume list\n" << endl;
		}
		i++;
	}
}


void PJLsession::read_dir(char *str) {
	String			ts;
	String			sline;
	String			ty,tsize;
	unsigned int	i=1;
	PJLfilePrim		*e;

	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append(PJL_FSDIRLIST);
	connection.sendbuf.append("\"");
	connection.sendbuf.append(str);
	connection.sendbuf.append("\" ENTRY=1 COUNT=999999\r\n");
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();

	connection.recvuntilstr(PJL_ENDSEQ,ctimeout);
	ts.set(connection.get(),connection.length());
	connection.clear();

	if (ts.stoken("@PJL FSDIRLIST",0)==NULL) {
#ifdef _DEBUG
		cerr << "PJLsession::read_dir(): did not receive command echo" << endl;
#endif //_DEBUG
		throw ExPJLerror();
	}

	if (ts.stoken("\r\n",1)==NULL) {
#ifdef _DEBUG
		cerr << "PJLsession::read_dir(): strange! got echo but no more lines" << endl;
#endif //_DEBUG
		throw ExPJLerror();
	} else {
		String err=ts.stoken("\r\n",1);

		if (err.findstr("FILEERROR")!=NULL) {
#ifdef _DEBUG
			cerr << "PJLsession::read_dir(): Filesystem error " << err.token('=',1) << endl;
#endif //_DEBUG
			throw ExPJLerror();
		}
	}

	dir.clear();
	pwd.set(str);

	while (ts.stoken("\r\n",i)!=NULL) {
		sline=ts.stoken("\r\n",i);
		sline.chomp();
		if (sline=="\x0c") break;

		if (sline.token(' ',1)!=NULL) {

			ty=sline.token(' ',1);
			if (ty.token('=',1)==NULL) {
				cerr << "PJLsession::read_dir(): strange token: '" << ty.get() 
					<< "' as type ..." << endl;
				continue;
			}
			ty=ty.token('=',1);
			
			if (ty=="FILE") {

				if (sline.token(' ',2)==NULL) {
					cerr << "PJLsession::read_dir(): '" << sline.get() << 
						"' is supposedly FILE but has no size" << endl;
					continue;
				}
				tsize=sline.token(' ',2);
				tsize=tsize.token('=',1);

				e=new PJLfilePrim;
				e->set_name(sline.token(' ',0));
				e->set_type(PJLFS_FILE);
				e->set_size((unsigned int)atoi(tsize.get()));
				dir.add_end(e);
			} else if (ty=="DIR") {
				e=new PJLfilePrim;
				e->set_name(sline.token(' ',0));
				e->set_type(PJLFS_DIR);
				dir.add_end(e);
			} else {
				cerr << "PJLsession::read_dir(): '" << sline.get() << 
					"' is unknown item type" << endl;
			}
		} else {
			cerr << "PJLsession::read_dir(): not enough space-tokens"
				<< " in directory list\n" << endl;
		}
		i++;
	}
}


int PJLsession::stat(char *str) {
	String			ts;
	String			sline;

	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append(PJL_FSQUERY);
	connection.sendbuf.append("\"");
	connection.sendbuf.append(str);
	connection.sendbuf.append("\"\r\n");
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();

	connection.recvuntilstr(PJL_ENDSEQ,ctimeout);
	ts.set(connection.get(),connection.length());
	connection.clear();

	if (ts.findstr("@PJL FSQUERY")==NULL) {
#ifdef _DEBUG
		cerr << "PJLsession::stat(): did not receive command echo" << endl;
#endif //_DEBUG
		throw ExPJLerror();
	}

	// success ... something exsists here 
	if (
		(ts.findstr("FILEERROR")==NULL)
		&&
		(ts.token(' ',3)!=NULL)
		) {

		String		typ=ts.token(' ',3);
		
		if (typ.findstr("FILE")!=NULL) return PJLFS_FILE;
		else if (typ.findstr("DIR")!=NULL) return PJLFS_DIR;
		else {
#ifdef _DEBUG
			cerr << "PJLsession::stat(): strange answer: '"
				<< ts.get() << "'" << endl;
#endif //_DEBUG
			throw ExPJLerror();
		}
	// failure ...
	} else {
		String err=ts.stoken("\r\n",1);

		if (err.findstr("FILEERROR")!=NULL) {
#ifdef _DEBUG
			cerr << "PJLsession::stat(): Filesystem error " << err.token('=',1) << endl;
#endif //_DEBUG
			return (-1);
		} else {
			#ifdef _DEBUG
			cerr << "PJLsession::does_exist(): strange answer: '"
				<< ts.get() << "'" << endl;
#endif //_DEBUG
			throw ExPJLerror();
		}
	}
}


void PJLsession::delete_file(char *str) {

	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append(PJL_FSDELETE);
	connection.sendbuf.append("\"");
	connection.sendbuf.append(str);
	connection.sendbuf.append("\"\r\n");
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();

	connection.clear();
	// you don't get anything back from the device for delete
}


void PJLsession::create_dir(char *str) {

	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append(PJL_FSMKDIR);
	connection.sendbuf.append("\"");
	connection.sendbuf.append(str);
	connection.sendbuf.append("\"\r\n");
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();

	connection.clear();
	// you don't get anything back from the device for mkdir
}


Rawmem *PJLsession::recv_file(char *str, unsigned int expsize) {
	String			ts;
	String			sline;
	char			numb[50];

#ifndef UNIX
	_snprintf(numb,49,"%u",expsize);
#else
	snprintf(numb,49,"%u",expsize);
#endif //UNIX

	filebuffer.clear();
	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append(PJL_FSUPLOAD);
	connection.sendbuf.append("\"");
	connection.sendbuf.append(str);
	connection.sendbuf.append("\" OFFSET=0 SIZE=");
	connection.sendbuf.append(numb);
	connection.sendbuf.append("\r\n");
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();

	// get the first line - it will tell us if the operation
	// was successfull or not since failure answers do not contain
	// the SIZE field
	connection.recvuntilstr("\r\n",ctimeout);
	ts.set(connection.get(),connection.length());
	connection.clear();

	if (ts.findstr("@PJL FSUPLOAD")==NULL) {
#ifdef _DEBUG
		cerr << "PJLsession::recv_file(): did not receive command echo" << endl;
#endif //_DEBUG
		throw ExPJLerror();
	}
	if (ts.findstr("SIZE=")==NULL) {
		// no SIZE field - no file :-((
		connection.recvuntilstr(PJL_ENDSEQ,ctimeout);
		ts.set(connection.get(),connection.length());
		connection.clear();

		if (ts.findstr("FILEERROR")!=NULL) {
#ifdef _DEBUG
			cerr << "PJLsession::recv_file(): Filesystem error " << ts.token('=',1) << endl;
#endif //_DEBUG
			throw ExPJLerror();
		} else {
#ifdef _DEBUG
			cerr << "PJLsession::recv_file(): strange answer: '"
				<< ts.get() << "'" << endl;
#endif //_DEBUG
			throw ExPJLerror();
		}
	} else {
		//
		// YES  - the line contains SIZE= ... there is a file comming
		//
		String		fsi=ts.findstr("SIZE=");

		fsi.chomp();
		fsi=fsi.token('=',1);
#ifdef _DEBUG
		//cout << "DEBUG: expected size: " << expsize << ", reported: " << atoi(fsi.get()) << endl;
#endif //_DEBUG

		// timeout depends on size (of course) ;)
		connection.recvatleast((unsigned int)atoi(fsi.get()),
			ftimeout*(unsigned int)atoi(fsi.get()));
		filebuffer.set(connection.get(),connection.length());
		// recv the final <FF> (\x0c) from device and discard it
		connection.recvatleast(1,ftimeout);
		connection.clear();
		return &filebuffer;
	}
}


void PJLsession::recv_file(char *str, unsigned int expsize, char *filename) {
	String			ts;
	String			sline;
	char			numb[50];
	int				fd,bw=0;

#ifndef UNIX
	_snprintf(numb,49,"%u",expsize);
	if ((fd=open(filename,_O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY))<0) {
#ifdef _DEBUG
		cerr << "PJLsession::recv_file(): Could not open local file "<<filename<<endl;
#endif //_DEBUG
		throw ExInvalid();
	}
#else
	snprintf(numb,49,"%u",expsize);
	if ((fd=open(filename,O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP))<0) {
#ifdef _DEBUG
		cerr << "PJLsession::recv_file(): Could not open local file "<<filename<<endl;
#endif //_DEBUG
		throw ExInvalid();
	}
#endif //UNIX
	
	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append(PJL_FSUPLOAD);
	connection.sendbuf.append("\"");
	connection.sendbuf.append(str);
	connection.sendbuf.append("\" OFFSET=0 SIZE=");
	connection.sendbuf.append(numb);
	connection.sendbuf.append("\r\n");
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();

	// get the first line - it will tell us if the operation
	// was successfull or not since failure answers do not contain
	// the SIZE field
	connection.recvuntilstr("\r\n",ctimeout);
	ts.set(connection.get(),connection.length());
	connection.clear();

	if (ts.findstr("@PJL FSUPLOAD")==NULL) {
#ifdef _DEBUG
		cerr << "PJLsession::recv_file(): did not receive command echo" << endl;
#endif //_DEBUG
		throw ExPJLerror();
	}
	if (ts.findstr("SIZE=")==NULL) {
		// no SIZE field - no file :-((
		connection.recvuntilstr(PJL_ENDSEQ,ctimeout);
		ts.set(connection.get(),connection.length());
		connection.clear();

		if (ts.findstr("FILEERROR")!=NULL) {
#ifdef _DEBUG
			cerr << "PJLsession::recv_file(): Filesystem error " << ts.token('=',1) << endl;
#endif //_DEBUG
			throw ExPJLerror();
		} else {
#ifdef _DEBUG
			cerr << "PJLsession::recv_file(): strange answer: '"
				<< ts.get() << "'" << endl;
#endif //_DEBUG
			throw ExPJLerror();
		}
	} else {
		//
		// YES  - the line contains SIZE= ... there is a file comming
		//
		String		fsi=ts.findstr("SIZE=");

		fsi.chomp();
		fsi=fsi.token('=',1);
#ifdef _DEBUG
		//cout << "DEBUG: expected size: " << expsize << ", reported: " << atoi(fsi.get()) << endl;
#endif //_DEBUG


		for (unsigned int i=0;i<expsize;i++) {
			connection.recvbuf.clear();
			try {
				connection.recvatleast(1,ftimeout);

#ifndef UNIX
				if ((bw=_write(fd,connection.recvbuf.get(),connection.recvbuf.length()))<0) {
#ifdef _DEBUG
					cerr << "PJLsession::recv_file(): _write() to local file failed" << endl;
#endif //_DEBUG
					throw ExInvalid();
				}
			} catch (TCPcon::ExTimeout) {
				_close(fd);
			}
		}
#else
				if ((bw=write(fd,connection.recvbuf.get(),connection.recvbuf.length()))<0) {
#ifdef _DEBUG
					cerr << "PJLsession::recv_file(): _write() to local file failed" << endl;
#endif //_DEBUG
					throw ExInvalid();
				}
			} catch (TCPcon::ExTimeout) {
				::close(fd);
			}
		}
#endif //UNIX
		
		connection.recvbuf.clear();
		// recv the final <FF> (\x0c) from device and discard it
		connection.recvatleast(1,ftimeout);
		connection.clear();
	}
}



void PJLsession::send_file(char *str) {
	char			numb[50];

#ifndef UNIX
	_snprintf(numb,49,"%u",filebuffer.length());
#else
	snprintf(numb,49,"%u",filebuffer.length());
#endif //UNIX

	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append(PJL_FSDOWNLOAD);
	connection.sendbuf.append("SIZE=");
	connection.sendbuf.append(numb);
	connection.sendbuf.append(" NAME=\"");
	connection.sendbuf.append(str);
	connection.sendbuf.append("\"\r\n");
	connection.sendbuf.append(filebuffer.get(),filebuffer.length());
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();

	connection.clear();
	// you don't get anything back from the device for downloads
}


#ifndef UNIX

/* 
 * Windows version for uploading files directly without
 * going though the filebuffer
 */

void PJLsession::send_file(char *str, char *filename) {
	char			numb[50];
	struct _stat	statbuf;
	int				fd,br=0;
	char			rb[1025];


	if (_stat(filename,&statbuf)!=0) {
#ifdef _DEBUG
		cerr << "PJLsession::send_file(2): could not stat file "
			<< filename << endl;
#endif //_DEBUG
		throw ExInvalid();
	}

	
	if ((fd=open(filename,_O_RDONLY | _O_BINARY))<0) {
#ifdef _DEBUG
		cerr << "PJLsession::send_file(2) Could not open local file "
			<< filename <<endl;
#endif //_DEBUG
		throw ExInvalid();
	} else {
		_snprintf(numb,49,"%u",statbuf.st_size);
		connection.clear();
		connection.sendbuf.set(PJL_START);
		connection.sendbuf.append(PJL_FSDOWNLOAD);
		connection.sendbuf.append("SIZE=");
		connection.sendbuf.append(numb);
		connection.sendbuf.append(" NAME=\"");
		connection.sendbuf.append(str);
		connection.sendbuf.append("\"\r\n");
		connection.senddata();

		while ((br=_read(fd,rb,1024))>0) {
			connection.clear();
			connection.sendbuf.set(rb,br);
			connection.senddata();
		}
		_close(fd);
	}
	connection.clear();
}

#else

/* 
 * UNIX version for uploading files directly without
 * going though the filebuffer
 */

void PJLsession::send_file(char *str, char *filename) {
	char			numb[50];
	struct stat		statbuf;
	int			fd,br=0;
	char			rb[1025];
	
	if (::stat(filename,&statbuf)!=0) {
#ifdef _DEBUG
		cerr << "PJLsession::send_file(2): could not stat file "
			<< filename << endl;
#endif //_DEBUG
		throw ExInvalid();
	}
	
	if ((fd=open(filename,O_RDONLY))<0) {
#ifdef _DEBUG
		cerr << "PJLsession::send_file(2) Could not open local file "
			<< filename <<endl;
#endif //_DEBUG
		throw ExInvalid();
	} else {
		snprintf(numb,49,"%lu",statbuf.st_size);
		connection.clear();
		connection.sendbuf.set(PJL_START);
		connection.sendbuf.append(PJL_FSDOWNLOAD);
		connection.sendbuf.append("SIZE=");
		connection.sendbuf.append(numb);
		connection.sendbuf.append(" NAME=\"");
		connection.sendbuf.append(str);
		connection.sendbuf.append("\"\r\n");
		connection.senddata();

		while ((br=read(fd,rb,1024))>0) {
			connection.clear();
			connection.sendbuf.set(rb,br);
			connection.senddata();
		}
		::close(fd);
	}
	connection.clear();
}

#endif //UNIX


void PJLsession::append_file(char *str) {
	char			numb[50];

#ifndef UNIX
	_snprintf(numb,49,"%u",filebuffer.length());
#else
	snprintf(numb,49,"%u",filebuffer.length());
#endif //UNIX

	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append(PJL_FSAPPEND);
	connection.sendbuf.append("SIZE=");
	connection.sendbuf.append(numb);
	connection.sendbuf.append(" NAME=\"");
	connection.sendbuf.append(str);
	connection.sendbuf.append("\"\r\n");
	connection.sendbuf.append(filebuffer.get(),filebuffer.length());
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();

	connection.clear();
	// you don't get anything back from the device for append
}


void PJLsession::close(void) {
	connection.closeconnection();
	env.clear();
}


bool PJLsession::connected(void) {
	return connection.is_connected();
}


void PJLsession::upload_RFU_firmware(char *rfu_file) {
	int			fd,br=0;
	char			rb[1025];

#ifndef UNIX

	// Windows upload

	if ((fd=open(rfu_file,_O_RDONLY | _O_BINARY))<0) {
#ifdef _DEBUG
		cerr << "PJLsession::upload_RFU_firmware() Could not open local file "
			<< rfu_file <<endl;
#endif //_DEBUG
		throw ExInvalid();
	} else {
		while ((br=_read(fd,rb,1024))>0) {
			connection.clear();
			connection.sendbuf.set(rb,br);
			connection.senddata();
		}
		_close(fd);
	}
#else

	// UNIX upload

	if ((fd=open(rfu_file,O_RDONLY))<0) {
#ifdef _DEBUG
		cerr << "PJLsession::upload_RFU_firmware() Could not open local file "
			<< rfu_file <<endl;
#endif //_DEBUG
		throw ExInvalid();
	} else {
		while ((br=read(fd,rb,1024))>0) {
			connection.clear();
			connection.sendbuf.set(rb,br);
			connection.senddata();
		}
		::close(fd);
	}

#endif //UNIX

	connection.clear();
}


void PJLsession::format_fs(char *vol) {

	connection.clear();
	connection.sendbuf.set(PJL_START);
	// start a secure job 
	connection.sendbuf.append("@PJL JOB PASSWORD=0\r\n");
	connection.sendbuf.append(PJL_FSINIT);
	connection.sendbuf.append("\"");
	connection.sendbuf.append(vol);
	connection.sendbuf.append("\"\r\n");
	connection.sendbuf.append("@PJL EOJ\r\n");
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();

	connection.clear();
	// you don't get anything back from the this
}


void PJLsession::change_printer_name(char *str) {

	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append(PJL_PRINTERNAME);
	connection.sendbuf.append(str);
	connection.sendbuf.append("\r\n");
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();

	connection.clear();
	// you don't get anything back from the this
}


void PJLsession::print_selftest(unsigned int sttype) {

	if ((sttype==0)||(sttype>7)) {
#ifdef _DEBUG
		cerr << "PJLsession::print_selftest(): out of range" << endl;
#endif //_DEBUG
		throw ExInvalid();
	}

	connection.clear();
	connection.sendbuf.set(PJL_START);
	connection.sendbuf.append(PJL_SELFTEST);
	switch (sttype) {
		case 1:	connection.sendbuf.append("SELFTEST");
			break;
		case 2:	connection.sendbuf.append("CONTSELFTEST");
			break;
		case 3:	connection.sendbuf.append("PCLTYPELIST");
			break;
		case 4:	connection.sendbuf.append("PCLDEMOPAGE");
			break;
		case 5:	connection.sendbuf.append("PSCONFIGPAGE");
			break;
		case 6:	connection.sendbuf.append("PSTYPEFACELIST");
			break;
		case 7:	connection.sendbuf.append("PSDEMOPAGE");
			break;
	}
	connection.sendbuf.append("\r\n");
	connection.sendbuf.append(PJL_FINISH);
	connection.senddata();

	connection.clear();
	// you don't get anything back from the this
}


/* **********************************************************************************
 * capsulated calls 
 * **********************************************************************************/

String *PJLsession::get_device_id(void) {
	return &device_id;
}

String *PJLsession::get_pwd(void) {
	return &pwd;
}
