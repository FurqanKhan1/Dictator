/* 
 * PJL File Transfer
 * 
 * command line interface to PJLlib functionality 
 * Comment of the Day: 
 *   // Did anyone ever wrote such a lazy piece of shit? 
 *   // No? Lets do it.
 *
 * $Id: main.cpp,v 1.8 2002/07/06 15:36:29 fx Exp fx $
 */
#include <iostream>
using namespace std;
#include <stdio.h>			// cant live without printf() ;)

#ifndef UNIX
// Windows header files
#include <direct.h>			// _getcwd() ...
#include <io.h>				// _open()
#include <fcntl.h>			//  -"-
#include <sys/types.h>			//  -"-
#include <sys/stat.h>			//  -"-
#include <conio.h>			// if key pressed _kbhit()
#else 
// UNIX header files
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>			// open(), close(), write()
#include <sys/stat.h>
#include <fcntl.h>
#endif //UNIX

#include "fxstrings.h"
#include "pjlsession.h"
#include "commands.h"

#define SPLASH			"PFT - PJL file transfer\n" \
						"\tFX of Phenoelit <fx@phenoelit.de>\n"\
						"\tVersion 0.7 ($Revision: 1.8 $)\n"
						
#define GENERIC_ERROR	"syntax error (try help)"

// commands available in command line
#define CMD_QUIT		"quit"
#define CMD_EXIT		"exit"
#define CMD_HELP		"help"
#define CMD_SERVER		"server"
#define CMD_PORT		"port"
#define CMD_CONNECT		"connect"
#define CMD_CLOSE		"close"
#define CMD_ENV			"env"
#define CMD_ENV_READ		"read"
#define CMD_ENV_PRINT		"print"
#define CMD_ENV_COMMIT		"commit"
#define CMD_ENV_SHOW		"show"
#define CMD_ENV_SET			"set"
#define CMD_ENV_OPTIONS		"options"
#define CMD_ENV_CHANGED		"changed"
#define CMD_ENV_UNPROTECT	"unprotect"
#define CMD_ENV_BRUTEFORCE	"bruteforce"
#define CMD_MESSAGE		"message"
#define CMD_FAILURE		"failure"
#define CMD_VOLUMES		"volumes"
#define CMD_LS			"ls"
#define CMD_CD			"cd"
#define CMD_PWD			"pwd"
#define CMD_CHVOL		"chvol"
#define CMD_RM			"rm"
#define CMD_MKDIR		"mkdir"
#define CMD_LPWD		"lpwd"
#define CMD_LCD			"lcd"
#define CMD_GET			"get"
#define CMD_PUT			"put"
#define CMD_APPEND		"append"
#define CMD_SESSION		"session"
#define CMD_TIMEOUT		"timeout"
#define CMD_PAUSE		"pause"
#define CMD_PRINTERNAME		"printername"
#define CMD_SELFTEST		"selftest"

PJLsession			sess;
bool				end_application=false;


// prototypes 
void	usage(char *s);
void	read_command(String *s);
void	cmdloop(void);
void	print_help(char *cc);
void	commandline_ident(void);
#ifdef UNIX
void	sighandl(int s);
#endif //UNIX


class Program_config {
	public:
		String			server;
		unsigned int	port;
		String			pwd;
		String			pvol;
		String			lpwd;
		bool			pause;
#ifdef UNIX
		bool			ctrlc;
#endif //UNIX
};

Program_config		cfg;

int main(int argc, char **argv) {

	cfg.server="10.1.1.16";
	cfg.port=9100;
	cfg.pause=true;
#ifdef UNIX
	cfg.ctrlc=false;
	signal(SIGINT,&sighandl);

	{
		char	cwdb[2048];
		cfg.lpwd=getcwd(cwdb,2048);
	}
#else 
	cfg.lpwd=_getcwd(NULL,0);
#endif //UNIX
	
	if (argc>3) {
		usage(argv[0]);
		return(-1);
	} else if (argc==2) {
		cfg.server=argv[1];
	} else if (argc==3) {
		cfg.server=argv[1];
		commandline_ident();
		return 0;
	}

	cout << SPLASH << endl;

	cmdloop();

	return 0;
}


// function implementation
#ifdef UNIX
void sighandl(int s) {
	cfg.ctrlc=true;
}
#endif //UNIX

void cmdloop(void) {
	String			cmd;
	String			basecmd;

	while (!end_application) {
		cout << "pft> ";
		read_command(&cmd);
		cmd.chomp();

		// catch single command lines
		if (cmd.token(' ',0)==NULL) {
			basecmd=cmd.get();
		} else {
			basecmd=cmd.token(' ',0);
		}

		// user requested end of communication ;)
		if (basecmd==CMD_QUIT) {
			end_application=true;
			continue;
		}

		// user wants to end talking but with the wrong cmd ;)
		else if (basecmd==CMD_EXIT) {
			cout << "Did you try 'quit'?"<<endl;
			continue;
		}

		// user want help
		else if (basecmd==CMD_HELP) {
			print_help(cmd.token(' ',1));
		}

		// user wants to set the server 
		else if (basecmd==CMD_SERVER) {
			if (cmd.token(' ',1)==NULL) {
				cerr << GENERIC_ERROR << endl;
				continue;
			} 
			cfg.server=cmd.token(' ',1);
			cout << "Server set to " << cfg.server.get() << endl;
		} 

		// user wants to set port
		else if (basecmd==CMD_PORT) {
			if (cmd.token(' ',1)==NULL) {
				cerr << GENERIC_ERROR << endl;
				continue;
			}
			cfg.port=atoi(cmd.token(' ',1));
			cout << "Port set to " << cfg.port << endl;
		}

		// user would like to connect
		else if (basecmd==CMD_CONNECT) {

#ifdef UNIX
			// endable default handler for ctrl-c during connect() call
			signal(SIGINT,SIG_DFL);
#endif //UNIX
			

			if (sess.connected()) {
				cerr << "already connected (hint: help close)" << endl;
				continue;
			}
			try {
				sess.initiate(cfg.server.get(),cfg.port);
				cout << "Connected to " << cfg.server.get() << ":" << cfg.port << endl;
			} catch (...) {
				cerr << "ERROR: connection failed" << endl;
			}
			// if we are connected, read the device ID now
			if (sess.connected()) {
				cfg.pwd.set("\\");
				cfg.pvol.set("0:");
				try {
					sess.write_ustatus("OFF");
					sess.read_device_id();
					cout << "Device: " << sess.get_device_id()->get() << endl;
				} catch (PJLsession::ExPJLerror) {
					cerr << "ERROR: PJL error while reading device ID" << endl;
				} catch (...) {
					cerr << "ERROR: while requesting device ID" << endl;
				}
			}
#ifdef UNIX
			signal(SIGINT,&sighandl);
#endif //UNIX
		}

		// close connection
		else if (basecmd==CMD_CLOSE) {
			if (sess.connected()) {
				sess.close();
				cout << "Connection closed" << endl;
			} else {
				cout << "not connected" << endl;
			}
		}

		// user requested environment list from the PJL device
		// to be downloaded, printed or commited 
		else if (basecmd==CMD_ENV) {
			// there is "env read", "env print", "env show", "env set" and "env commit"
			String		subc;

			if (!sess.connected()) {
				cout << "not connected" << endl;
				continue;
			}

			if (cmd.token(' ',1)==NULL) {
				cerr << GENERIC_ERROR << endl;
				continue;
			} 
			subc=cmd.token(' ',1);
			
			// env read
			if (subc==CMD_ENV_READ) {
				try {
					sess.read_env();
					cout << sess.env.count() << " variables read" << endl;
				} catch (...) {
					cerr << "ERROR: could not get environment information" << endl;
				}
			// env print
			} else if (subc==CMD_ENV_PRINT) {
				unsigned int	l=0;
				char			tonne;

				for (unsigned int i=0;i<sess.env.count();i++) {
					if (sess.env.element(i)->get_changed())
						cout << "*\t";
					else 
						cout << "\t";
					
					cout 
						<< (sess.env.element(i))->get_var()->get() 
						<< "="
						<< (sess.env.element(i))->get_val()->get();
					if (sess.env.element(i)->get_lang()->length()>0)
						cout << " (" << sess.env.element(i)->get_lang()->get() << ")";
					cout << endl;

					if ((++l==24)&&(cfg.pause)) {
						cout << "-- press ENTER to continue --";
						cin.get(tonne);
						l=0;
					}
				}
			// env changed
			} else if (subc==CMD_ENV_CHANGED) {
				for (unsigned int i=0;i<sess.env.count();i++) {
					if (sess.env.element(i)->get_changed()) {
						cout << "\t" 
						<< (sess.env.element(i))->get_var()->get() << "="
						<< (sess.env.element(i))->get_val()->get();
						if (sess.env.element(i)->get_lang()->length()>0)
							cout << " (" << sess.env.element(i)->get_lang()->get() << ")";
						cout << endl;
					}
				}
			// env show VAR
			} else if (subc==CMD_ENV_SHOW) {
				String	v;
				if (cmd.token(' ',2)==NULL) {
					cerr << "for 'env show', it would be cool to supply the"
						<< " variable you wanne see ..." << endl;
					continue;
				}
				v=cmd.token(' ',2);
				if (sess.env[v.get()]==NULL) {
					cerr << "no variable known by the name of '" << v.get() << "'" << endl;
					continue;
				}
				for (unsigned int i=0; i<sess.env.count(); i++) {
					if (v == sess.env.element(i)->get_var()->get()) {
						cout << v.get() << "=" << sess.env.element(i)->get_val()->get();
						if (sess.env.element(i)->get_lang()->length()>0) 
							cout << " (" << sess.env.element(i)->get_lang()->get() << ")";
						cout << endl;
					}
				} 
			// env commit
			} else if (subc==CMD_ENV_COMMIT) {
				try {
					sess.env_commit_changes();
				} catch (...) {
					cerr << "ERROR: could not commit changes in environment";
				}
			// env set VAR "VALUE"
			} else if (subc==CMD_ENV_SET) {
				String			v,w,t;
				PJLenvPrim		*e;
				unsigned int	multiple=0;
				unsigned int	whichone[100];

				memset(whichone,0,sizeof(whichone));
				if (cmd.token(' ',3)==NULL) {
					cerr << "for 'env set', it would be cool to supply the"
						<< " variable you wanne change and a value..." << endl;
					continue;
				}
				v=cmd.token(' ',2);
				if (sess.env[v.get()]==NULL) {
					cerr << "no variable known by the name of '" << v.get() << "'" << endl;
					continue;
				}

				// env set VAR "VAL TO SET"
				//             ^^^^ - 3
				w=cmd.findstr("\"");
				if (w.token('"',1)==NULL) {
					cerr << GENERIC_ERROR << endl;
					continue;
				}

				// check if there are more then one variables with this 
				// name and different language settings
				for (unsigned int i=0; i<sess.env.count(); i++) {
					if (v == sess.env.element(i)->get_var()->get()) {
						whichone[multiple]=i;
						multiple++;
					}
				}
				if (multiple > 1) {
					String			ch;
					unsigned int	cho;

					cout << "Multpile variables of that name. Select one:" << endl;
					for (unsigned int i=0; i<multiple; i++) {
						cout << "[" << i <<"] " 
							<< sess.env.element(whichone[i])->get_var()->get() 
							<< "  "
							<< sess.env.element(whichone[i])->get_lang()->get() 
							<< endl;
					}
					read_command(&ch);
					ch.chomp();
					cho=(unsigned int)strtoul(ch.get(),(char**)NULL,10);
					if (cho>multiple-1) {
						cerr << "Illegal selection. Dumb ass."<<endl;
						continue;
					} else {
						e=sess.env.element(whichone[cho]);
					}
				} else {
					e=sess.env.element(v.get());
				}

				t=w.token('"',1);
				cout << "Before: " << v.get() << "=" << e->get_val()->get() 
					<< "\t(" << e->get_lang()->get() << ")" << endl;
				e->set_val(t.get());
				cout << "After : " << v.get() << "=" << e->get_val()->get() 
					<< "\t(" << e->get_lang()->get() << ")" << endl;
				// e->set_changed(true); is done by set_val()
			// env options VAR
			} else if (subc==CMD_ENV_OPTIONS) {
				String	v;
				if (cmd.token(' ',2)==NULL) {
					cerr << "for 'env options', it would be cool to supply the"
						<< " variable you wanne see ..." << endl;
					continue;
				}
				v=cmd.token(' ',2);
				if (sess.env[v.get()]!=NULL) {
					for (unsigned int i=0; i<sess.env.count(); i++) {
						if (v == sess.env.element(i)->get_var()->get()) {
							cout << "Options for " << v.get() 
								<< " (" << sess.env.element(i)->get_lang()->get() << ")";
							if (sess.env.element(i)->get_range()) {
								cout << " (range)" << endl;
							} else {
								cout << " (enumerated)" << endl;
							}

							for (unsigned int j=0;
								j<sess.env.element(i)->options_count();j++) {
								//cout << "\t" << sess.env.element(v.get())->option(i) << endl;
								if ( sess.env.element(i)->option(j) != NULL) { 
									cout << "\t" <<	sess.env.element(i)->option(j) << "\n";
								} else {
									cerr << "Oh cool, element " << i <<" is NULL ! FUCK!\n";
								}
							}
						}
					}
				} else {
					cerr << "no variable known by the name of '" << v.get() << "'" << endl;
				}
			// env unprotect num
			} else if (subc==CMD_ENV_UNPROTECT) {
				unsigned int	p;
				if (cmd.token(' ',2)==NULL) {
					cerr << GENERIC_ERROR << endl;
					continue;
				}
				if ((p=atoi(cmd.token(' ',2)))==0) {
					cerr << "password is between 1 and 65535" << endl;
					continue;
				}
				try {
					if (sess.disable_pjl_password(p)) 
						cout << "PJL security disabled" << endl;
					else
						cout << "password wrong" << endl;
				} catch(...) {
					cerr << "Disabling PJL security failed on PJL level" << endl;
				}
			// env bruteforce
			} else if (subc==CMD_ENV_BRUTEFORCE) {
				unsigned int	dx=30;
				unsigned int	di=0;
				unsigned int	bstart=0;
				const unsigned int		dx_increment=1;
				const unsigned int		dx_decrement=2;

				if ( (cmd.token(' ',2)==NULL) || (atoi(cmd.token(' ',2))==0) )
					bstart=1;
				else 
					bstart=atoi(cmd.token(' ',2));

				for (unsigned int p=bstart;p<=65535;p++) {
					try {
						sess.blind_disable_pjl_password(p);
					} catch (...) {
						cerr << "Error while beating the shit out of the device" << endl;
						break;
					}

#ifndef UNIX
					if (_kbhit()) break;
#else
					if (cfg.ctrlc) break;
#endif //UNIX

					if (++di==dx) {
						cout << "try " << p << endl;
						// every dx-th attempt read back status
						try {
							sess.force_recv_clear(dx*9,(unsigned int)(dx/3));
						} catch (TCPcon::ExTimeout) {
							cerr << "INFO: force_recv_clear() timed out for " 
								<< dx*9 << "bytes (" 
								<< (unsigned int)(dx/3) << " sec) "
								<< endl;
						}

						try {
							if (sess.chk_pjl_password()) {
								cout << "Password disabled successfully" << endl;
								break;
							} else {
								//cout << "Still some way to go" << endl;
								dx+=dx_increment;
								cout << "\tincreasing dx to " << dx << endl;
							}
						} catch (TCPcon::ExTimeout) {
							cerr << "Device seems to be unhappy\n" 
								<< "\ttesting again from " << p-dx << endl;

							if (p>dx) p-=dx; else p=0;
							if (dx>10) dx-=dx_decrement; else dx=10;
							cerr << "\treverting dx to " << dx << endl;
						}
						di=0;
					}
#ifndef UNIX
					if (_kbhit()) break;
#else
					if (cfg.ctrlc) break;
#endif //UNIX
				}

			// env invalid
			} else {
				cerr << GENERIC_ERROR << endl;
			}
		} // message command
		else if (basecmd==CMD_MESSAGE) {
			String	t,w;

			if (!sess.connected()) {
				cout << "not connected" << endl;
				continue;
			}

			if (cmd.token(' ',1)==NULL) {
				cerr << GENERIC_ERROR << endl;
				continue;
			}
			w=cmd.findstr("\"");
			if (w.token('"',1)==NULL) {
				cerr << GENERIC_ERROR << endl;
				continue;
			}
			t=w.token('"',1);
			try {
				sess.write_ready_message(t.get());
				cout << "Display message set to '" << t.get() << "'" << endl;
			} catch(...) {
				cerr << "ERROR: could not send message" <<endl;
			}
		} 
		// failure command
		else if (basecmd==CMD_FAILURE) {
			String	t,w;

			if (!sess.connected()) {
				cout << "not connected" << endl;
				continue;
			}

			if (cmd.token(' ',1)==NULL) {
				cerr << GENERIC_ERROR << endl;
				continue;
			}
			w=cmd.findstr("\"");
			if (w.token('"',1)==NULL) {
				cerr << GENERIC_ERROR << endl;
				continue;
			}
			t=w.token('"',1);
			try {
				sess.write_failure_message(t.get());
				cout << "Failure message set to '" << t.get() << "' (device offline)" << endl;
			} catch(...) {
				cerr << "ERROR: could not send message" <<endl;
			}
		}
		// volumes command
		else if (basecmd==CMD_VOLUMES) {
			if (!sess.connected()) {
				cout << "not connected" << endl;
				continue;
			}
			try {
				sess.read_volumes();
			} catch (...) {
				cerr << "ERROR: while reading volume information" << endl;
				continue;
			}
			printf("%8s %10s %10s %15s %10s %10s\n",
					"Volume","Size","Free","Location","Label","Status");
			for (unsigned int i=0;i<sess.vol.count();i++) {
				printf("%8s %10s %10s %15s %10s %10s\n",
					sess.vol.element(i)->get_volume()->get(),
					sess.vol.element(i)->get_size()->get(),
					sess.vol.element(i)->get_free()->get(),
					sess.vol.element(i)->get_location()->get(),
					sess.vol.element(i)->get_label()->get(),
					sess.vol.element(i)->get_status()->get());
			}
		}
		// ls command
		else if (basecmd==CMD_LS) {
			String			dest;
			unsigned int	l=0;
			char			tonne;

			if (!sess.connected()) {
				cout << "not connected" << endl;
				continue;
			}
			try {
				// get current volume
				dest=cfg.pvol.get();
				// append current directory
				dest.append(cfg.pwd.get());
				// list 
				sess.read_dir(dest.get());
			} catch (...) {
				if (dest.get()!=NULL) 
					cerr << "ERROR: Could not list directory '" << dest.get() << "'" << endl;
				else
					cerr << "ERROR: Could not list directory!" << endl;
				continue;
			}
			cout << dest.get() << endl;

			for (unsigned int i=0;i<sess.dir.count();i++) {
				if (sess.dir.element(i)->get_type()==PJLFS_FILE) {
					printf("%-20s %10u %10s\n",
						sess.dir.element(i)->get_name()->get(),
						sess.dir.element(i)->get_size(),
						"-");
				} else if (sess.dir.element(i)->get_type()==PJLFS_DIR) {
					printf("%-20s %10s %10s\n",
						sess.dir.element(i)->get_name()->get(),
						"-","d");
				}

				if ((++l==24)&&(cfg.pause)) {
						cout << "-- press ENTER to continue --";
						cin.get(tonne);
						l=0;
				}
			}
		}
		// cd command
		else if (basecmd==CMD_CD) {
			String		dest,np;

			if (!sess.connected()) {
				cout << "not connected" << endl;
				continue;
			}
			if (cmd.token(' ',1)==NULL) {
				cerr << "could you try to tell me where to cd to? Thanks." << endl;
				continue;
			}

			dest=cmd.token(' ',1);
			if (dest==".") {
				cerr << "wise guy" << endl;
				continue;
			}
			if (dest=="..") {
				int		i=1;

				if (cfg.pwd=="\\") continue;
				while (cfg.pwd.token('\\',i+1)!=NULL) {
					np.append("\\");
					np.append(cfg.pwd.token('\\',i));
					i++;
				}

				if (np.get()!=NULL) {
					cfg.pwd.set(np.get());
				} else {
					cfg.pwd.set("\\");
				}


			} else {
				np=cfg.pvol.get();
				np.append(cfg.pwd.get());
				np.append("\\");
				np.append(dest.get());
				try {
					if (sess.stat(np.get())==PJLFS_DIR) {
						// make it pwd ...
						if (cfg.pwd=="\\") {
							cfg.pwd.append(dest.get());
						} else {
							cfg.pwd.append("\\");
							cfg.pwd.append(dest.get());
						}
						cout << "New directory is '" << cfg.pwd.get() << "'" << endl;
					} else {
						cerr << "directoy not found: '" << np.get() <<"'"<<endl;
					}
				} catch (...) {
					cerr << "something went wrong :-(" << endl;
				}
			}
		}
		// pwd command
		else if (basecmd==CMD_PWD) {
			if (!sess.connected()) {
				cout << "not connected" << endl;
				continue;
			}
			cout << cfg.pvol.get() << cfg.pwd.get() << endl;
		}
		// chvol command
		else if (basecmd==CMD_CHVOL) {
			bool found=false;
			
			if (!sess.connected()) {
				cout << "not connected" << endl;
				continue;
			}
			if (cmd.token(' ',1)==NULL) {
				cerr << GENERIC_ERROR << endl;
				continue;
			}
			try {
				sess.read_volumes();
			} catch (...) {
				cerr << "ERROR: while reading volume information" << endl;
				continue;
			}

			for (unsigned int i=0;i<sess.vol.count();i++) {
				if (*(sess.vol.element(i)->get_volume())==cmd.token(' ',1)) {
					found=true;
				}
			}

			if (found) {
				cfg.pvol.set(cmd.token(' ',1));
				cfg.pwd.set("\\");
				cout << "volume changed to " << cfg.pvol.get() << endl;
			} else {
				cerr << "volume " << cmd.token(' ',1) << " not existing" << endl;
			}
		}
		// rm command
		else if (basecmd==CMD_RM) {
			String		targ;

			if (!sess.connected()) {
				cout << "not connected" << endl;
				continue;
			}
			if (cmd.token(' ',1)==NULL) {
				cerr << "what should I delete ?" << endl;
				continue;
			}

			targ=cfg.pvol.get();
			targ.append(cfg.pwd.get());
			targ.append("\\");
			targ.append(cmd.token(' ',1));
			try {
				if (sess.stat(targ.get())!=PJLFS_NOTFOUND) {
					sess.delete_file(targ.get());
				} else {
					cerr << "file '" << targ.get() << "' not found" <<endl;
				}
			} catch (...) {
				cerr << "Could not stat file or send failed"  << endl;
			}
		}
		// mkdir command
		else if (basecmd==CMD_MKDIR) {
			String		targ;

			if (!sess.connected()) {
				cout << "not connected" << endl;
				continue;
			}
			if (cmd.token(' ',1)==NULL) {
				cerr << "create some dir eh?" << endl;
				continue;
			}

			targ=cfg.pvol.get();
			targ.append(cfg.pwd.get());
			targ.append("\\");
			targ.append(cmd.token(' ',1));
			try {
				sess.create_dir(targ.get());
				cerr << "directory '" << targ.get() << "' created" <<endl;
			} catch (...) {
				cerr << "Could not create directory"  << endl;
			}
		}
		// lpwd command
		else if (basecmd==CMD_LPWD) {
			cout << cfg.lpwd.get() << endl;
		}
		// lcd command
		else if (basecmd==CMD_LCD) {
			if (cmd.token(' ',1)==NULL) {
				cerr << "where should I lcd to?" << endl;
				continue;
			}
#ifndef UNIX
			if (_chdir(cmd.token(' ',1))==0) {
				cfg.lpwd=_getcwd(NULL,0);
				cout << "Local directory changed to " << cfg.lpwd.get() << endl;
			} else {
				cerr << "lcd failed" << endl;
			}
#else
			if (chdir(cmd.token(' ',1))==0) {
				char	cwd[2048];
				cfg.lpwd=getcwd(cwd,2048);
				cout << "Local directory changed to " << cfg.lpwd.get() << endl;
			} else {
				cerr << "lcd failed" << endl;
			}
#endif //UNIX
		}
		// get command
		else if (basecmd==CMD_GET) {
			String			targ,dest;
			//bool			found=false;
			PJLfilePrim		*e;

			if (!sess.connected()) {
				cout << "not connected" << endl;
				continue;
			}
			if (cmd.token(' ',1)==NULL) {
				cerr << "which file?" << endl;
				continue;
			}

			// make sure we know the directory listing so we know
			// the size of this file
			try {
				dest=cfg.pvol.get();
				// append current directory
				dest.append(cfg.pwd.get());
				// list 
				sess.read_dir(dest.get());
			} catch (...) {
				cerr << "Could not even get a directory listing ..." << endl;
				continue;
			}

			
			if ((e=sess.dir.element(cmd.token(' ',1)))==NULL) {
				cerr << "file '" << cmd.token(' ',1) << "' not found" <<endl;
				continue;
			}

			targ=cfg.pvol.get();
			targ.append(cfg.pwd.get());
			targ.append("\\");
			targ.append(cmd.token(' ',1));

			cout << "Trying to recv file " << targ.get() << " of size " 
				<<e->get_size()<<endl;

			try {
				sess.recv_file(targ.get(),e->get_size(),cmd.token(' ',1));
			} catch (...) {
				cerr << "Could not receive file"  << endl;
				continue;
			}

		}
		// put command 
		else if (basecmd==CMD_PUT) {
			String		targ;

			if (!sess.connected()) {
				cout << "not connected" << endl;
				continue;
			}
			if (cmd.token(' ',1)==NULL) {
				cerr << "which file?" << endl;
				continue;
			}

			targ=cfg.pvol.get();
			targ.append(cfg.pwd.get());
			targ.append("\\");
			targ.append(cmd.token(' ',1));

			try {
				sess.send_file(targ.get(),cmd.token(' ',1));
				cout << "Uploaded  to " << targ.get() << endl;
			} catch (...) {
				cerr << "Sending the file failed" << endl;
			}
		}	
		// append command 
		else if (basecmd==CMD_APPEND) {
			String		targ;
			int			fp,br=0;
			char		rb[1024];

			if (!sess.connected()) {
				cout << "not connected" << endl;
				continue;
			}
			if (cmd.token(' ',2)==NULL) {
				cerr << GENERIC_ERROR << endl;
				continue;
			}

			targ=cfg.pvol.get();
			targ.append(cfg.pwd.get());
			targ.append("\\");
			targ.append(cmd.token(' ',2));

#ifndef UNIX
			if ((fp=open(cmd.token(' ',1),_O_RDONLY | _O_BINARY))<0) {
					cerr << "Could not open local file "<<cmd.token(' ',1)<<endl;
					continue;
			} else {
				sess.filebuffer.clear();
				while ((br=_read(fp,rb,1024))>0) {
					sess.filebuffer.append(rb,br);
				}
				_close(fp);
				cout << sess.filebuffer.length() 
					<< " bytes read from local file " << cmd.token(' ',1)<< endl;
			}
#else
			if ((fp=open(cmd.token(' ',1),O_RDONLY))<0) {
					cerr << "Could not open local file "<<cmd.token(' ',1)<<endl;
					continue;
			} else {
				sess.filebuffer.clear();
				while ((br=read(fp,rb,1024))>0) {
					sess.filebuffer.append(rb,br);
				}
				close(fp);
				cout << sess.filebuffer.length() 
					<< " bytes read from local file " << cmd.token(' ',1)<< endl;
			}
#endif //UNIX

			try {
				sess.append_file(targ.get());
				cout << "Appended " << sess.filebuffer.length() << " bytes to "
					<< targ.get() << endl;
			} catch (...) {
				cerr << "Sending the file failed" << endl;
			}
			sess.filebuffer.clear();
		}	
		// session command
		else if (basecmd==CMD_SESSION) {
			if (cfg.server.get()!=NULL) 
				cout << "Server: " << cfg.server.get()
				<< " (port " << cfg.port << ")" << endl;
			else 
				cout << "Server not set (port " << cfg.port << ")" << endl;

			if (!sess.connected())
				cout << "not connected" << endl;
			else 
				cout << "connected" <<endl;

			cout << "Command timeout: " << sess.ctimeout << endl;
			cout << "File tranfer timeout: " << sess.ftimeout << endl;
		}
		// timeout command
		else if (basecmd==CMD_TIMEOUT) {
			if (cmd.token(' ',1)==NULL) {
				cerr << "yes, sure. Timeout." << endl;
				continue;
			}

			if (atoi(cmd.token(' ',1))==0) {
				cerr << "Timeout value '" << cmd.token(' ',1) << 
					"' seems to be strange at least" << endl;
				continue;
			} else {
				sess.ctimeout=atoi(cmd.token(' ',1));
				cout << "Command timeout set to " << sess.ctimeout << " seconds" << endl;
			}
		}	
		// pause command
		else if (basecmd==CMD_PAUSE) {
			if (cfg.pause) {
				cfg.pause=false;
				cout << "Disabled" << endl;
			} else {
				cfg.pause=true;
				cout << "Enabled" << endl;
			}
		}
		// printername command
		else if (basecmd==CMD_PRINTERNAME) {
			String	t,w;

			if (!sess.connected()) {
				cout << "not connected" << endl;
				continue;
			}

			if (cmd.token(' ',1)==NULL) {
				cerr << GENERIC_ERROR << endl;
				continue;
			}
			w=cmd.findstr("\"");
			if (w.token('"',1)==NULL) {
				cerr << GENERIC_ERROR << endl;
				continue;
			}
			t=w.token('"',1);
			try {
				sess.change_printer_name(t.get());
				cout << "Printer name set to '" << t.get() << "'" << endl;
			} catch(...) {
				cerr << "ERROR: could not change name" <<endl;
			}
		}	
		// selftest command
		else if (basecmd==CMD_SELFTEST) {
			if (cmd.token(' ',1)==NULL) {
				cerr << "Specify 1-7!" << endl;
				continue;
			}

			if ( (atoi(cmd.token(' ',1))<=0)
				|| (atoi(cmd.token(' ',1))>7)) {
				cerr << "Selftest type '" << cmd.token(' ',1) << 
					"' is not btw 1 and 7" << endl;
				continue;
			} else {
				sess.print_selftest(atoi(cmd.token(' ',1)));
				cout << "Selftest requested" << endl;
			}
		}	
					
		// unknown command
		else {
			cerr << GENERIC_ERROR << endl;
		}

	}
}


void read_command(String *s) {
#define CMDSIZE		4096
	char			command_line[CMDSIZE];

	cin.getline(command_line,CMDSIZE-1);
	s->set(command_line);
}


void usage(char *s) {
	cout << SPLASH << endl;
	cout << s << " [hostname] [{ident}]" << endl;
}

void print_help(char *cc){

	if (cc==NULL) {
		cout  
			<< "\t help <command>\n"
			<< "\t quit\n"

			<< "\t server [hostname]\n"
			<< "\t port [port number]\n"
			<< "\t connect\n"
			<< "\t close\n"

			<< "\t env {read|print|show|set|options|changed|commit|unprotect|bruteforce}\n"
			<< "\t message \"Display Msg\"\n"
			<< "\t failure \"Failure Msg\"\n"

			<< "\t volumes\n"
			<< "\t chvol [vol:]\n"

			<< "\t pwd\n"
			<< "\t ls\n"
			<< "\t cd [directory]\n"
			<< "\t mkdir [directory]\n"
			<< "\t rm [file]\n"
			<< "\t get [file]\n"
			<< "\t put [local file]\n"
			<< "\t append [local file] [file]\n"
			
			<< "\t lpwd\n"
			<< "\t lcd [directory]\n"
			
			<< "\t session\n"
			<< "\t timeout [timeout]\n"
			<< "\t pause"
			<< endl;
	} else {
		String	ts=cc;

		if (ts==CMD_QUIT) {
			cout << "throws you back to whatever you call a shell" << endl;
		} else if (ts==CMD_SERVER) {
			cout
				<< "EXAMPLE: server hplj.company.com\n"
				<< "specifies which PJL server (printer?) you wanne talk to" << endl;
		} else if (ts==CMD_PORT) {
			cout
				<< "EXAMPLE: port 12345\n"
				<< "changes the default port 9100 to whatever you say" << endl;
		} else if (ts==CMD_CONNECT) {
			cout 
				<< "connects you to the server:port you specified" << endl;
		} else if (ts==CMD_CLOSE) {
			cout << "closes your connection" << endl;
		} else if (ts==CMD_ENV) {
			cout 
				<< "The env command accesses the device's environment variables\n"
				<< " env read              Reads the environment from the device.\n"
				<< " env print             Prints what was received completely.\n"
				<< " env show VAR          Prints the content of variable VAR\n"
				<< " env options VAR       Prints the options allowed by the device\n"
				<< "                       for variable VAR\n"
				<< " env set VAR \"VAL\"     Sets the value of VAR to VAL (on client side)\n"
				<< " env changed           Prints all variables that have been changed on\n"
				<< "                       the client side and were not commited yet\n"
				<< " env commit            Writes changed environment variables back\n"
				<< "                       to the device\n"
				<< " env unprotect NUM     Disables PJL protection using the password NUM\n"
				<< " env bruteforce <NUM>  Disables PJL protection using brute force\n"
				<< "                       optionally starting at NUM (default 1)\n"
				<< "NOTE:\n New values for variables are not checked against the options ;)"
				<< endl;
		} else if (ts==CMD_MESSAGE) {
			cout << "Sets a display (ready) message on the device. Have fun." << endl;
		} else if (ts==CMD_FAILURE) {
			cout << "Sets a failure message on the device and makes the device hereby offline"
				<< endl;
		} else if (ts==CMD_VOLUMES) {
			cout << "Lists the available volumes" << endl;
		} else if (ts==CMD_LS) {
			cout << "Lists the files and directories at the current directory" << endl;
		} else if (ts==CMD_CD) {
			cout << "Changes the current working directory. No tricks - just the\n"
				<< " name or .." << endl;
		} else if (ts==CMD_PWD) {
			cout << "Gives your current location in the filesystem"<<endl;
		} else if (ts==CMD_CHVOL) {
			cout << "Changes the current volume.\n"
				<< "Example: chvol 1:" << endl;
		} else if (ts==CMD_RM) {
			cout << "Deletes a file or an empty directory" << endl;
		} else if (ts==CMD_MKDIR) {
			cout << "Creates directory in pwd\n"
				<< "Example: mkdir foo\n" << endl;
		} else if (ts==CMD_LPWD) {
			cout << "prints your local current directory" << endl;
		} else if (ts==CMD_LCD) {
			cout << "changes you local directory to whatever\n"
				<< "Example: lcd .." << endl;
		} else if (ts==CMD_GET) {
			cout << "Receives a file from device and stores it in lpwd\n"
				<< "Example: get run.txt" << endl;
		} else if (ts==CMD_PUT) {
			cout << "Writes a file to the pwd on device from you lpwd" << endl;
		} else if (ts==CMD_APPEND) {
			cout << "Appends the contents of the local file to the specified\n"
				<< "file on remote device. File is created if not exisiting\n"
				<< "Example: append local_file.txt remote_file.txt" << endl;
		} else if (ts==CMD_SESSION) {
			cout << "Prints session settings" << endl;
		} else if (ts==CMD_TIMEOUT) {
			cout << "Sets the command timeout to [n] seconds" << endl;
		} else if (ts==CMD_PAUSE) {
			cout << "Enables or disables pause during ls or env print" << endl;
		} else {
			cout << "No help available for '" << ts.get() << "'" << endl;
		}
	}
}


void commandline_ident(void) {
#ifdef UNIX
	// endable default handler for ctrl-c during connect() call
	signal(SIGINT,SIG_DFL);
#endif //UNIX

	try {
		sess.initiate(cfg.server.get(),cfg.port);
		cout << cfg.server.get() << ":" << cfg.port << "\t";
	} catch (...) {
		cerr << "ERROR: connection failed" << endl;
	}
	// if we are connected, read the device ID now
	if (sess.connected()) {
		try {
			sess.write_ustatus("OFF");
			sess.read_device_id();
			cout << sess.get_device_id()->get() << endl;
		} catch (PJLsession::ExPJLerror) {
			cerr << "ERROR: PJL error while reading device ID" << endl;
		} catch (...) {
			cerr << "ERROR: while requesting device ID" << endl;
		}
	}
	sess.close();
}
