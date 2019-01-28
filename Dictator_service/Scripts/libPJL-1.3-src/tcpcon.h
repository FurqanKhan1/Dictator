/* TCPcon class 
 * $Id: tcpcon.h,v 1.3 2005/04/21 07:37:28 fx Exp fx $ 
 */
#ifndef __TCPCON_H__
#define __TCPCON_H__

#ifndef UNIX
#include <winsock2.h>
#else 
#include <netinet/in.h>
#include <sys/time.h>
#endif //UNIX

#include "rawmem.h"
#include "exceptions.h"

// recv buffer size
#define TPSIZE				65535
#define DEF_TIMEOUT_SEC		0
#define DEF_TIMEOUT_USEC	100000

class TCPcon:BaseExceptions {
	public:
		Rawmem			sendbuf;
		Rawmem			recvbuf;

		// initializes the instance, Sets the timeout to 
		// default value DEF_TIMEOUT_*, starts WSA socket
		TCPcon(void);
		// destructor: closes connection if still open
		~TCPcon(void);

		// sets the host to connect to. Uses gethostbyname() to resolve the host.
		void set_host(char *host);
		// sets the port to connect to.
		void set_port(unsigned int port);
		
		// timeout set/get functions
		void set_timeout(long sec, long usec);
		long get_timeout_sec(void);
		long get_timeout_usec(void);

		// starting and stopping the connection
		// Obtains a socket and connects to host
		void startconnection(void);
		// closes connection
		void closeconnection(void);
		// returns the connection status
		bool is_connected(void);

		// sending and receiving 
		// Sends the data in sendbuf to a connected host. 
		// Throws ExSocket() or ExInvalid().
		void senddata(void);
		// Receives data into a buffer of TPSIZE size. Throws 
		// ExTimeout() if the receive process times out without 
		// providing any data. Otherwise, the data is appended to
		// recvbuf. For subsequent calls, either the clear() method
		// of recvbuf or the general clear() method must be called
		// to obtain only new data.
		void recvdata(void);
		// Receives exactly one byte or times out
		void recvbyte(void);
		// Receives data using recvdata() until either the timer 
		// run out or the character c is found
		void recvuntilchr(char c, unsigned long timer);
		// Receives data using recvdata() until either the timer 
		// run out or the string *str is found
		void recvuntilstr(char *str, unsigned long timer);
		// Receuves data using recvdata() until the recvbuffer 
		// is at least n bytes in size of timer is reached
		void recvatleast(unsigned int n, unsigned long timer);

		// accessing data
		// Returns recvbuf.get()
		void *get(void);
		// returns recvbuf.length()
		unsigned int length(void);
		// Sets sendbuf.set(void *, unsigned int)
		void set(void *s, unsigned int lengt);
		// Sets sendbuf.set(char *)
		void set(char *s);
		// Clears sendbuf and recvbuf
		void clear(void);
		
		// exceptions
		class ExResolver{};			// could not resolve host 
		class ExSocket{};			// socket(), connect(), send() .... failed
		class ExWinSock{};			// WSA shit didn't work
		class ExTimeout{};			// operation timed out

	private:
		// information you need for connecting
		struct sockaddr_in 	dest;

		// connection handling and other stuff
		int			sfd;
		struct timeval		timeout;

		// status
		bool			connected;
};

#endif //__TCPCON_H__
