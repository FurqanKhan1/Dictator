/* 
 *
 * FX of Phenoelit
 * $Id: rawmem.h,v 1.3 2005/04/21 07:37:28 fx Exp fx $ 
 */
#ifndef __RAWMEM_H__
#define __RAWMEM_H__

#include "exceptions.h"

class Rawmem:BaseExceptions {
	public:
		// creates an empty Rawmem instance
		Rawmem(void);
		// creates a Rawmem instance initialized with *src of size bytes
		Rawmem(void *src, unsigned int size);
		// free()s the memory block
		~Rawmem(void);

		// sets rawmem to have to contents of string *src
		// no 0 char is appended 
		void set(char *src);
		// sets rawmem to be *src of size bytes
		void set(void *src,unsigned int size);
		// appends string to rawmem - no 0 char is appendet
		void append(char *src);
		// appends memory block *src of size bytes to rawmem
		void append(void *src, unsigned int size);
		// returns a chunk of rawmem starting at start of size bytes.
		// If size would point outside of rawmem, only the part in
		// rawmem is actually returned and size will be adjusted
		void *chunk(unsigned int start, unsigned int *size);
		// empties rawmem
		void clear(void);
		
		// returns the size of rawmem
		unsigned int length(void);
		// returns the rawmem block pointer
		void *get(void);
		// returns true if character is in rawmem or fals if not
		bool findchr(char c);
		// returns true if string is in rawmem or false if not
		bool findstr(char *str);

		// dumps the contents of rawmem to stdout
		void dump(void);

	private:
		void			*mem;
		unsigned int	len;
		void			*ch;	// for calls to chunk() method

};

#endif //__RAWMEM_H__
