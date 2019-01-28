/* FX seine String class 
 *
 * $Id: fxstrings.h,v 1.4 2005/04/21 07:37:28 fx Exp fx $ 
 */

#ifndef __FXSTRINGS_H__
#define __FXSTRINGS_H__

#include "exceptions.h"

class String:BaseExceptions {
    public:
		// Constructor that creates an empty string instance
		String(void);
		// Constructor that creates a string instance initialized with 
		// string *s
		String(char *s);
		// Destructor deletes the string
		~String(void);

		// assign s to be the string
		void set(char *s);
		// assign memory location *s as the string
		// if this location contains a 0 character, the string is the 
		// number of characters until the first 0 character occurance
		// otherwise, the string is terminated after length characters
		// with a 0 char
		void set(void *s, unsigned int length);
		// append string *s to string
		void append(char *s);
		// resets the string and length
		void clear(void);

		// returns the token n with delim as delimiter 
		// If there is no token n, NULL is returned
		char *token(char delim, unsigned int n);
		// returns the n'th token for the string split by delim.
		// If there is no token n, NULL is returned
		char *stoken(char *delim, unsigned int n);
		// removes any \r or \n at the end of the string if they are there
		void chomp(void);
		// returns if the string contains needle
		char *findstr(char *needle);
		// modifies the string by changing multiple spaces to one tab
		void multispace2tab(void);

		// overloads the == operator for comparsion of String objects
		bool operator == (String s);
		// overloads the == operator for comparsion with char * 
		bool operator == (char *other);
		// overloads the = operator for assignments
		void operator = (char *s);
		
		// returns the string
		char *get(void);
		// returns the length of string
		unsigned int length(void);

    private:
		char			*str;
		unsigned int	l;
		/* used for interim returns from methods such as token() */
		char			*ret_val;
};


#endif //__FXSTRINGS_H__
