/*
 * first attempt to code a linked list object
 * $Id: llist.h,v 1.3 2005/04/21 07:37:28 fx Exp fx $ 
 */

#ifndef __LLIST_H__
#define __LLIST_H__

#include "exceptions.h"
#include "fxstrings.h"

// Generic list element 
// this element has no real functionality and is here to 
// be inherited by other classes such as PJLenv
class ListPrimitive:BaseExceptions {
	public:
		// constructor - might be overwritten 
		ListPrimitive(void);
		// virtual destructor - must be overwritten
		virtual ~ListPrimitive(void);

		// virtual method print() provides a way to 
		// output the list
		virtual void print(void);

		// set_next() method assigns a new value to *next
		void set_next(ListPrimitive *attach);
		// get_next method returns the value of *next
		ListPrimitive *get_next(void);

	private:
		ListPrimitive	*next;
};


// class for generic linked lists
// this class provides all features of a linked list for 
// a generic element ListPrimitive or a class based uppon 
// this
class LinkList:BaseExceptions {
	public:

		// creates and initializes the list
		LinkList(void);
		// destroys the list
		~LinkList(void);

		// clears the list
		void clear();
		// add_front() method adds the primitive *prim to
		// the top of the list. *prim the becomes *anchor
		void add_front(ListPrimitive *prim);
		// add_end() mathod appends the primitive to the 
		// end of the list
		void add_end(ListPrimitive *prim);
		
		// returns the number of elements in the list
		unsigned int count(void);

		// returns the current value of *current
		ListPrimitive *get_current(void);
		// retrieves a pointer to the element 
		// with number num
		ListPrimitive *element(unsigned int num);

		// prints all list contents 
		void dump(void);

	private:
		ListPrimitive	*anchor;
		ListPrimitive	*current;
};


// List primitive class 
// for storing strings as list members
class StringElement: public ListPrimitive {
	public:
		virtual ~StringElement(void);

		virtual void print(void);
		void set(char *str);
		char *get(void);
		
	private:
		String	s;
		
};


#endif //__LLIST_H__
