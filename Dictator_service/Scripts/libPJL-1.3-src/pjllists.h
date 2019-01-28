/* PJL lists 
 * $Id: pjllists.h,v 1.3 2005/04/21 07:37:28 fx Exp fx $ 
 */

#ifndef __PJLLISTS_H__
#define __PJLLISTS_H__

#include "fxstrings.h"
#include "llist.h"

// PJLenvPrim class 
// This class holds the environment variables of the PJL device 
// and their current settings. It also contains a list of possible
// values for the specific variable
class PJLenvPrim: public ListPrimitive {
	public:
		virtual ~PJLenvPrim(void);

		virtual void print(void);

		// sets the name of this variable
		void set_var(char *str);
		// sets the value of this variable
		void set_val(char *str);
		// sets the language specification 
		void set_lang(char *str);
		// returns the name of this variable
		String * get_var(void);
		// returns the value of this variable
		String * get_val(void);
		// returns the language specification for the variable (if any)
		String * get_lang(void);
		// sets the "changed" variable
		void set_changed(bool yesno);
		// returns the status of the changed variable
		bool get_changed(void);
		// sets the "range" value (true=RANGE, false =ENUMERATED)
		void set_range(bool yesno);
		// gets the "range" value
		bool get_range(void);

		// returns the number of elements in the options list
		unsigned int options_count(void);
		// returns the option with number num
		char *option(unsigned int num);
		// adds an option to the list options
		void option_add(char *str);

	private:
		String		variable;
		String		value;
		String		lang;
		LinkList	options;
		bool		changed;
		bool		range;
};


// PJLenv class
// Inherited from LinkList, it provides access to the environment
// variables via a convinient object instance 
class PJLenv: public LinkList {
	public:
		// all methods just overloaded from LinkList 
		void add_front(PJLenvPrim *e);
		void add_end(PJLenvPrim *e);
		PJLenvPrim *get_current(void);
		PJLenvPrim *element(unsigned int num);
		PJLenvPrim *element(char *vname);

		// returns the pointer to *value according to *var
		String * operator[] (char *var);

	private:
};


// PJLvolPrim
// ListPrimitive class for storing file system information
// from the printer
class PJLvolPrim: public ListPrimitive {
	public:
		virtual ~PJLvolPrim(void);
		virtual void print(void);

		void set_volume(char *str);
		void set_size(char *str);
		void set_free(char *str);
		void set_location(char *str);
		void set_label(char *str);
		void set_status(char *str);

		String *get_volume(void);
		String *get_size(void);
		String *get_free(void);
		String *get_location(void);
		String *get_label(void);
		String *get_status(void);

	private:
		String		volume;
		String		size;
		String		free;
		String		location;
		String		label;
		String		status;
};


// PJLvol 
// LinkList class to handle volumes found on the PJL device
class PJLvol: public LinkList {
	public:
		void add_front(PJLvolPrim *e);
		void add_end(PJLvolPrim *e);
		PJLvolPrim *element(unsigned int num);
		PJLvolPrim *element(char *vname);
};


// PJLfilePrim
// ListPrimitive class for storing directory contents
class PJLfilePrim: public ListPrimitive {
	public:
		PJLfilePrim(void);
		virtual ~PJLfilePrim(void);
		virtual void print(void);

		void set_name(char *str);
		void set_type(int t);
		void set_size(unsigned int s);

		String *get_name(void);
		int get_type(void);
		unsigned int get_size(void);

	private:
		String			name;
		int				type;
		unsigned int	size;
};


// PJLfile
// LinkList class to hold file infos
class PJLfile: public LinkList {
	public:
		void add_front(PJLfilePrim *e);
		void add_end(PJLfilePrim *e);
		PJLfilePrim *element(unsigned int num);
		PJLfilePrim *element(char *vname);
};


#endif //__PJLLISTS_H__
