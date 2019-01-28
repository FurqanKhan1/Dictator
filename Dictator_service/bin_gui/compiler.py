import py_compile
while 1:
	file_name=raw_input("enter file name ")
	if (file_name=="1"):
		break
	py_compile.compile(file_name)
