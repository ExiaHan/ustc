ioRedirect:FORCE
	@gcc  -m32 -o ioRedirect ioRedirect.o
	@sudo chown root:root ioRedirect
	@sudo chmod u+s ioRedirect


FORCE:ioRedirect.c
	@gcc  -m32 -c ioRedirect.c
