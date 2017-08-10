all:
	gcc -o perm perm.c
	gcc -o nseg2ip nseg2ip.c

clean:
	rm -fr perm nseg2ip
