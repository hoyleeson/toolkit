all:
	gcc -o perm perm.c
	gcc -o nseg2ip nseg2ip.c
	gcc -o strftime strftime.c
	gcc -o netspeed netspeed.c

clean:
	rm -fr perm nseg2ip strftime netspeed 
