#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static int int2perm(int val)
{
	int i = 0;
	int v = 0;

	while(val) {
		v |= (val % 10) << (i*3);
		val /= 10;
		i++;
	}
	return v;
}

static int perm2int(int val)
{
	int i = 1;
	int v = 0;
	while(val) {
		v = v + (val & 7) * i;
		val >>= 3;
		i *= 10;
	}
	return v;
}

static int file_perm_compare(unsigned long a, unsigned long b)
{
	int fperm = (int)a;
	int bperm = (int)b;

	if(fperm == bperm)
		return 0;

	return (fperm & (~bperm)) ? 1 : -1;
}

static int get_file_mode(const char *path)
{
	int ret;
	struct stat st;

	ret = stat(path, &st);
	if(ret != 0){
		printf("'%s' not exist.", path);
		exit(0);
	}
	ret = st.st_mode & (0xfff);
	return ret;
}

static char cmp_sym[3] = {'<', '=', '>'};

int main(int argc, char **argv)
{
	char s;
	int ret;
	int a;
	int x;
	int mode;
    char *path;

	if(argc < 3) {
		printf("invaild. eg: ./perm 644\n");
		return 0;
	}

    path = argv[1];
	a = atoi(argv[2]);
	x = int2perm(a);
	mode = get_file_mode(path);

	ret = file_perm_compare(mode, x);
	s = cmp_sym[ret + 1];
	printf("perm compare: file '%s' mode(%d) %c %d\n", path, perm2int(mode), s, a);
	return 0;
}

