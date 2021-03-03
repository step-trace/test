#include <stdio.h>

int main(int argc, char* argv[]){
	int a = 10;
	int cube[3][3][3] = {
		{{1, 2, 3}, {4, 5, 6},{7, 8, 9}},
		{{10, 11, 12}, {13, 14, 15},{16, 17, 18}},
		{{19, 20, 21}, {22, 23, 24},{25, 26, 27}}
	};
	int *p = &a;
	a = *p + 10;
	int *ptr = &cube[0][0][0];
	int **m = &ptr;
	int ***q = &m;
	*(*(*(cube + 1) + 1) + 1) = 555;
	printf("%d\n", *(ptr + 1*3*3 + 1*3 + 1));
	printf("%d\n", *(*(*(cube + 1) + 1) + 1));
	printf("%d\n", *(*(*((int(*)[3][3])(&cube[0][0][0]) + 1) + 1) + 1));
	printf("%d\n", *(*(*(cube + 2) ) + 1));
	printf("%p\n", *(cube + 1));
	printf("%d\n", ***q);
	return 0;
}