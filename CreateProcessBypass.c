#include <stdio.h>
#include <Windows.h>

int main()
{
	CreateMutexA(NULL, TRUE, "timb3r");
	printf("You can run the process now.\n");
	getchar();
}