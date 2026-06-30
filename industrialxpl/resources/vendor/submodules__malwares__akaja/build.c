#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void catch(){
    system("gcc ping.c -o ping"); 

    system("sudo ./ping 127.0.0.1"); /*Only usable in linux device*/  
}

int main(){
    catch();
    return 0;
}

