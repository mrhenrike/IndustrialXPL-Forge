/*
For this, you won't be needing an actual API/php script on the server to make the calls. You can now do it simply by making API requests to public or private API services, such as api.c99.nl
 
However, you'll need a snippet of code that will parse out the 'Response Headers' so it will only accept the 'Response Body' 

This can easily be found on this current repo under 'headers' named: replace.h
*/

char Geolocate()         {
  fflush(stdin);
  char APBuffer[2048];
  memset(APBuffer, 0, sizeof APBuffer);
  int port = 80;
  char *host = "api.c99.nl"; char *key  = " "; char *tool = "geoip"; char InputAnswer[80];
 
  sprintf(botnet, ""white"Host:"red" ");
  if (send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1); 
  if (fdgets(InputAnswer, sizeof APBuffer, thefd) < 1);
 
  trim(InputAnswer); char *req = {"GET /%s?key=%s&host=%s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n"};
 
    struct hostent *server; 
    struct sockaddr_in srv_addr; 
    int APSocket, bytes, sent, received, total; 
    char message[5000], response[20000]; 
    sprintf(message, req, tool, key, InputAnswer, host);
 
    /* create the socket */
    APSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (APSocket < 0) printf("ERROR opening socket");
    /* lookup the ip address */
    server = gethostbyname(host); 
    if (server == NULL) printf("Error: No Such Host\n");
    /* fill in the structure */
    memset(&srv_addr,0,sizeof(srv_addr)); 
    srv_addr.sin_family = AF_INET; 
    srv_addr.sin_port = htons(port); 
    memcpy(&srv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
    /* connect the socket */
    if (connect(APSocket,(struct sockaddr *)&srv_addr,sizeof(srv_addr)) < 0) printf("Error: Socket Connection Failure\n");
    /* send the request */
    total = strlen(message); sent = 0;
    do {
    bytes = write(APSocket,message+sent,total-sent);
    if (bytes < 0) printf("Error: Failed to write message to socket\n");
    if (bytes == 0) break; sent+=bytes;
    } while (sent < total);
    /* receive the response */
    memset(response,0,sizeof(response)); total = sizeof(response)-1; received = 0;
    do {
        bytes = read(APSocket,response+received,total-received);
        if (bytes < 0) printf("Error: Failed to read response from socket\n");
        if (bytes == 0) break; received+=bytes;
        } while (received < total);
    if (received == total) printf("Error: Failed to store complete response from socket\n");
    /* close the socket */
    char *httpbody; const char *new = replace(response); char OurResponse [500];
    httpbody = strstr(new, "\r\n\r\n"); 
    if(httpbody) httpbody += 4; trim(APBuffer);
    /* process response */
    sleep(1);
    sprintf(OurResponse, "%s\n", httpbody); if(send(thefd, OurResponse, strlen(OurResponse), MSG_NOSIGNAL) == -1); 
    close(APSocket);
    req = '\0'; httpbody = '\0'; new = '\0'; }
