//
//  SSHWrapper.m
//  libssh2-for-iOS
//
//  Created by Felix Schulze on 01.02.11.
//  Copyright 2010 Felix Schulze. All rights reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//
//  @see: http://www.libssh2.org/examples/ssh2_exec.html

#import "SSHWrapper.h"

#include "libssh2.h"
#include "libssh2_config.h"
#include "libssh2_sftp.h"
#include <sys/socket.h>
#include <arpa/inet.h>


unsigned long hostaddr;
int sock;
LIBSSH2_SESSION *session;
LIBSSH2_CHANNEL *channel;
int rc;

static int waitsocket(int socket_fd, LIBSSH2_SESSION *session)
{
    struct timeval timeout;
    int rc;
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd = NULL;
    int dir;
	
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
	
    FD_ZERO(&fd);
	
    FD_SET(socket_fd, &fd);
	
    /* now make sure we wait in the correct direction */
    dir = libssh2_session_block_directions(session);
	
    if(dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;
	
    if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;
	
    rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);
	
    return rc;
}

char *passwordFunc(const char *s)
{
    static char *pw = NULL;
    if (strlen(s)) {
        pw = s;
    } 
    return pw;
}

void keyboard_interactive(const char *name, int name_len, const char *instr, int instr_len, 
                          int num_prompts, const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts, LIBSSH2_USERAUTH_KBDINT_RESPONSE *res, 
                          void **abstract)
{
    res[0].text = strdup(passwordFunc(""));
    res[0].length = strlen(passwordFunc(""));
}

@implementation SSHWrapper

- (NSString*) resolveHost:(NSString*) hostname {
    Boolean result;
    NSArray *addresses;
    NSString *resolvedHost = nil;
    CFHostRef hostRef = CFHostCreateWithName(kCFAllocatorDefault, (CFStringRef)hostname);
    if (hostRef) {
        result = CFHostStartInfoResolution(hostRef, kCFHostAddresses, NULL); // pass an error instead of NULL here to find out why it failed
        if (result == TRUE) {
            addresses = (NSArray*)CFHostGetAddressing(hostRef, &result);
        }
    }
    if (result == TRUE) {
        NSMutableArray *tempDNS = [[NSMutableArray alloc] init];
        for(int i = 0; i < CFArrayGetCount((CFArrayRef)addresses); i++){
            struct sockaddr_in* remoteAddr;
            CFDataRef saData = (CFDataRef)CFArrayGetValueAtIndex((CFArrayRef)addresses, i);
            remoteAddr = (struct sockaddr_in*)CFDataGetBytePtr(saData);
            
            if(remoteAddr != NULL){
                // Extract the ip address
                //const char *strIP41 = inet_ntoa(remoteAddr->sin_addr);
                NSString *strDNS =[NSString stringWithCString:inet_ntoa(remoteAddr->sin_addr) encoding:NSASCIIStringEncoding];
                NSLog(@"RESOLVED %d:<%@>", i, strDNS);
                [tempDNS addObject:strDNS];
                
                if (resolvedHost == nil) resolvedHost = [strDNS retain];
            }
        }
    } else {
        NSLog(@"Not resolved");
    }
    
    return [resolvedHost autorelease];
}

- (int) connectToHost:(NSString *)host port:(int)port user:(NSString *)username password:(NSString *)password {
    host = [self resolveHost:host];

	const char* hostChar = [host cStringUsingEncoding:NSUTF8StringEncoding];
	const char* userChar = [username cStringUsingEncoding:NSUTF8StringEncoding];
	const char* passwordChar = [password cStringUsingEncoding:NSUTF8StringEncoding];

    char *userAuthList;
    const char *fingerprint;
    int i, auth_pw = 0;
    
    (void) passwordFunc(passwordChar); /* save for future use */
    
    hostaddr = inet_addr(hostChar);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in soin;
    soin.sin_family = AF_INET;
    soin.sin_port = htons(port);
    soin.sin_addr.s_addr = hostaddr;
    if (connect(sock, (struct sockaddr*)(&soin),sizeof(struct sockaddr_in)) != 0) {
        fprintf(stderr, "failed to connect!\n");
        return -1;
    }
	
    /* Create a session instance */
    session = libssh2_session_init();
    if (!session)
        return -1;
	
    
    
    
    /* tell libssh2 we want it all done non-blocking */
    libssh2_session_set_blocking(session, 0);
	
    /* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */
    while ((rc = libssh2_session_startup(session, sock)) ==
           LIBSSH2_ERROR_EAGAIN);
    if (rc) {
        fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
        return -1;
    }

    fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_MD5);
    
    // XXX track this, display in an alert if we've not seen it before
    printf("Fingerprint: ");
    for(i = 0; i < 16; i++) {
        printf("%02X:", (unsigned char)fingerprint[i]);
    }
    printf("\n");
    
    libssh2_session_set_blocking(session, 1);
    userAuthList = libssh2_userauth_list(session, userChar, strlen(userChar)); 
    
    printf("%s", userAuthList);
    
    if (strstr(userAuthList, "password") != NULL) {
        auth_pw |= 1;
    }
    if (strstr(userAuthList, "keyboard-interactive") != NULL) {
        auth_pw |= 2;
    }
    if (strstr(userAuthList, "publickey") != NULL) {
        auth_pw |= 4;
    }
    
    if (auth_pw & 1) {
        /* We can authenticate via password */
        if (libssh2_userauth_password(session, userChar, passwordChar)) {
            printf("\tAuthentication by password failed!\n");
            return 1;
        } else {
            printf("\tAuthentication by password succeeded.\n");
        }
    } else if (auth_pw & 2) {
        /* Or via keyboard-interactive */
        if (libssh2_userauth_keyboard_interactive(session, userChar, &keyboard_interactive) ) {
            printf("\tAuthentication by keyboard-interactive failed!\n");
            return 1;
        } else {
            printf("\tAuthentication by keyboard-interactive succeeded.\n");
        }
    } else {
        printf("No supported authentication methods found!\n");
        return 1;
    }
    
    libssh2_session_set_blocking(session, 0);    
	return 0;
}

-(void) setPortForwardFromPort:(unsigned int)localPort toHost:(NSString*)remoteHost onPort:(unsigned int)remotePort {
    const char *local_listenip = "0.0.0.0";
    unsigned int local_listenport = localPort;
//    const char *remote_desthost = "www.iana.org"; // resolved by the server
    const char *remote_desthost = [remoteHost cStringUsingEncoding:NSUTF8StringEncoding]; // "192.0.32.8"
    unsigned int remote_destport = remotePort;        
    
    NSLog(@"%s:%d -> %s:%d", local_listenip, local_listenport, remote_desthost, remote_destport);
        
    int listensock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(local_listenport);
    
    if (INADDR_NONE == (sin.sin_addr.s_addr = inet_addr(local_listenip))) {
        perror("inet_addr");
        close(listensock);
    }
    int sockopt = 1;
    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt));
    socklen_t sinlen=sizeof(sin);
    if (-1 == bind(listensock, (struct sockaddr *)&sin, sinlen)) {
        perror("bind");
        fprintf(stderr, "after-bind");
        close(listensock);
    }
    if (-1 == listen(listensock, 2)) {
        perror("listen");
        close(listensock);
    }
    

    libssh2_session_set_blocking(session, 1);
    
    printf("Waiting for TCP connection on %s:%d...\n",
           inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
    
    int forwardsock = -1;
    forwardsock = accept(listensock, (struct sockaddr *)&sin, &sinlen);
    if (-1 == forwardsock) {
        perror("accept");
        close(forwardsock);
        close(listensock);
    }
    
    const char *shost;
    unsigned int sport;    
    shost = inet_ntoa(sin.sin_addr);
    sport = ntohs(sin.sin_port);
    
    printf("Forwarding connection from %s:%d here to remote %s:%d\n", shost,
           sport, remote_desthost, remote_destport);
    
    channel = libssh2_channel_direct_tcpip_ex(session, remote_desthost,
                                              remote_destport, shost, sport);
    if (!channel) {
        fprintf(stderr, "Could not open the direct-tcpip channel!\n"
                "(Note that this can be a problem at the server!"
                " Please review the server logs.)\n");
        close(forwardsock);
        close(listensock);
        if (channel) libssh2_channel_free(channel);
        return;
    }
    
    /* Must use non-blocking IO hereafter due to the current libssh2 API */
    libssh2_session_set_blocking(session, 0);
    
    int rc, i;
    fd_set fds;
    struct timeval tv;
    ssize_t len, wr;
    char buf[16384];
    
    while (1) {
        FD_ZERO(&fds);
        FD_SET(forwardsock, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        rc = select(forwardsock + 1, &fds, NULL, NULL, &tv);
        if (-1 == rc) {
            perror("select");
            close(forwardsock);
            close(listensock);
            if (channel) libssh2_channel_free(channel);    
            return;
        }
        if (rc && FD_ISSET(forwardsock, &fds)) {
            len = recv(forwardsock, buf, sizeof(buf), 0);
            if (len < 0) {
                perror("read");
                close(forwardsock);
                close(listensock);
                if (channel) libssh2_channel_free(channel);    
                return;
            } else if (0 == len) {
                printf("The client at %s:%d disconnected!\n", shost, sport);
                close(forwardsock);
                close(listensock);
                if (channel) libssh2_channel_free(channel);    
                return;
            }
            wr = 0;
            do {
                i = libssh2_channel_write(channel, buf, len);
                if (i < 0) {
                    fprintf(stderr, "libssh2_channel_write: %d\n", i);
                    close(forwardsock);
                    close(listensock);
                    if (channel) libssh2_channel_free(channel);    
                    return;
                }
                wr += i;
            } while(i > 0 && wr < len);
        }
        while (1) {
            len = libssh2_channel_read(channel, buf, sizeof(buf));
            if (LIBSSH2_ERROR_EAGAIN == len)
                break;
            else if (len < 0) {
                fprintf(stderr, "libssh2_channel_read: %d", (int)len);
                close(forwardsock);
                close(listensock);
                if (channel) libssh2_channel_free(channel);    
                return;
            }
            wr = 0;
            while (wr < len) {
                i = send(forwardsock, buf + wr, len - wr, 0);
                if (i <= 0) {
                    perror("write");
                    close(forwardsock);
                    close(listensock);
                    if (channel) libssh2_channel_free(channel);    
                    return;
                }
                wr += i;
            }
            if (libssh2_channel_eof(channel)) {
                printf("The server at %s:%d disconnected!\n",
                       remote_desthost, remote_destport);
                close(forwardsock);
                close(listensock);
                if (channel) libssh2_channel_free(channel);    
                return;
            }
        }
        
    }
    
}

-(NSString *)executeCommand:(NSString *)command {
	const char* commandChar = [command cStringUsingEncoding:NSUTF8StringEncoding];

	NSString *result;
	
    /* Exec non-blocking on the remove host */
    while( (channel = libssh2_channel_open_session(session)) == NULL &&
		  libssh2_session_last_error(session,NULL,NULL,0) == LIBSSH2_ERROR_EAGAIN )
    {
        waitsocket(sock, session);
    }
    if( channel == NULL )
    {
        fprintf(stderr,"Error\n");
        exit( 1 );
    }
    while( (rc = libssh2_channel_exec(channel, commandChar)) == LIBSSH2_ERROR_EAGAIN )
    {
        waitsocket(sock, session);
    }
    if( rc != 0 )
    {
        fprintf(stderr,"Error\n");
        exit( 1 );
    }
    for( ;; )
    {
        /* loop until we block */
        int rc1;
        do
        {
            char buffer[0x2000];
            rc1 = libssh2_channel_read( channel, buffer, sizeof(buffer) -1 );
            if( rc1 > 0 )
            {
                buffer[rc1] = '\0';
				result = [NSString stringWithCString:buffer encoding:NSASCIIStringEncoding];
            }
        }
        while( rc1 > 0 );
		
        /* this is due to blocking that would occur otherwise so we loop on
		 this condition */
        if( rc1 == LIBSSH2_ERROR_EAGAIN )
        {
            waitsocket(sock, session);
        }
        else
            break;
    }
    while( (rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN )
        waitsocket(sock, session);
	
    libssh2_channel_free(channel);
    channel = NULL;
	
    return result;
	
}

-(int) closeConnection {	
    libssh2_session_disconnect(session,"Normal Shutdown, Thank you for playing");
    libssh2_session_free(session);
	
    close(sock);

    fprintf(stderr, "Connection closed\n");
	
	return 0;
}

@end
