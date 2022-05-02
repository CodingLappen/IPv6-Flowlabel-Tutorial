# How to IPV6 Flowlabel

This is a documentation for public use, for setting the ipv6 flowlabel.
From my experience that is not a straight forward task, you have to do some research and mind many things, that I will describe in this project.

## Getting started
In this section there are mutliple steps needed to setup the flowlabel sending.

###  Libraries to include and variables to set.
The variables need to be 32 Bit integer number,
because the syscall does not accept other sizes.
It shouldn't matter if a unsigned or signed integer,
because the numbers 0 and 1 are the same in either 
number representation.
```c
#ifndef IPV6_FLOWINFO_SEND
#define IPV6_FLOWINFO_SEND 33 
#endif
#ifndef IPV6_FLOWINFO
#define IPV6_FLOWINFO 11
#endif
/* Glibc weirdness */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/in6.h>
#include <stdio.h>
#include <errno.h>
#include <types.h>
uint32_t on=1;
uint32_t off=0;
```
###  Enabling sending the flowlabel per socket. 
Following syscalls enable the sending and receiving of flowlabels. 
```c
if(setsockopt(sockfd, IPPROTO_IPV6, IPV6_FLOWINFO_SEND,
                    (const char*)&on, sizeof(on)) < 0) {
        perror("FLOWINFO_SEND failed.");
}
if(setsockopt(sockfd, IPPROTO_IPV6, IPV6_FLOWINFO,
                    (const char*)&on, sizeof(on)) < 0) {
	perror("FLOWINFO failed.");
}
if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_AUTOFLOWLABEL,
        &off, sizeof(off))){
	perror("AUTFLOWLABEL failed.");
    }
```
## Reserving a flowlabel
To reserve flowlabels following function was defined as kind of a macro:
```c
int flowlabel_get(int fd, uint32_t label, uint8_t share, uint16_t flags, struct in6_addr * addr)
{
	struct in6_flowlabel_req req = {
		.flr_action = IPV6_FL_A_GET,
		.flr_label = htonl(label),
		.flr_flags = flags,
		.flr_share = share,
	};
	memset(&req.flr_dst.s6_addr,0,sizeof(req.flr_dst.s6_addr));
    	if (addr !=NULL) {
        	memcpy(&req.flr_dst,addr ,sizeof(struct in6_addr));
    	}
	/* do not pass IPV6_ADDR_ANY or IPV6_ADDR_MAPPED */
	return setsockopt(fd, SOL_IPV6, 32, &req, sizeof(req));
}
```
The first argument socket descriptor, the second is the flowlabel and the fifth is the ipv6 address.
The third indicates that the flowlabel is either exclusive, exclusive to the user or that anyone can use it.
The fourth argument are flags, that either indicate, if a flowlabel should be allocated (created) or not and if an shared label should be acquired exclusively.

Following use cases are described.
```c
/* fd is the socket file descriptor */
/* addr is the ipv6 address */
uint32_t flowlabel=7432; // Can be 20 bits long
if (((1<<32 | i<<32-1)-(i<<21)-1) &flowlabel ){
	perror("flowlabel to large");
	return -1;
}
int res;
/* Create the a new label, so anyone has access */
res= flowlabel_get(fd,flowlabel,IPV6_FL_S_ANY,IPV6_FL_F_CREATE,addr);
/* Get the label, if the flowlabel has been created, it doesn't matter if you call it with the flag.*/
res= flowlabel_get(fd,flowlabel,IPV6_FL_S_ANY,0,addr);
/* Get it exclusively */
res= flowlabel_get(fd,flowlabel,IPV6_FL_S_ANY,IPV6_FL_F_EXCL,addr);
/* Create an exclusive label  */
res= flowlabel_get(fd,flowlabel,IPV6_FL_S_EXCL,IPV6_FL_F_CREATE,addr);
/* Create an user exclusive label */
res= flowlabel_get(fd,flowlabel,IPV6_FL_S_USER,IPV6_FL_F_CREATE,addr);
/* Create an process exclusive label */
res= flowlabel_get(fd,flowlabel,IPV6_FL_S_PROCESS,IPV6_FL_F_CREATE,addr);
/* Make an label process exclusive */
res= flowlabel_get(fd,flowlabel,IPV6_FL_S_PROCESS,0,addr);
```

After an label has been allocated exclusively, make sure the reference has been deleted later,
so an label can be allocated exclusively later and exclusive locks are later freed.
The call is defined in the following function.
```c
static int flowlabel_put(int fd, uint32_t label)
{
	struct in6_flowlabel_req req = {
		.flr_action = IPV6_FL_A_PUT,
		.flr_label = htonl(label),
	};
	return setsockopt(fd, SOL_IPV6, IPV6_FLOWLABEL_MGR, &req, sizeof(req));
}
```

### Sending a packet with flowlabel
If you want to send packet with a flowlabel enabled,
you have to enable the flowlabel in the address struct.
```c
#include <string.h>
struct sockadddr_in6 addr;
const char * const buffer="Hello World!";
const char * const addr_s ="3a:3a:3a:3a:3a:3a";
inet_pton(AF_INET6, addr_s,&(addr.sin6_addr));
addr.sin6_family=AF_INET6;
t.sin6_port=55;
t.sin6_scope_id=0;
t.sin6_flowinfo=htonl(flowlabel & IPV6_FLOWINFO_FLOWLABEL);
flowlabel_get(fd,flowlabel,IPV6_FL_S_ANY,IPV6_FL_F_CREATE,&t.sin6_addr);
sendto(fd,buffer, strlen(buffer), 0, &addr_s,sizeof(addr_s));
flowlabel_put(fd,flowlabel);
```

Another method is the set the FLOWINFO within a cmsghdr header struct of the msghdr struct when using sendmsg instead of sendto.
```
struct msghdr msg = {0};
struct cmsghdr *cm;
/* Allocate the buffer for the flowlabel */
char control[CMSG_SPACE(sizeof(flowlabel))] = {0};
cm = (void *)control;
cm->cmsg_len = CMSG_LEN(sizeof(flowlabel));
cm->cmsg_level = SOL_IPV6;
cm->cmsg_type = IPV6_FLOWINFO;
*(uint32_t *)CMSG_DATA(cm) = htonl(flowlabel);

msg.msg_control = control;
msg.msg_controllen = sizeof(control);
```
### Receiving flowlabels
Receiving the flowlabel is the reversal to the previous section.
If you want to extract it with the recvfrom function,  use a
struct sockaddr\_storage to determine if actually IPv6 was used instead of a normal socket.
After checking for the address family, you can cast it.
```c
// This code is not tested, but should work regardless.
// sd is the socket descriptor.
struct sockaddr_storage saddr;
struct sockaddr_in6 * pointer;
char buffer[1024];
size_t length =sizeof(struct sockaddr_storage);
recvfrom(sd,buffer, sizeof(buffer) ,MSG_WAITALL, &saddr, &length);
if (saddr.ss_family == AF_INET6){
	pointer=&addr;
	printf("Flowinfo: %d",ntohl(pointer->sin6_flowinfo));
	fflush(stdout);
}
```
When using the recv\_msg function extract the the from the cmsghdr struct.
```c
// This code is not tested, but should work regardless.
// See the first source for actual use.
struct msghdr msg = {0};
ret = recvmsg(fd, &msg, 0);
char control[CMSG_SPACE(sizeof(uint32_t))];
struct cmsghdr *cm;
msg.msg_control = control;
msg.msg_controllen = sizeof(control);
cm = CMSG_FIRSTHDR(&msg);
while(cm!=NULL){
	if (cm->cmsg_level == SOL_IPV6 || cm->cmsg_type == IPV6_FLOWINFO){
		printf("Flowinfo: %d",ntohl(*(uint32_t*)CMSG_DATA(cm)));
		fflush(stdout);
	}
	cm=CMSG_NXTHDR(&msg,cm);
}
```
## Example

```c
/*
	IPv6 multicast example - ipv6_multicast_send.c
	2012 - Bjorn Lindgren <nr@c64.org>
	https://github.com/bjornl/ipv6_multicast_example
*/

int
main(int argc, char *argv[])
{
	struct sockaddr_in6 saddr;
	struct ipv6_mreq mreq;
	char buf[1400];
	ssize_t len = 1;
	int sd,fd,off = 0, on = 1, hops = 255, ifidx = 0;
	unsigned int flowlabel=666;
	unsigned char random;
	if (argc < 3) {
		printf("\nUsage: %s <address> <port>\n\nExample: %s ff02::5:6 12345\n\n", argv[0], argv[0]);
		return 1;
	}
	sd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sd < 0) {
		perror("socket");
		return 1;
	}
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &on, sizeof(on)) == -1) {
        	printf("setsockopt(IPV6_FLOWINFO_SEND): %s\n", strerror(errno));
        	return 1;
    	}
    	if (setsockopt(sock, IPPROTO_IPV6, IPV6_FLOWINFO, &on, sizeof(on)) == -1) {
    	    printf("setsockopt(IPV6_FLOWINFO): %s\n", strerror(errno));
    	    return 1;
    	}
	if (setsockopt(sd, SOL_IPV6, IPV6_AUTOFLOWLABEL, &off, sizeof(off))) {
		perror("setsockopt autoflowlabel");
		return 1;
	}
	if (flowlabel_get(sd, flowlabel,  IPV6_FL_S_ANY, IPV6_FL_F_CREATE, &(saddr.sin6_addr)) != 0) {
		perror("flowlabelget");
	}
	memset(&saddr, 0, sizeof(struct sockaddr_in6));
	saddr.sin6_family = AF_INET6;
	saddr.sin6_port = htons(atoi(argv[2]));
	saddr.sin6_flowinfo = htonl(flowlabel & IPV6_FLOWINFO_FLOWLABEL);
	inet_pton(AF_INET6, argv[1], &saddr.sin6_addr);
	fd = open("/dev/stdin"  , O_RDONLY, NULL);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	while (len) {
		len = read(fd, buf, 1400);
		get_flow_labels(sd);
		/* printf("read %zd bytes from fd\n", len); */
		if (!len) {
			break;
		} else if (len < 0) {
			perror("read");
			return 1;
		} else {
			len = sendto(sd, buf, len, 0, (const struct sockaddr *) &saddr, sizeof(saddr));
			/* printf("sent %zd bytes to sd\n", len); */
			usleep(10000); /* rate limit, 10000 = 135 kilobyte/s */
		}
	}
	if (flowlabel_put(sd, 366)) != 0) { 
		perror("flowlabelput");
	}
	close(sd);
	close(fd);
	return 0;
}
```

## Sources

[https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/net/ipv6_flowlabel.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/net/ipv6_flowlabel.c)

[https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/net/ipv6_flowlabel_mgr.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/net/ipv6_flowlabel_mgr.c)

[https://github.com/bjornl/ipv6_multicast_example](https://github.com/bjornl/ipv6_multicast_example)
