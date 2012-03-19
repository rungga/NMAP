/***************************************************************************
 * ncat_broker.c -- --broker and --chat modes.                             *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, and version detection.                                       *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-db or nmap-service-probes.                                    *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                *
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is meant to clarify our *
 * interpretation of derived works with some common examples.  Our         *
 * interpretation applies only to Nmap--we don't speak for other people's  *
 * GPL works.                                                              *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates as well as helping to     *
 * fund the continued development of Nmap technology.  Please email        *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/

/* $Id: ncat_broker.c 21905 2011-01-21 00:04:51Z fyodor $ */

#include "ncat.h"

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifndef WIN32
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#else
#include <fcntl.h>
#endif

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

/* read_fds is the clients we are accepting data from. broadcast_fds is the
   clients were are sending data to. broadcast_fds doesn't include the listening
   socket and stdin. Network clients are not added to read_fds when --send-only
   is used, because they would be always selected without having data read. */
static fd_set read_fds, broadcast_fds;
/* These are bookkeeping data structures that are parallel to read_fds and
   broadcast_fds. */
static fd_list_t read_fdlist, broadcast_fdlist;
static int listen_socket;
static int conn_count = 0;
/* Has stdin seen EOF? */
static int stdin_eof = 0;
static int crlf_state = 0;

static void handle_connection(void);
static void read_and_broadcast(int recv_socket);
static int chat_announce_connect(int fd, const union sockaddr_u *su);
static int chat_announce_disconnect(int fd);
static char *chat_filter(char *buf, size_t size, int fd, int *nwritten);

int ncat_broker(void)
{
#ifdef HAVE_OPENSSL
    SSL_CTX *ctx;
#endif

    /* clear out structs */
    FD_ZERO(&read_fds);
    FD_ZERO(&broadcast_fds);
    zmem(&read_fdlist, sizeof(read_fdlist));
    zmem(&broadcast_fdlist, sizeof(broadcast_fdlist));

#ifndef WIN32
    /* Ignore the SIGPIPE that occurs when a client disconnects suddenly and we
       send data to it before noticing. */
    Signal(SIGPIPE, SIG_IGN);
#endif

#ifdef HAVE_OPENSSL
    if (o.ssl)
        ctx = setup_ssl_listen();
#endif

    /* setup the main listening socket */
    listen_socket = do_listen(SOCK_STREAM, IPPROTO_TCP);

    /* Make our listening socket non-blocking because there are timing issues
     * which could cause us to block on accept() even though select() says it's
     * readable.  See UNPv1 2nd ed, p422 for more.
     */
    unblock_socket(listen_socket);

    /* setup select sets and max fd */
    FD_SET(listen_socket, &read_fds);

    /* we need a list of fds to keep current fdmax */
    init_fdlist(&read_fdlist, sadd(o.conn_limit, 2));
    add_fd(&read_fdlist, listen_socket);
    add_fd(&read_fdlist, STDIN_FILENO);

    init_fdlist(&broadcast_fdlist, o.conn_limit);

    while (1) {
        fd_set fds;
        int i, fds_ready;

        if (o.debug > 1)
            logdebug("Broker connection count is %d\n", conn_count);

        fds = read_fds;
        fds_ready = fselect(read_fdlist.fdmax + 1, &fds, NULL, NULL, NULL);

        if(o.debug > 1)
            logdebug("select returned %d fds ready\n", fds_ready);

        /*
         * FIXME: optimize this loop to look only at the fds in the fd list,
         * doing it this way means that if you have one descriptor that is very
         * large, say 500, and none close to it, that you'll loop many times for
         * nothing.
         */
        for (i = 0; i <= read_fdlist.fdmax && fds_ready > 0; i++) {
            /* Loop through descriptors until there's something to read */
            if (!FD_ISSET(i, &fds))
                continue;

            if (o.debug > 1)
                logdebug("fd %d is ready\n", i);

            if (i == listen_socket) {
                /* we have a new connection request */
                handle_connection();
            } else if (i == STDIN_FILENO || !o.sendonly) {
                /* Handle incoming client data and distribute it. */
                read_and_broadcast(i);
            }

            fds_ready--;
        }
    }

    return 0;
}

/* Accept a connection on a listening socket. Allow or deny the connection.
   If allowed, add the new socket to the watch set. */
static void handle_connection(void)
{
    union sockaddr_u remoteaddr;
    socklen_t ss_len;
    struct fdinfo s = { 0 };

    ss_len = sizeof(remoteaddr.storage);
    errno = 0;
    s.fd = accept(listen_socket, &remoteaddr.sockaddr, &ss_len);

    if (s.fd < 0) {
        if (o.debug)
            logdebug("Error in accept: %s\n", strerror(errno));

        close(s.fd);
        return;
    }

    if (o.verbose) {
        if (o.chat)
            loguser("Connection from %s on file descriptor %d.\n", inet_socktop(&remoteaddr), s.fd);
        else
            loguser("Connection from %s.\n", inet_socktop(&remoteaddr));
    }

    /* Check conditions that might cause us to deny the connection. */
    if (conn_count >= o.conn_limit) {
        if (o.verbose)
            loguser("New connection denied: connection limit reached (%d)\n", conn_count);
        Close(s.fd);
        return;
    }
    if (!allow_access(&remoteaddr)) {
        if (o.verbose)
            loguser("New connection denied: not allowed\n");
        Close(s.fd);
        return;
    }

    /* On Linux the new socket will be blocking, but on BSD it inherits the
       non-blocking status of the listening socket. The socket must be blocking
       for operations like SSL_accept to work in the way that we use them. */
    block_socket(s.fd);

#ifdef HAVE_OPENSSL
    if (o.ssl) {
        s.ssl = new_ssl(s.fd);
        if (SSL_accept(s.ssl) != 1) {
            if (o.verbose) {
                loguser("Failed SSL connection from %s: %s\n",
                        inet_socktop(&remoteaddr), ERR_error_string(ERR_get_error(), NULL));
            }
            SSL_free(s.ssl);
            Close(s.fd);
            return;
        }
    }
#endif

    conn_count++;

    /* Now that a client is connected, pay attention to stdin. */
    if (!stdin_eof)
        FD_SET(STDIN_FILENO, &read_fds);
    if (!o.sendonly) {
        /* add to our lists */
        FD_SET(s.fd, &read_fds);
        /* add it to our list of fds for maintaining maxfd */
        if (add_fdinfo(&read_fdlist, &s) < 0)
             bye("add_fdinfo() failed.");
    }
    FD_SET(s.fd, &broadcast_fds);
    if (add_fdinfo(&broadcast_fdlist, &s) < 0)
         bye("add_fdinfo() failed.");

    if (o.chat)
        chat_announce_connect(s.fd, &remoteaddr);
}

/* Read from recv_fd and broadcast whatever is read to all other descriptors in
   read_fds, with the exception of stdin, listen_socket, and recv_fd itself.
   Handles EOL translation and chat mode. On read error or end of stream,
   closes the socket and removes it from the read_fds list. */
static void read_and_broadcast(int recv_fd)
{
    struct fdinfo *fdn;
    int pending;

    fdn = get_fdinfo(&read_fdlist, recv_fd);
    assert(fdn);

    /* Loop while ncat_recv indicates data is pending. */
    do {
	char buf[DEFAULT_TCP_BUF_LEN];
	char *chatbuf, *outbuf;
	char *tempbuf = NULL;
	fd_set fds;
	int n;

	/* Behavior differs depending on whether this is stdin or a socket. */
	if (recv_fd == STDIN_FILENO) {
	    n = read(recv_fd, buf, sizeof(buf));
	    if (n <= 0) {
		if (n < 0 && o.verbose)
		    logdebug("Error reading from stdin: %s\n", strerror(errno));
		if (n == 0 && o.debug)
		    logdebug("EOF on stdin\n");

		/* Don't close the file because that allows a socket to be
		   fd 0. */
		FD_CLR(recv_fd, &read_fds);
		/* But mark that we've seen EOF so it doesn't get re-added to
		   the select list. */
		stdin_eof = 1;

		return;
	    }

	    if (o.crlf)
		fix_line_endings((char *) buf, &n, &tempbuf, &crlf_state);

	    pending = 0;
	} else {
	    /* From a connected socket, not stdin. */
	    n = ncat_recv(fdn, buf, sizeof(buf), &pending);

	    if (n <= 0) {
		if (o.debug)
		    logdebug("Closing connection.\n");
#ifdef HAVE_OPENSSL
		if (o.ssl && fdn->ssl) {
		    if (n == 0)
			SSL_shutdown(fdn->ssl);
		    SSL_free(fdn->ssl);
		}
#endif
		close(recv_fd);
		FD_CLR(recv_fd, &read_fds);
		rm_fd(&read_fdlist, recv_fd);
		FD_CLR(recv_fd, &broadcast_fds);
		rm_fd(&broadcast_fdlist, recv_fd);

		conn_count--;
		if (conn_count == 0)
		    FD_CLR(STDIN_FILENO, &read_fds);

		if (o.chat)
		    chat_announce_disconnect(recv_fd);

		return;
	    }
        }

	if (o.debug > 1)
	    logdebug("Handling data from client %d.\n", recv_fd);

	chatbuf = NULL;
	/* tempbuf is in use if we read from STDIN and fixed EOL */
	if (tempbuf == NULL)
	    outbuf = buf;
	else
	    outbuf = tempbuf;

	if (o.chat) {
	    chatbuf = chat_filter(outbuf, n, recv_fd, &n);
	    if (chatbuf == NULL) {
		if (o.verbose)
		    logdebug("Error formatting chat message from fd %d\n", recv_fd);
	    } else {
		outbuf = chatbuf;
	    }
	}

	/* Send to everyone except the one who sent this message. */
	fds = broadcast_fds;
	FD_CLR(recv_fd, &fds);
	ncat_broadcast(&fds, &broadcast_fdlist, outbuf, n);

	free(chatbuf);
	free(tempbuf);
	tempbuf = NULL;
    } while (pending);
}

/* Announce the new connection and who is already connected. */
static int chat_announce_connect(int fd, const union sockaddr_u *su)
{
    char *buf = NULL;
    size_t size = 0, offset = 0;
    int i, count, ret;

    strbuf_sprintf(&buf, &size, &offset,
        "<announce> %s is connected as <user%d>.\n", inet_socktop(su), fd);

    strbuf_sprintf(&buf, &size, &offset, "<announce> already connected: ");
    count = 0;
    for (i = 0; i < read_fdlist.fdmax; i++) {
        union sockaddr_u su;
        socklen_t len = sizeof(su.storage);

        if (i == fd || !FD_ISSET(i, &broadcast_fds))
            continue;

        if (getpeername(i, &su.sockaddr, &len) == -1)
            bye("getpeername for sd %d failed: %s.", strerror(errno));

        if (count > 0)
            strbuf_sprintf(&buf, &size, &offset, ", ");

        strbuf_sprintf(&buf, &size, &offset, "%s as <user%d>", inet_socktop(&su), i);

        count++;
    }
    if (count == 0)
        strbuf_sprintf(&buf, &size, &offset, "nobody");
    strbuf_sprintf(&buf, &size, &offset, ".\n");

    ret = ncat_broadcast(&broadcast_fds, &broadcast_fdlist, buf, offset);

    free(buf);

    return ret;
}

static int chat_announce_disconnect(int fd)
{
    char buf[128];
    int n;

    n = Snprintf(buf, sizeof(buf),
        "<announce> <user%d> is disconnected.\n", fd);
    if (n >= sizeof(buf) || n < 0)
        return -1;

    return ncat_broadcast(&broadcast_fds, &broadcast_fdlist, buf, n);
}

/*
 * This is stupid. But it's just a bit of fun.
 *
 * The file descriptor of the sender is prepended to the
 * message sent to clients, so you can distinguish
 * each other with a degree of sanity. This gives a
 * similar effect to an IRC session. But stupider.
 */
static char *chat_filter(char *buf, size_t size, int fd, int *nwritten)
{
    char *result = NULL;
    size_t n = 0;
    const char *p;
    int i;

    n = 32;
    result = (char *) safe_malloc(n);
    i = Snprintf(result, n, "<user%d> ", fd);

    /* Escape control characters. */
    for (p = buf; p - buf < size; p++) {
        char repl[32];
        int repl_len;

        if (isprint((int) (unsigned char) *p) || *p == '\r' || *p == '\n' || *p == '\t') {
            repl[0] = *p;
            repl_len = 1;
        } else {
            repl_len = Snprintf(repl, sizeof(repl), "\\%03o", (unsigned char) *p);
        }

        if (i + repl_len > n) {
            n = (i + repl_len) * 2;
            result = (char *) safe_realloc(result, n + 1);
        }
        memcpy(result + i, repl, repl_len);
        i += repl_len;
    }
    /* Trim to length. (Also does initial allocation when str is empty.) */
    result = (char *) safe_realloc(result, i + 1);
    result[i] = '\0';

    *nwritten = i;

    return result;
}
