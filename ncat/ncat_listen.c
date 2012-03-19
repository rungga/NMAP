/***************************************************************************
 * ncat_listen.c -- --listen mode.                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2009 Insecure.Com LLC. Nmap is    *
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
 * listed in the included COPYING.OpenSSL file, and distribute linked      *
 * combinations including the two. You must obey the GNU GPL in all        *
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

/* $Id: ncat_listen.c 16410 2010-01-06 05:54:55Z david $ */

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
/* Has stdin seen EOF? */
static int stdin_eof = 0;

static void handle_connection(void);
static int read_stdin(void);
static int read_socket(int recv_fd);

/* The number of connected clients is the difference of conn_inc and conn_dec.
   It is split up into two variables for signal safety. conn_dec is modified
   (asynchronously) only in signal handlers and conn_inc is modified
   (synchronously) only in the main program. get_conn_count loops while conn_dec
   is being modified. */
static unsigned int conn_inc = 0;
static volatile unsigned int conn_dec = 0;
static volatile sig_atomic_t conn_dec_changed;

static void decrease_conn_count(void) {
    conn_dec_changed = 1;
    conn_dec++;
}

static int get_conn_count(void)
{
    unsigned int count;

    /* conn_dec is modified in a signal handler, so loop until it stops
       changing. */
    do {
        conn_dec_changed = 0;
        count = conn_inc - conn_dec;
    } while (conn_dec_changed);
    assert(count <= INT_MAX);

    return count;
}

#ifndef WIN32
static void sigchld_handler(int signum)
{
    while (waitpid(-1, NULL, WNOHANG) > 0)
        decrease_conn_count();
}
#endif

static int ncat_listen_stream(int proto)
{
    int rc;
#ifdef HAVE_OPENSSL
    SSL_CTX *ctx;
#endif

    /* clear out structs */
    FD_ZERO(&read_fds);
    FD_ZERO(&broadcast_fds);
    zmem(&read_fdlist, sizeof(read_fdlist));
    zmem(&broadcast_fdlist, sizeof(broadcast_fdlist));

#ifdef WIN32
    set_pseudo_sigchld_handler(decrease_conn_count);
#else
    /* Reap on SIGCHLD */
    Signal(SIGCHLD, sigchld_handler);
    /* Ignore the SIGPIPE that occurs when a client disconnects suddenly and we
       send data to it before noticing. */
    Signal(SIGPIPE, SIG_IGN);
#endif

#ifdef HAVE_OPENSSL
    if (o.ssl)
        ctx = setup_ssl_listen();
#endif

    /* setup the main listening socket */
    listen_socket = do_listen(SOCK_STREAM, proto);

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

        if(o.debug > 1)
            logdebug("selecting, fdmax %d\n", read_fdlist.fdmax);

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
            } else if(i == STDIN_FILENO) {
                /* Read from stdin and write to all clients. */
                rc = read_stdin();
                if (rc == 0 && o.sendonly)
                    /* There will be nothing more to send. If we're not
                       receiving anything, we can quit here. */
                    return 0;
                if (rc < 0)
                    return 1;
            } else if (!o.sendonly) {
                /* Read from a client and write to stdout. */
                rc = read_socket(i);
                if (rc <= 0 && !o.keepopen)
                    return rc == 0 ? 0 : 1;
            }

            fds_ready--;
        }
    }

    return 0;
}

/* Accept a connection on a listening socket. Allow or deny the connection.
   Fork a command if o.cmdexec is set. Otherwise, add the new socket to the
   watch set. */
static void handle_connection(void)
{
    union sockaddr_u remoteaddr;
    socklen_t ss_len;
    struct fdinfo s = { 0 };
    int conn_count;

    ss_len = sizeof(remoteaddr.storage);
    errno = 0;
    s.fd = accept(listen_socket, &remoteaddr.sockaddr, &ss_len);

    if (s.fd < 0) {
        if (o.debug)
            logdebug("Error in accept: %s\n", strerror(errno));

        close(s.fd);
        return;
    }

    if (o.verbose)
        loguser("Connection from %s.\n", inet_socktop(&remoteaddr));

    /* Check conditions that might cause us to deny the connection. */
    conn_count = get_conn_count();
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

    conn_inc++;

    /*
     * are we executing a command? if so then don't add this guy
     * to our descriptor list or set.
     */
    if (o.cmdexec) {
        netrun(&s, o.cmdexec);
    } else {
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
    }
}

/* Read from stdin and broadcast to all client sockets. Return the number of
   bytes read, or -1 on error. */
int read_stdin(void)
{
    int nbytes;
    char buf[DEFAULT_TCP_BUF_LEN];
    char* tempbuf = NULL;

    nbytes = read(STDIN_FILENO, buf, sizeof(buf));
    if (nbytes <= 0) {
        if (nbytes < 0 && o.verbose)
            logdebug("Error reading from stdin: %s\n", strerror(errno));
        if (nbytes == 0 && o.debug)
            logdebug("EOF on stdin\n");

        /* Don't close the file because that allows a socket to be fd 0. */
        FD_CLR(STDIN_FILENO, &read_fds);
        /* Buf mark that we've seen EOF so it doesn't get re-added to the
           select list. */
        stdin_eof = 1;

        return nbytes;
    }

    if (o.crlf)
        fix_line_endings((char *) buf, &nbytes, &tempbuf);

    if(o.linedelay)
        ncat_delay_timer(o.linedelay);

    /* Write to everything in the broadcast set. */
    if (tempbuf != NULL) {
        ncat_broadcast(&broadcast_fds, &broadcast_fdlist, tempbuf, nbytes);
        free(tempbuf);
        tempbuf = NULL;
    } else
        ncat_broadcast(&broadcast_fds, &broadcast_fdlist, buf, nbytes);
    

    return nbytes;
}

/* Read from a client socket and write to stdout. Return the number of bytes
   read from the socket, or -1 on error. */
int read_socket(int recv_fd)
{
    char buf[DEFAULT_TCP_BUF_LEN];
    struct fdinfo *fdn;
    int nbytes, pending;

    fdn = get_fdinfo(&read_fdlist, recv_fd);
    assert(fdn != NULL);

    nbytes = 0;
    do {
        int n;

        n = ncat_recv(fdn, buf, sizeof(buf), &pending);
        if (n <= 0) {
            if (o.debug)
                logdebug("Closing connection.\n");
#ifdef HAVE_OPENSSL
            if (o.ssl && fdn->ssl) {
                if (nbytes == 0)
                    SSL_shutdown(fdn->ssl);
                SSL_free(fdn->ssl);
            }
#endif
            close(fdn->fd);
            FD_CLR(fdn->fd, &read_fds);
            rm_fd(&read_fdlist, fdn->fd);
            FD_CLR(fdn->fd, &broadcast_fds);
            rm_fd(&broadcast_fdlist, fdn->fd);

            conn_inc--;
            if (get_conn_count() == 0)
                FD_CLR(STDIN_FILENO, &read_fds);

            return n;
        }

        Write(STDOUT_FILENO, buf, n);
        nbytes += n;
    } while (pending);

    return nbytes;
}

/* This is sufficiently different from the TCP code (wrt SSL, etc) that it
 * resides in its own simpler function
 */
static int ncat_listen_dgram(int proto)
{
    int sockfd, fdmax, nbytes, fds_ready;
    char buf[DEFAULT_UDP_BUF_LEN] = {0};
    char* tempbuf = NULL;
    fd_set read_fds;
    union sockaddr_u remotess;
    socklen_t sslen = sizeof(remotess.storage);

    FD_ZERO(&read_fds);

    /* Initialize remotess struct so recvfrom() doesn't hit the fan.. */
    zmem(&remotess.storage, sizeof(remotess.storage));
    remotess.storage.ss_family = o.af;

#ifdef WIN32
    set_pseudo_sigchld_handler(decrease_conn_count);
#else
    /* Reap on SIGCHLD */
    Signal(SIGCHLD, sigchld_handler);
#endif

    while (1) {
        /* create the UDP listen socket */
        sockfd = do_listen(SOCK_DGRAM, proto);

        while (1) {
            int conn_count;

            /*
             * We just peek so we can get the client connection details without
             * removing anything from the queue. Sigh.
             */
            nbytes = Recvfrom(sockfd, buf, sizeof(buf), MSG_PEEK,
                              &remotess.sockaddr, &sslen);

            /* Check conditions that might cause us to deny the connection. */
            conn_count = get_conn_count();
            if (conn_count >= o.conn_limit) {
                if (o.verbose)
                    loguser("New connection denied: connection limit reached (%d)\n", conn_count);
            } else if (!allow_access(&remotess)) {
                if (o.verbose)
                    loguser("New connection denied: not allowed\n");
            } else {
                /* Good to go. */
                break;
            }

            /* Dump the current datagram */
            Recv(sockfd, buf, sizeof(buf), 0);
        }

        conn_inc++;

        /*
         * We're using connected udp. This has the down side of only
         * being able to handle one udp client at a time
         */
        Connect(sockfd, &remotess.sockaddr, sslen);

        /* clean slate for buf */
        zmem(buf, sizeof(buf));

        /* are we executing a command? then do it */
        if (o.cmdexec) {
            struct fdinfo info = { 0 };

            info.fd = sockfd;
            netrun(&info, o.cmdexec);
            continue;
        }

        FD_SET(sockfd, &read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        fdmax = sockfd;

        /* stdin -> socket and socket -> stdout */
        while (1) {
            fd_set fds;

            fds = read_fds;

            if(o.debug > 1)
                logdebug("udp select'ing\n");

            fds_ready = fselect(fdmax + 1, &fds, NULL, NULL, NULL);

            if (FD_ISSET(STDIN_FILENO, &fds)) {
                nbytes = Read(STDIN_FILENO, buf, sizeof(buf));
                if (nbytes < 0) {
                    loguser("%s.\n", strerror(errno));
                    return 1;
                } else if (nbytes == 0) {
                    return 0;
                }
                if (o.crlf)
                    fix_line_endings((char *) buf, &nbytes, &tempbuf);
                if (!o.recvonly) {
                    if (tempbuf != NULL)
                        send(sockfd, tempbuf, nbytes, 0);
                    else
                        send(sockfd, buf, nbytes, 0);
                }
                if (tempbuf != NULL) {
                    free(tempbuf);
                    tempbuf = NULL;
                }
            }
            if (FD_ISSET(sockfd, &fds)) {
                nbytes = recv(sockfd, buf, sizeof(buf), 0);
                if (nbytes < 0) {
                    loguser("%s.\n", socket_strerror(socket_errno()));
                    close(sockfd);
                    return 1;
                }
                if (!o.sendonly)
                    Write(STDOUT_FILENO, buf, nbytes);
            }

            zmem(buf, sizeof(buf));
        }
    }

    return 0;
}

int ncat_listen()
{
    if (o.httpserver)
        return ncat_http_server();
    else if (o.udp)
        return ncat_listen_dgram(IPPROTO_UDP);
    else if (o.sctp)
        return ncat_listen_stream(IPPROTO_SCTP);
    else
        return ncat_listen_stream(IPPROTO_TCP);

    /* unreached */
    return 1;
}
