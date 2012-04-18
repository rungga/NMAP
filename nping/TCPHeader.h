
/***************************************************************************
 * TCPHeader.h -- The TCPHeader Class represents a TCP packet. It contains *
 * methods to set the different header fields. These methods tipically     *
 * perform the necessary error checks and byte order conversions.          *
 *                                                                         *
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

#ifndef __TCPHEADER_H__
#define __TCPHEADER_H__ 1

#include "TransportLayerElement.h"

/* TCP FLAGS */
#define TH_FIN   0x01
#define TH_SYN   0x02
#define TH_RST   0x04
#define TH_PUSH  0x08
#define TH_ACK   0x10
#define TH_URG   0x20
#define TH_ECN   0x40
#define TH_CWR   0x80

#define TCP_HEADER_LEN 20
#define MAX_TCP_OPTIONS_LEN 40

class TCPHeader : public TransportLayerElement {

    private:

        struct nping_tcp_hdr {
            u16 th_sport;                      /* Source port                 */
            u16 th_dport;                      /* Destination port            */
            u32 th_seq;                        /* Sequence number             */
            u32 th_ack;                        /* Acknowledgement number      */
            #if WORDS_BIGENDIAN
                u8 th_off:4;                   /* Data offset                 */
                u8 th_x2:4;                    /* Reserved                    */
            #else
                u8 th_x2:4;                    /* Reserved                    */
                u8 th_off:4;                   /* Data offset                 */
            #endif
            u8 th_flags;                       /* Flags                       */
            u16 th_win;                        /* Window size                 */
            u16 th_sum;                        /* Checksum                    */
            u16 th_urp;                        /* Urgent pointer              */

            u8 options[MAX_TCP_OPTIONS_LEN ];  /* Space for TCP Options       */
        }__attribute__((__packed__));

        typedef struct nping_tcp_hdr nping_tcp_hdr_t;

        nping_tcp_hdr_t h;

        struct tcpopt_hdr {
            u_char type;   /* type   */
            u_char len;    /* length */
            u_short value; /* value  */
        };

        int tcpoptlen; /**< Length of TCP options */

    public:

        TCPHeader();
        ~TCPHeader();
        void reset();
        u8 *getBufferPointer();
        int storeRecvData(const u8 *buf, size_t len);
        int validate();

        int setSrcPort(u16 p);
        u16 getSrcPort();

        int setDstPort(u16 p);
        u16 getDstPort();

        int setSeq(u32 p);
        u32 getSeq();

        int setAck(u32 p);
        u32 getAck();

        int setOffset(u8 o);
        int setOffset();
        u8 getOffset();

        int setFlags(u8 f);
        u8 getFlags();
        bool setCWR();
        bool unsetCWR();
        bool getCWR();
        bool setECE();
        bool unsetECE();
        bool getECE();
        bool setECN();
        bool unsetECN();
        bool getECN();
        bool setURG();
        bool unsetURG();
        bool getURG();
        bool setACK();
        bool unsetACK();
        bool getACK();
        bool setPUSH();
        bool unsetPUSH();
        bool getPUSH();
        bool setRST();
        bool unsetRST();
        bool getRST();
        bool setSYN();
        bool unsetSYN();
        bool getSYN();
        bool setFIN();
        bool unsetFIN();
        bool getFIN();

        int setWindow(u16 p);
        u16 getWindow();

        int setUrgPointer(u16 l);
        u16 getUrgPointer();

        int setSum(u16 s);
        int setSum(struct in_addr source, struct in_addr destination);
        int setSumRandom();
        int setSumRandom(struct in_addr source, struct in_addr destination);
        u16 getSum();

}; /* End of class TCPHeader */

#endif /* __TCPHEADER_H__ */