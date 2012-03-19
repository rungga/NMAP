
/***************************************************************************
 * TCPHeader.cc -- The TCPHeader Class represents a TCP packet. It         *
 * contains methods to set the different header fields. These methods      *
 * tipically perform the necessary error checks and byte order             *
 * conversions.                                                            *
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

#include "TCPHeader.h"
#include "nping.h"
#include "common.h"
#include "../libnetutil/netutil.h"


TCPHeader::TCPHeader(){
  this->reset();
} /* End of TCPHeader constructor */


TCPHeader::~TCPHeader(){

} /* End of TCPHeader destructor */

/** Sets every attribute to its default value- */
void TCPHeader::reset(){
  memset(&this->h, 0, sizeof(nping_tcp_hdr_t));
  this->length=20; /* Initial value 20. This will be incremented if options are used */
  this->tcpoptlen=0;
} /* End of reset() */


/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 * TCPHeader::getBufferPointer(){
  return (u8*)(&h);
} /* End of getBufferPointer() */


/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The TCPHeader class is able to hold a maximum of 60 bytes. If the
  * supplied buffer is longer than that, only the first 60 bytes will be stored
  * in the internal buffer.
  * @warning Supplied len MUST be at least 20 bytes (min TCP header length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int TCPHeader::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<TCP_HEADER_LEN){
    return OP_FAILURE;
  }else{
    int stored_len = MIN((TCP_HEADER_LEN + MAX_TCP_OPTIONS_LEN), len);
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=stored_len;
    memcpy(&(this->h), buf, stored_len);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */


/** Performs some VERY BASIC checks that intend to validate the information
  * stored in the internal buffer, as a valid protocol header.
  * @warning If the information stored in the object has been set through a
  * call to storeRecvData(), the object's internal length count may be updated
  * if the validation is successful.
  * @return the length, in bytes, of the header, if its found to be valid or
  * OP_FAILURE (-1) otherwise. */
int TCPHeader::validate(){
  if(this->getOffset()<5)
    return OP_FAILURE;
  else if(this->getOffset()*4 > this->length)
    return OP_FAILURE;
  this->length=this->getOffset()*4;
  return this->length;
} /* End of validate() */


/** Sets source port.
 *  @warning Port must be supplied in host byte order. This method performs
 *  byte order conversion using htons() */
int TCPHeader::setSrcPort(u16 p){
  h.th_sport = htons(p);
  return OP_SUCCESS;
} /* End of setSrcPort() */


/** Returns source port in HOST byte order */
u16 TCPHeader::getSrcPort(){
  return ntohs(h.th_sport);
} /* End of getSrcPort() */


/** Sets destination port.
 *  @warning Port must be supplied in host byte order. This method performs
 *  byte order conversion using htons() */
int TCPHeader::setDstPort(u16 p){
  h.th_dport = htons(p);
  return OP_SUCCESS;
} /* End of setDstPort() */


/** Returns destination port in HOST byte order  */
u16 TCPHeader::getDstPort(){
  return ntohs(h.th_dport);
} /* End of getDstPort() */


/** Sets sequence number.
 *  @warning Seq number must be supplied in host byte order. This method
 *  performs byte order conversion using htonl() */
int TCPHeader::setSeq(u32 p){
  h.th_seq = htonl(p);
  return OP_SUCCESS;
} /* End of setSeq() */


/** Returns sequence number in HOST byte order */
u32 TCPHeader::getSeq(){
  return ntohl(h.th_seq);
} /* End of getSeq() */


/** Sets acknowledgement number.
 *  @warning ACK number must be supplied in host byte order. This method
 *  performs byte order conversion using htonl() */
int TCPHeader::setAck(u32 p){
  h.th_ack = htonl(p);
  return OP_SUCCESS;
} /* End of setAck() */


/** Returns ACK number in HOST byte order */
u32 TCPHeader::getAck(){
  return ntohl(h.th_ack);
} /* End of getAck() */


/* TODO: Test this method. It may not work becuasse th_off is supposed to
 * be 4 bits long and arg o is 8.
 * UPDATE: It seems to work just fine. However, let's keep this note just
 * in case problems arise. */
int TCPHeader::setOffset(u8 o){
  h.th_off = o;
  return OP_SUCCESS;
} /* End of setOffset() */


int TCPHeader::setOffset(){
  h.th_off = 5 + tcpoptlen/4;
  return OP_SUCCESS;
} /* End of setOffset() */


/** Returns offset value */
u8 TCPHeader::getOffset(){
  return h.th_off;
} /* End of getOffset() */


/** Sets TCP flags */
int TCPHeader::setFlags(u8 f){
  h.th_flags = f;
  return OP_SUCCESS;
} /* End of setFlags() */


/** Returns the 8bit flags field of the TCP header */
u8 TCPHeader::getFlags(){
  return h.th_flags;
} /* End of getFlags() */


/** Sets flag CWR
 *  @return Previous state of the flag */
bool TCPHeader::setCWR(){
  u8 prev = h.th_flags & TH_CWR;
  h.th_flags |= TH_CWR;
  return prev;
} /* End of setCWR() */


/** Unsets flag CWR
 *  @return Previous state of the flag */
bool TCPHeader::unsetCWR(){
  u8 prev = h.th_flags & TH_CWR;
  h.th_flags ^= TH_CWR;
  return prev;
} /* End of unsetCWR() */


/** Get CWR flag */
bool TCPHeader::getCWR(){
  return h.th_flags & TH_CWR;
} /* End of getCWR() */


/** Sets flag ECE/ECN
 *  @return Previous state of the flag */
bool TCPHeader::setECE(){
  u8 prev = h.th_flags & TH_ECN;
  h.th_flags |= TH_ECN;
  return prev;
} /* End of setECE() */


/** Unsets flag ECE/ECN
 *  @return Previous state of the flag */
bool TCPHeader::unsetECE(){
  u8 prev = h.th_flags & TH_ECN;
  h.th_flags ^= TH_ECN;
  return prev;
} /* End of unsetECE() */


/** Get CWR flag */
bool TCPHeader::getECE(){
  return  h.th_flags & TH_ECN;
} /* End of getECE() */


/** Same as setECE() but with a different name since there are two possible
 *  ways to call this flag
 *  @return Previous state of the flag */
bool TCPHeader::setECN(){
  u8 prev = h.th_flags & TH_ECN;
  h.th_flags |= TH_ECN;
  return prev;
} /* End of setECN() */


/** Unsets flag ECE/ECN
 *  @return Previous state of the flag */
bool TCPHeader::unsetECN(){
  u8 prev = h.th_flags & TH_ECN;
  h.th_flags ^= TH_ECN;
  return prev;
} /* End of unsetECN() */


/** Get ECN flag */
bool TCPHeader::getECN(){
  return  h.th_flags & TH_ECN;
} /* End of getECN() */


/** Sets flag URG
 *  @return Previous state of the flag */
bool TCPHeader::setURG(){
  u8 prev = h.th_flags & TH_URG;
  h.th_flags |= TH_URG;
  return prev;
} /* End of setURG() */


/** Unsets flag URG
 *  @return Previous state of the flag */
bool TCPHeader::unsetURG(){
  u8 prev = h.th_flags & TH_URG;
  h.th_flags ^= TH_URG;
  return prev;
} /* End of unsetURG() */


/** Get URG flag */
bool TCPHeader::getURG(){
  return  h.th_flags & TH_URG;
} /* End of getURG() */


/** Sets flag ACK
 *  @return Previous state of the flag */
bool TCPHeader::setACK(){
  u8 prev = h.th_flags & TH_ACK;
  h.th_flags |= TH_ACK;
  return prev;
} /* End of setACK() */


/** Unsets flag ACK
 *  @return Previous state of the flag */
bool TCPHeader::unsetACK(){
  u8 prev = h.th_flags & TH_ACK;
  h.th_flags ^= TH_ACK;
  return prev;
} /* End of unsetACK() */


/** Get ACK flag */
bool TCPHeader::getACK(){
  return  h.th_flags & TH_ACK;
} /* End of getACK() */


/** Sets flag PUSH
 *  @return Previous state of the flag */
bool TCPHeader::setPUSH(){
  u8 prev = h.th_flags & TH_PUSH;
  h.th_flags |= TH_PUSH;
  return prev;
} /* End of setPUSH() */


/** Unsets flag PUSH
 *  @return Previous state of the flag */
bool TCPHeader::unsetPUSH(){
  u8 prev = h.th_flags & TH_PUSH;
  h.th_flags ^= TH_PUSH;
  return prev;
} /* End of unetPUSH() */


/** Get PUSH flag */
bool TCPHeader::getPUSH(){
  return  h.th_flags & TH_PUSH;
} /* End of getPUSH() */


/** Sets flag RST
 *  @return Previous state of the flag */
bool TCPHeader::setRST(){
  u8 prev = h.th_flags & TH_RST;
  h.th_flags |= TH_RST;
  return prev;
} /* End of setRST() */


/** Unsets flag RST
 *  @return Previous state of the flag */
bool TCPHeader::unsetRST(){
  u8 prev = h.th_flags & TH_RST;
  h.th_flags ^= TH_RST;
  return prev;
} /* End of unsetRST() */


/** Get RST flag */
bool TCPHeader::getRST(){
  return  h.th_flags & TH_RST;
} /* End of getRST() */


/** Sets flag SYN
 *  @return Previous state of the flag */
bool TCPHeader::setSYN(){
  u8 prev = h.th_flags & TH_SYN;
  h.th_flags |= TH_SYN;
  return prev;
} /* End of setSYN() */


/** Unsets flag SYN
 *  @return Previous state of the flag */
bool TCPHeader::unsetSYN(){
  u8 prev = h.th_flags & TH_SYN;
  h.th_flags ^= TH_SYN;
  return prev;
} /* End of unsetSYN() */


/** Get SYN flag */
bool TCPHeader::getSYN(){
  return  h.th_flags & TH_SYN;
} /* End of getSYN() */


/** Sets flag FIN
 *  @return Previous state of the flag */
bool TCPHeader::setFIN(){
  u8 prev = h.th_flags & TH_FIN;
  h.th_flags |= TH_FIN;
  return prev;
} /* End of setFIN() */


/** Unsets flag FIN
 *  @return Previous state of the flag */
bool TCPHeader::unsetFIN(){
  u8 prev = h.th_flags & TH_FIN;
  h.th_flags ^= TH_FIN;
  return prev;
} /* End of unsetFIN() */


/** Get FIN flag */
bool TCPHeader::getFIN(){
  return  h.th_flags & TH_FIN;
} /* End of getFIN() */


/** Sets window size.
 *  @warning Win number must be supplied in host byte order. This method
 *  performs byte order conversion using htons() */
int TCPHeader::setWindow(u16 p){
   h.th_win = htons(p);
  return OP_SUCCESS;
} /* End of setWindow() */


/** Returns window size in HOST byte order. */
u16 TCPHeader::getWindow(){
  return ntohs(h.th_win);
} /* End of getWindow() */


/** Sets urgent pointer.
 *  @warning Pointer must be supplied in host byte order. This method
 *  performs byte order conversion using htons() */
int TCPHeader::setUrgPointer(u16 l){
  h.th_urp = htons(l);
  return OP_SUCCESS;
} /* End of setUrgPointer() */


/** Returns Urgent Pointer in HOST byte order. */
u16 TCPHeader::getUrgPointer(){
  return ntohs(h.th_urp);
} /* End of getUrgPointer() */


int TCPHeader::setSum(struct in_addr src, struct in_addr dst){
  int bufflen;
  u8 aux[ MAX_TCP_PAYLOAD_LEN ];
  /* FROM: RFC 1323: TCP Extensions for High Performance, March 4, 2009
   *
   * "With IP Version 4, the largest amount of TCP data that can be sent in
   *  a single packet is 65495 bytes (64K - 1 - size of fixed IP and TCP
   *  headers)".
   *
   *  In theory TCP should not worry about the practical max payload length
   *  because it is supposed to be independent of the network layer. However,
   *  since TCP does not have any length field and we need to allocate a
   *  buffer, we are using that value. (Note htat in UDPHeader.cc we do just
   *  the opposite, forget about the practical limitation and allow the
   *  theorical limit for the payload.                                       */
  h.th_sum = 0;

  /* Copy packet contents to a buffer */
  bufflen=dumpToBinaryBuffer(aux, MAX_TCP_PAYLOAD_LEN);

  /* Compute checksum */
  h.th_sum = tcpudp_cksum(&src, &dst, IPPROTO_TCP, bufflen, (char *)aux);

  return OP_SUCCESS;
} /* End of setSum() */


/** @warning Sum is set to supplied value with NO byte ordering conversion
 *  performed. */
int TCPHeader::setSum(u16 s){
  h.th_sum = s;
  return OP_SUCCESS;
} /* End of setSum() */


/** Set the TCP checksum field to a random value, which may accidentally
  * match the correct checksum */
int TCPHeader::setSumRandom(){
  h.th_sum=get_random_u16();
  return OP_SUCCESS;
} /* End of setSumRandom() */

/** Set the TCP checksum field to a random value. It takes the source and
  * destination address to make sure the random generated sum does not
  * accidentally match the correct checksum. This function only handles
  * IPv4 address. */
int TCPHeader::setSumRandom(struct in_addr source, struct in_addr destination){
  u16 correct_csum=0;
  /* Compute the correct checksum */
  this->setSum(source, destination);
  correct_csum=this->getSum();
  /* Generate numbers until one does not match the correct sum */
  while( (h.th_sum=get_random_u16())==correct_csum);
  return OP_SUCCESS;
} /* End of setSumRandom() */


/** Returns the TCP checksum field in NETWORK byte order */
u16 TCPHeader::getSum(){
  return h.th_sum;
} /* End of getSum() */
