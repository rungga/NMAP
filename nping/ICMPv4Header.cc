
/***************************************************************************
 * ICMPv4Header.cc -- The ICMPv4Header Class represents an ICMP version 4  *
 * packet. It contains methods to set any header field. In general, these  *
 * methods do error checkings and byte order conversion.                   *
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

#include "nping.h"
#include "common.h"
#include "dnet.h"
#include "utils_net.h"
#include "ICMPv4Header.h"


ICMPv4Header::ICMPv4Header() {
  this->reset();
} /* End of ICMPv4Header constructor */


ICMPv4Header::~ICMPv4Header() {

} /* End of ICMPv4Header destructor */


void ICMPv4Header::reset(){
  memset(&this->h, 0, sizeof(nping_icmpv4_hdr_t));
  this->routeradventries=0;
} /* End of reset() */


/** Sets every class attribute to zero */
void ICMPv4Header::zero(){
  memset (&h, 0, sizeof(h) );
  routeradventries=0;
} /* End of zero() */


/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 *ICMPv4Header::getBufferPointer(){
  return (u8*)(&h);
} /* End of getBufferPointer() */


/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The ICMPv4Header class is able to hold a maximum of 1508 bytes.
  * If the supplied buffer is longer than that, only the first 1508 bytes will
  * be stored in the internal buffer.
  * @warning Supplied len MUST be at least 8 bytes (min ICMPv4 header length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int ICMPv4Header::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<ICMP_STD_HEADER_LEN){
    return OP_FAILURE;
  }else{
    int stored_len = MIN((ICMP_STD_HEADER_LEN + ICMP_PAYLOAD_LEN), len);
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=stored_len;
    memcpy(&(this->h), buf, stored_len);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */


int ICMPv4Header::setType(u8 val){
  h.type = val;
  length = getICMPHeaderLengthFromType( val );
  return OP_SUCCESS;
} /* End of setType() */


/** @warning Returned value is in HOST byte order */
u8 ICMPv4Header::getType(){
  return h.type;
} /* End of getType() */


bool ICMPv4Header::validateType(u8 val){
    switch( val ){
        case ICMP_ECHOREPLY:
        case ICMP_UNREACH:
        case ICMP_SOURCEQUENCH:
        case ICMP_REDIRECT:
        case ICMP_ECHO:
        case ICMP_ROUTERADVERT:
        case ICMP_ROUTERSOLICIT:
        case ICMP_TIMXCEED:
        case ICMP_PARAMPROB:
        case ICMP_TSTAMP:
        case ICMP_TSTAMPREPLY:
        case ICMP_INFO:
        case ICMP_INFOREPLY:
        case ICMP_MASK:
        case ICMP_MASKREPLY:
        case ICMP_TRACEROUTE:
            return true;
        break;

        default:
            return false;
        break;
    }
    return false;
} /* End of validateType() */


bool ICMPv4Header::validateType(){
    return validateType( this->h.type );
} /* End of validateType() */


int ICMPv4Header::setCode(u8 val){
  h.code = val;
  return OP_SUCCESS;
} /* End of setCode() */


/** @warning Returned value is in HOST byte order */
u8 ICMPv4Header::getCode(){
  return h.code;
} /* End of getCode() */


/** Given an ICMP Type and a code, determines whether the code corresponds to
  * a RCP compliant code (eg: code 0x03  for "port unreachable" in ICMP
  * Unreachable messages) or just some other bogus code. */
bool ICMPv4Header::validateCode(u8 type, u8 code){
    switch (type){
        case ICMP_ECHOREPLY:
            return (code==0);
        break;

        case ICMP_UNREACH:
            switch( code ){
                case ICMP_UNREACH_NET:
                case ICMP_UNREACH_HOST:
                case ICMP_UNREACH_PROTOCOL:
                case ICMP_UNREACH_PORT:
                case ICMP_UNREACH_NEEDFRAG:
                case ICMP_UNREACH_SRCFAIL:
                case ICMP_UNREACH_NET_UNKNOWN:
                case ICMP_UNREACH_HOST_UNKNOWN:
                case ICMP_UNREACH_ISOLATED:
                case ICMP_UNREACH_NET_PROHIB:
                case ICMP_UNREACH_HOST_PROHIB:
                case ICMP_UNREACH_TOSNET:
                case ICMP_UNREACH_TOSHOST:
                case ICMP_UNREACH_COMM_PROHIB:
                case ICMP_UNREACH_HOSTPRECEDENCE:
                case ICMP_UNREACH_PRECCUTOFF:
                    return true;
            }
        break;

        case ICMP_REDIRECT:
            switch( code ){
                case ICMP_REDIRECT_NET:
                case ICMP_REDIRECT_HOST:
                case ICMP_REDIRECT_TOSNET:
                case ICMP_REDIRECT_TOSHOST:
                    return true;
            }
        break;

        case ICMP_ROUTERADVERT:
            switch( code ){
                case 0:
                case ICMP_ROUTERADVERT_MOBILE:
                    return true;
            }
        break;

        case ICMP_TIMXCEED:
            switch( code ){
                case ICMP_TIMXCEED_INTRANS:
                case ICMP_TIMXCEED_REASS:
                    return true;
            }
        break;

        case ICMP_PARAMPROB:
            switch( code ){
                case ICMM_PARAMPROB_POINTER:
                case ICMP_PARAMPROB_OPTABSENT:
                case ICMP_PARAMPROB_BADLEN:
                    return true;
            }
        break;

        case ICMP_TSTAMP:
        case ICMP_TSTAMPREPLY:
        case ICMP_INFO:
        case ICMP_INFOREPLY:
        case ICMP_MASK:
        case ICMP_MASKREPLY:
        case ICMP_ROUTERSOLICIT:
        case ICMP_SOURCEQUENCH:
        case ICMP_ECHO:
            return (code==0);
        break;

        case ICMP_TRACEROUTE:
            switch( code ){
                case ICMP_TRACEROUTE_SUCCESS:
                case ICMP_TRACEROUTE_DROPPED:
                    return true;
            }
        break;

        default:
            return false;
        break;
    }
    return false;
} /* End of validateCode() */


/** Computes the ICMP header checksum and sets the checksum field to the right
 *  value. */
int ICMPv4Header::setSum(){
  u8 buffer[65535];
  int total_len=0;
  h.checksum = 0;
  
  memcpy(buffer, &h, length);
  
  if( this->getNextElement() != NULL)
    total_len=next->dumpToBinaryBuffer(buffer+length, 65535-length);   
  total_len+=length;
  
  h.checksum = in_cksum((unsigned short *)buffer, total_len);

  return OP_SUCCESS;
} /* End of setSum() */


/** @warning Sum is set to supplied value with NO byte ordering conversion
 *  performed.
 *  @warning If sum is supplied this way, no error checks are made. Caller is
 *  responsible for the correctness of the value. */
int ICMPv4Header::setSum(u16 s){
  h.checksum = s;
  return OP_SUCCESS;
} /* End of setSum() */


/** Set the checksum field to a random value */
int ICMPv4Header::setSumRandom(){
   h.checksum=get_random_u16();
  return OP_SUCCESS;
} /* End of setRandomSum() */


/** Returns the value of the checksum field.
 *  @warning The returned value is in NETWORK byte order, no conversion is
 *  performed */
u16 ICMPv4Header::getSum(){
  return h.checksum;
} /* End of getSum() */



/* Dest unreach/Source quench/Time exceeded **********************************/

/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htonl() */
int ICMPv4Header::setUnused(u32 val){
  h.h3.unused = htonl(val);
  return OP_SUCCESS;
} /* End of setUnused() */


/** @warning Returned value is in HOST byte order */
u32 ICMPv4Header::getUnused(){
  return ntohl( h.h3.unused );
} /* End of getUnused() */



/* Redirect ******************************************************************/
/** @warning Supplied IP MUST be in NETWORK byte order */
int ICMPv4Header::setPreferredRouter(struct in_addr ipaddr){
  h.h3.addr = ipaddr.s_addr;
  return OP_SUCCESS;
} /* End of setPreferredRouter() */


/** @warning Returned IP is in NETWORK byte order */
u32 ICMPv4Header::getPreferredRouter(){
  return h.h3.addr;
} /* End of getPreferredRouter() */



/* Parameter problem *********************************************************/

/** Sets pointer value in Parameter Problem messages */
int ICMPv4Header::setPointer(u8 val){
  h.h3.pointer8_unused24[0] = val;
  return OP_SUCCESS;
} /* End of setPointer() */


/** @warning Returned value is in HOST byte order */
u8 ICMPv4Header::getPointer(){
  return h.h3.pointer8_unused24[0];
} /* End of getPointer() */



/* Router Solicitation *******************************************************/
/* FROM: RFC 1256, ICMP Router Discovery Messages, September 1991

   ICMP Router Solicitation Message

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |     Code      |           Checksum            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                           Reserved                            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htonl() */
int ICMPv4Header::setReserved( u32 val ){
  h.h3.f32= htonl( val );
  return OP_SUCCESS;
} /* End of setReserved() */


/** @warning Returned value is in HOST byte order */
u32 ICMPv4Header::getReserved(){
  return ntohl( h.h3.f32 );
} /* End of getReserved() */



/* Router Advertisement ******************************************************/
/* FROM: RFC 1256, ICMP Router Discovery Messages, September 1991

  ICMP Router Advertisement Message

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |     Code      |           Checksum            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   Num Addrs   |Addr Entry Size|           Lifetime            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Router Address[1]                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                      Preference Level[1]                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Router Address[2]                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                      Preference Level[2]                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                               .                               |
      |                               .                               |
      |                               .                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

int ICMPv4Header::setNumAddresses(u8 val){
  h.h3.num8_size8_time16[0] = val;
  return OP_SUCCESS;
} /* End of setNumAddresses() */


u8 ICMPv4Header::getNumAddresses(){
  return h.h3.num8_size8_time16[0];
} /* End of getNumAddresses() */


int ICMPv4Header::setAddrEntrySize(u8 val){
  h.h3.num8_size8_time16[1] = val;
  return OP_SUCCESS;
} /* End of setAddrEntrySize() */


/** @warning Returned value is in HOST byte order */
u8 ICMPv4Header::getAddrEntrySize(){
  return h.h3.num8_size8_time16[1];
} /* End of getAddrEntrySize() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int ICMPv4Header::setLifetime(u16 val){
  h.h3.f16[1] = htons(val);
  return OP_SUCCESS;
} /* End of setLifetime() */


/** @warning Returned value is in HOST byte order */
u16 ICMPv4Header::getLifetime(){
  return ntohs( h.h3.f16[1] );
} /* End of getLifetime() */


/** @warning Asummes entries have a length of 2*32bits and consist of
 *  two 32bit values.
 *  @warning This method automatically updates field "Number of addreses"
 *  calling this->setNumAddresses(). If you want to place a bogus number
 *  on such field, setNumAddresses() must be called AFTER any calls to
 *  addRouterAdvEntry()
 * */
int ICMPv4Header::addRouterAdvEntry(struct in_addr raddr, u32 pref){
  u32 *pnt1=NULL;
  u32 *pnt2=NULL;

  if ( this->routeradventries >= ((ICMP_PAYLOAD_LEN/8) -1) )
    outFatal(QT_3, "addRouterAdEntry(): Not enough space for more entries");

  /* Get pointer */
  pnt1 = (u32 *)(&(h.data[ this->routeradventries*8]));
  pnt2 = (u32 *)(&(h.data[ this->routeradventries*8 + 4]));

  /* Set info */
  *pnt1 = raddr.s_addr;
  *pnt2 = htonl( pref );

  this->routeradventries++; /* Update entry count */
  length += 8;             /* Update total length of the ICMP packet */
  this->setNumAddresses(  this->routeradventries );
  return OP_SUCCESS;
} /* End of addRouterAdEntry() */


u8 *ICMPv4Header::getRouterAdvEntries(int *num){
  if( this->routeradventries <= 0 )
    return NULL;
  if (num!=NULL)
    *num = this->routeradventries;
  return h.data;
} /* End of getRouterEntries() */


int ICMPv4Header::clearRouterAdvEntries(){
  memset( h.data, 0, ICMP_PAYLOAD_LEN);
  this->routeradventries=0;
  return OP_SUCCESS;
} /* End of clearRouterEntries*/



/* Echo/Timestamp/Mask *******************************************************/
/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int ICMPv4Header::setIdentifier(u16 val){
  h.h3.id_seq[0] = htons(val);
  return OP_SUCCESS;
} /* End of setIdentifier() */


/** @warning Returned value is in HOST byte order */
u16 ICMPv4Header::getIdentifier(){
  return ntohs( h.h3.id_seq[0] );
} /* End of getIdentifier() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int ICMPv4Header::setSequence(u16 val){
  h.h3.id_seq[1]  = htons(val);
  return OP_SUCCESS;
} /* End of setSequence() */


/** @warning Returned value is in HOST byte order */
u16 ICMPv4Header::getSequence(){
  return ntohs( h.h3.id_seq[1] );
} /* End of getSequence() */



/* Timestamp only ************************************************************/

/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htonl() */
int ICMPv4Header::setOriginateTimestamp(u32 val){
  u32 *pnt=NULL;
  pnt = (u32 *)(&(h.data[0]));   /* Point to the first byte of payload */
  *pnt = htonl(val);
  return OP_SUCCESS;
} /* End of setOriginateTimestamp() */


/** @warning Returned value is in HOST byte order */
u32 ICMPv4Header::getOriginateTimestamp(){
  u32 *pnt=NULL;
  pnt = (u32 *)(&(h.data[0]));   /* Point to the first byte of payload */
  return ntohl( *pnt );
} /* End of getOriginateTimestamp() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htonl() */
int ICMPv4Header::setReceiveTimestamp(u32 val){
  u32 *pnt=NULL;
  pnt = (u32 *)(&(h.data[4]));   /* Point to the 5th byte of payload */
  *pnt = htonl(val);
  return OP_SUCCESS;
} /* End of setReceiveTimestamp() */


/** @warning Returned value is in HOST byte order */
u32 ICMPv4Header::getReceiveTimestamp(){
  u32 *pnt=NULL;
  pnt = (u32 *)(&(h.data[4]));   /* Point to the 5th byte of payload */
  return ntohl( *pnt );
} /* End of getReceiveTimestamp() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htonl() */
int ICMPv4Header::setTransmitTimestamp(u32 val){
  u32 *pnt=NULL;
  pnt = (u32 *)(&(h.data[8]));   /* Point to the 9th byte of payload */
  *pnt = htonl(val);
  return OP_SUCCESS;
} /* End of setTransmitTimestamp() */


/** @warning Returned value is in HOST byte order */
u32 ICMPv4Header::getTransmitTimestamp(){
  u32 *pnt=NULL;
  pnt = (u32 *)(&(h.data[8]));   /* Point to the 9th byte of payload */
  return ntohl( *pnt );
} /* End of getTransmitTimestamp() */



/* Traceroute ****************************************************************/

/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int ICMPv4Header::setIDNumber(u16 val){
  h.h3.id_unused[0] = htons(val);
  return OP_SUCCESS;
} /* End of setIDNumber() */


/** @warning Returned value is in HOST byte order */
u16 ICMPv4Header::getIDNumber(){
  return ntohs( h.h3.id_unused[0] );
} /* End of getIDNumber() */



/* Payload *******************************************************************/
int ICMPv4Header::addPayload(const u8 *src, int len){
  if (src == NULL )
    outFatal(QT_3,"addPayload(): NULL pointer supplied.");
  if(len > ICMP_PAYLOAD_LEN || len<0)
    outFatal(QT_3,"addPayload(): Supplied payload is %s.", (len<0) ? "negative" : "too large" );
  memcpy( h.data, src, len );
  length += len; /* Update our total length */
  return OP_SUCCESS;
} /* End of addPayload() */


/** @warning Supplied string MUST be NULL-terminated */
int ICMPv4Header::addPayload(const char *src){
 u8 *pnt = (u8 *)src;
 if(src==NULL)
    return OP_FAILURE;
 addPayload(pnt, strlen(src) );
 return OP_SUCCESS;
} /* End of addPayload() */



/* Miscellanious *************************************************************/

/** Returns the standard ICMP header length for the supplied ICMP message type.
 *  @warning Return value corresponds strictly to the ICMP header, this is,
 *  the minimum length of the ICMP header, variable length payload is never
 *  included. For example, an ICMP Router Advertising has a fixed header of 8
 *  bytes but then the packet contains a variable number of Router Addresses
 *  and Preference Levels, so while the length of that ICMP packet is
 *  8bytes + ValueInFieldNumberOfAddresses*8, we only return 8 because we
 *  cannot guarantee that the NumberOfAddresses field has been set before
 *  the call to this method. Same applies to the rest of types.              */
int ICMPv4Header::getICMPHeaderLengthFromType( u8 type ){

  switch( type ){

        case ICMP_ECHO:
        case ICMP_ECHOREPLY:
            return 8; /* (+ optional data) */
        break;

        case ICMP_UNREACH:
            return 8; /* (+ payload) */
        break;

        case ICMP_SOURCEQUENCH:
            return 8; /* (+ payload) */
        break;

        case ICMP_REDIRECT:
            return 8; /* (+ payload) */
        break;

        case ICMP_ROUTERADVERT:
            return 8; /* (+ value of NumAddr field * 8 ) */
        break;

        case ICMP_ROUTERSOLICIT:
            return 8;
        break;

        case ICMP_TIMXCEED:
            return 8; /* (+ payload) */
        break;

        case ICMP_PARAMPROB:
            return 8; /* (+ payload) */
        break;

        case ICMP_TSTAMP:
        case ICMP_TSTAMPREPLY:
            return 20;
        break;

        case ICMP_INFO:
        case ICMP_INFOREPLY:
            return 8;
        break;

        case ICMP_MASK:
        case ICMP_MASKREPLY:
            return 12;
        break;

        case ICMP_TRACEROUTE:
            return 20;
        break;

        /* Packets with non RFC-Compliant types will be represented as
           an 8-byte ICMP header, just like the types that don't include
           additional info (time exceeded, router solicitation, etc)  */
        default:
            return 8;
        break;
  }
  return 8;
} /* End of getICMPHeaderLengthFromType() */
