
/***************************************************************************
 * IPv4Header.cc -- The IPv4Header Class represents an IPv4 datagram. It   *
 * contains methods to set any header field. In general, these methods do  *
 * error checkings and byte order conversion.                              *
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
 
#include "IPv4Header.h"
#include "nping.h"
#include "common.h"
#include "common_modified.h"
#include "dnet.h"
#include "utils_net.h"


IPv4Header::IPv4Header() {
  this->reset();
} /* End of IPv4Header constructor */


IPv4Header::~IPv4Header() {

} /* End of IPv4Header destructor */

/** Sets every attribute to its default value- */
void IPv4Header::reset() {
  memset(&this->h, 0, sizeof(nping_ipv4_hdr_t));
  this->ipoptlen=0;
  this->length=20;   /* Initial value 20. This will be incremented if options are used */
  setVersion();
  setHeaderLength();
  setTTL(DEFAULT_IP_TTL);
  setTotalLength();
} /* End of IPv4Header destructor */


/** Sets every IP header field to zero. This affects the IP Header and any
  * options that it contained. After calling this method, the IP header will
  * be a standard 20-byte header with no options. */
void IPv4Header::zero(){
  memset(&h, 0, 20 + MAX_IP_OPTIONS_LEN);
  ipoptlen=0;
  length=20;
} /* End of zero() */


/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 *IPv4Header::getBufferPointer(){
  return (u8*)(&h);
} /* End of getBufferPointer() */

/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The IPv4Header class is able to hold a maximum of 60 bytes. If the
  * supplied buffer is longer than that, only the first 60 bytes will be stored
  * in the internal buffer.
  * @warning Supplied len MUST be at least 20 bytes (min IP header length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int IPv4Header::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<IP_HEADER_LEN){
    return OP_FAILURE;
  }else{
    int stored_len = MIN((IP_HEADER_LEN + MAX_IP_OPTIONS_LEN), len);
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
int IPv4Header::validate(){
  if(this->getVersion()!=4)
    return OP_FAILURE;
  else if( this->getHeaderLength()<5)
    return OP_FAILURE;
  else if( this->getHeaderLength()*4 > this->length)
    return OP_FAILURE;
//else if( this->getTotalLength()==0)
//  return OP_FAILURE;
  this->length=this->getHeaderLength()*4;
  return this->length;
} /* End of validate() */


int IPv4Header::setVersion(){
  h.ip_v   = 4;
  return 4;
} /* End of setVersion() */


u8 IPv4Header::getVersion(){
  return (u8)h.ip_v;
} /* End of getVersion() */


int IPv4Header::setHeaderLength(){
  h.ip_hl  = 5 + (ipoptlen/4);
  return OP_SUCCESS;
} /* End of setHeaderLength() */



int IPv4Header::setHeaderLength(u8 l){
  h.ip_hl  = l;
  return OP_SUCCESS;
} /* End of setHeaderLength() */


u8 IPv4Header::getHeaderLength(){
  return h.ip_hl;
} /* End of getHeaderLength() */


int IPv4Header::setTOS(u8 v){
  h.ip_tos = v;
  return OP_SUCCESS;
} /* End of setTOS() */


u8 IPv4Header::getTOS(){
  return h.ip_tos;
} /* End of getTOS() */


int IPv4Header::setTotalLength(){
  int mylen = 4*getHeaderLength();
  int otherslen=0;

  if (next!=NULL)
      otherslen=next->getLen();
  h.ip_len=htons( mylen+otherslen );
  return OP_SUCCESS;
} /* End of setTotalLength() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int IPv4Header::setTotalLength(u16 l){
  h.ip_len = htons(l);
  return OP_SUCCESS;
} /* End of setTotalLength() */


/** @warning Returned value is already in host byte order. */
u16 IPv4Header::getTotalLength(){
  return ntohs(h.ip_len);
} /* End of getTotalLength() */


/** Sets identification field to a random value */
int IPv4Header::setIdentification(){
  h.ip_id=get_random_u16();
  return OP_SUCCESS;
} /* End of setIdentification() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int IPv4Header::setIdentification(u16 i){
  h.ip_id = htons(i);
  return OP_SUCCESS;
} /* End of setIdentification() */


/** @warning Returned value is already in host byte order. */
u16 IPv4Header::getIdentification(){
  return ntohs(h.ip_id);
} /* End of getIdentification() */


/** Sets fragment offset field to a random value */
int IPv4Header::setFragOffset(){
  /* TODO: Should we check here that i<8192 ? */
  h.ip_off=get_random_u16();
  return OP_SUCCESS;
} /* End of setFragOffset() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int IPv4Header::setFragOffset(u16 i){
  /* TODO: Should we check here that i<8192 ? */
  h.ip_off = htons(i);
  return OP_SUCCESS;
} /* End of setFragOffset() */


/** @warning Returned value is already in host byte order. */
u16 IPv4Header::getFragOffset(){
  return ntohs(h.ip_off);
} /* End of getFragOffset() */


/** Set RF flag */
int IPv4Header::setRF(){
  h.ip_off |= htons(IP_RF);
  return OP_SUCCESS;
} /* End of setRF() */

/** Unset RF flag */
int IPv4Header::unsetRF(){
  h.ip_off ^= htons(IP_RF);
  return OP_SUCCESS;
} /* End of unsetRF() */


/** Get RF flag */
bool IPv4Header::getRF(){
  return h.ip_off & htons(IP_RF);
} /* End of getRF() */


/** Set MF flag */
int IPv4Header::setMF(){
  h.ip_off |= htons(IP_MF);
  return OP_SUCCESS;
} /* End of setMF() */


/** Unset MF flag */
int IPv4Header::unsetMF(){
  h.ip_off ^= htons(IP_MF);
  return OP_SUCCESS;
} /* End of unsetMF() */


/* Get MF flag */
bool IPv4Header::getMF(){
  return h.ip_off & htons(IP_MF);
} /* End of getMF() */


/** Set DF flag */
int IPv4Header::setDF(){
  h.ip_off |= htons(IP_DF);
  return OP_SUCCESS;
} /* End of setDF() */


/** Unset DF flag */
int IPv4Header::unsetDF(){
  h.ip_off ^= htons(IP_DF);
  return OP_SUCCESS;
} /* End of unsetDF() */


/** Get DF flag */
bool IPv4Header::getDF(){
  return h.ip_off & htons(IP_DF);
} /* End of getDF) */


/** Sets TTL field to a random value */
int IPv4Header::setTTL(){
  h.ip_ttl=get_random_u8();
  return OP_SUCCESS;
} /* End of setTTL() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int IPv4Header::setTTL(u8 t){
  h.ip_ttl = t;
  return OP_SUCCESS;
} /* End of setTTL() */


/** @warning Returned value is already in host byte order. */
u8 IPv4Header::getTTL(){
  return h.ip_ttl;
} /* End of getTTL() */


/** Sets field "next protocol" to the supplied value.
 *  @warning: No error checks are made. Make sure the supplied value
 *  corresponds to an actual IANA number. Check
 *  http://www.iana.org/assignments/protocol-numbers/ for more details.      */
int IPv4Header::setNextProto(u8 p){
  h.ip_p = htons(p);
  return OP_SUCCESS;
} /* End of setNextProto() */


/** Sets field "next protocol" to the number that corresponds to the supplied
 *  protocol name. Currently onyl TCP, UDP and ICMP are supported. Any
 *  help to extend this functionality would be appreciated. For a list of all
 *  proto names and numbers check:
 *  http://www.iana.org/assignments/protocol-numbers/                        */
int IPv4Header::setNextProto(const char *p){
  if (p==NULL){
        printf("setNextProto(): NULL pointer supplied\n");
    return OP_FAILURE;
  }
  if( !strcasecmp(p, "TCP") )
        h.ip_p=6;   /* 6=IANA number for proto TCP */

  else if( !strcasecmp(p, "UDP") )
        h.ip_p=17;  /* 17=IANA number for proto UDP */

  else if( !strcasecmp(p, "ICMP") )
        h.ip_p=1;   /* 1=IANA number for proto ICMP */
  else{
        printf("setNextProto(): Invalid protocol number\n");
        return OP_FAILURE;
  }
  return OP_SUCCESS;
} /* End of setNextProto() */


/** Returns next protocol number */
u8 IPv4Header::getNextProto(){
  return h.ip_p;
} /* End of getNextProto() */


/** Computes the IPv4 header checksum and sets the ip_sum field to the right
 *  value. */
int IPv4Header::setSum(){
  h.ip_sum = 0;
  /* ip_checksum() comes from libdnet */
  ip_checksum((void*)&h, 20 + ipoptlen );
  return OP_SUCCESS;
} /* End of setSum() */


/** @warning Sum is set to supplied value with NO byte ordering conversion
 *  performed.
 *  @warning If sum is supplied this way, no error checks are made. Caller is
 *  responsible for the correctness of the value. */
int IPv4Header::setSum(u16 s){
  h.ip_sum = s;
  return OP_SUCCESS;
} /* End of setSum() */


/** Set the checksum field to a random value */
int IPv4Header::setSumRandom(){
  h.ip_sum=get_random_u16();
  return OP_SUCCESS;
} /* End of setRandomSum() */


/** Returns the value of the checksum field.
 *  @warning The returned value is in NETWORK byte order, no conversion is
 *  performed */
u16 IPv4Header::getSum(){
  return h.ip_sum;
} /* End of getSum() */


/** Sets destination IP address.
 *  @warning Destination IP must be supplied in NETWORK byte order. Usually
 *  all regular library functions return IPs in network byte order so there
 *  should be no need to worry.  */
int IPv4Header::setDstIP(u32 d){
  h.ip_dst.s_addr =  d;
  return OP_SUCCESS;
} /* End of getDstIP() */

/** Sets destination IP address.
 *  @warning Destination IP must be supplied in NETWORK byte order. Usually
 *  all regular library functions return IPs in network byte order so there
 *  should be no need to worry.  */
int IPv4Header::setDstIP(struct in_addr d){
  h.ip_dst=d;
  return OP_SUCCESS;
} /* End of getDstIP() */


/** Returns destination ip
 *  @warning Returned value is in NETWORK byte order. */
struct in_addr IPv4Header::getDstIP(){
  return h.ip_dst;
} /* End of getDstIP() */


/** Sets source IP address.
 *  @warning Destination IP must be supplied in NETWORK byte order. Usually
 *  all regular library functions return IPs in network byte order so there
 *  should be no need to worry.  */
int IPv4Header::setSrcIP(u32 d){
  h.ip_src.s_addr =  d;
  return OP_SUCCESS;
} /* End of setSrcIP() */

/** Sets source IP address.
 *  @warning Destination IP must be supplied in NETWORK byte order. Usually
 *  all regular library functions return IPs in network byte order so there
 *  should be no need to worry. */
int IPv4Header::setSrcIP(struct in_addr d){
  h.ip_src=d;
  return OP_SUCCESS;
} /* End of setSrcIP() */


/** Returns source ip
 *  @warning Returned value is in NETWORK byte order. */
struct in_addr IPv4Header::getSrcIP(){
  return h.ip_src;
} /* End of getSrcIP() */


int IPv4Header::setOpts(const char *txt){
  int foo=0;
  int bar=0;
  int ret=0;
  u8 buffer[128];
  char errstr[256];

   if(txt==NULL){
    printf("setOpts(): NULL pointer supplied.\n");
    return OP_FAILURE;
   }

   /* Parse IP options */
   if((ret=parse_ip_options(txt, buffer, 128, &foo, &bar, errstr, sizeof(errstr)))==OP_FAILURE){
    printf("%s\n", errstr);
    return OP_FAILURE;
   }else{
     /* Copy options to our IP header */
     memcpy(h.options, buffer, ret);
     this->ipoptlen=ret;
     this->length += ret;
     this->setHeaderLength();
   }
   return OP_SUCCESS;
} /* End of setOpts() */


u8 *IPv4Header::getOpts(){
  return h.options;
} /* End of getOpts() */


u8 *IPv4Header::getOpts(int *len){
  if(len==NULL)
    printf("getOpts(): NULL pointer supplied.\n");
  *len=ipoptlen;
  return h.options;
} /* End of getOpts() */


int IPv4Header::printOptions(){
  char *p=format_ip_options(this->h.options, this->ipoptlen);
  printf("%s", p);
  return OP_SUCCESS;
} /* End of printOptions() */

char *IPv4Header::getOptionsString(){
  return format_ip_options(this->h.options, this->ipoptlen);
} /* End of getOptionsString() */

