
/***************************************************************************
 * PacketElement.h -- The PacketElement Class is a generic class that      *
 * represents a protocol header or a part of a network packet. Many other  *
 * classes inherit from it (NetworkLayerElement, TransportLayerElement,    *
 * etc).                                                                   *
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

#ifndef PACKETELEMENT_H
#define PACKETELEMENT_H  1

#include "nping.h"
#include "nbase.h"
#include "output.h"

class PacketElement {

  protected:

    int length;
    PacketElement *next;    /**< Next PacketElement (next proto header)      */
    PacketElement *prev;    /**< Prev PacketElement (previous proto header)  */

  public:

    PacketElement();
    ~PacketElement();

    /** This function MUST be overwritten on ANY class that inherits from
      *  this one. Otherwise getBinaryBuffer will fail */
    virtual u8 * getBufferPointer(){
        outFatal(VB_1,"getBufferPointer(): Attempting to use superclass PacketElement method.\n");
        return NULL;
     } /* End of getBufferPointer() */


    /** Returns a buffer that contains the header of the packet + all the
     *  lower level headers and payload. Returned buffer should be ok to be
     *  passes to a send() call to be transferred trough a socket.
     *  @return a pointer to a free()able buffer that contains packet's binary
     *  data.
     *  @warning If there are linked elements, their getBinaryBuffer() method
     *  will be called recursively and the buffers that they return WILL be
     *  free()d as soon as we copy the data in our own allocated buffer.
     *  @warning Calls to this method may not ve very efficient since they
     *  always involved a few malloc()s and free()s. If you want efficiency
     *  use dumpToBinaryBuffer(); */
    virtual u8 * getBinaryBuffer(){
      u8 *ourbuff=NULL;
      u8 *othersbuff=NULL;
      u8 *totalbuff=NULL;
      long otherslen=0;

      /* Get our own buffer address */
      if ( (ourbuff=getBufferPointer()) == NULL ){
          outFatal(VB_1,"getBinaryBuffer(): Couldn't get own data pointer\n");
      }
      if( next != NULL ){ /* There is some other packet element */
        othersbuff = next->getBinaryBuffer();
        otherslen=next->getLen();
        totalbuff=(u8 *)safe_zalloc(otherslen + length);
        memcpy(totalbuff, ourbuff, length);
        memcpy(totalbuff+length, othersbuff, otherslen);
        free(othersbuff);
      }else{
           totalbuff=(u8 *)safe_zalloc(length);
           memcpy(totalbuff, ourbuff, length);
      }
      return totalbuff;
    } /* End of getBinaryBuffer() */


    virtual int dumpToBinaryBuffer(u8* dst, int maxlen){
      u8 *ourbuff=NULL;
      long ourlength=0;
      /* Get our own buffer address and length */
      if ( (ourbuff=getBufferPointer()) == NULL ||  (ourlength=this->length) < 0 )
            outFatal(VB_1,"getBinaryBuffer(): Couldn't get own data pointer\n");
      /* Copy our part of the buffer */
      if ( maxlen < ourlength )
            outFatal(VB_1,"getBinaryBuffer(): Packet exceeds maximum length %d\n", maxlen);
      memcpy( dst, ourbuff, ourlength);
       /* If there are more elements, tell them to copy their part */
       if( next!= NULL ){
            next->dumpToBinaryBuffer(dst+ourlength, maxlen-ourlength);
       }
       return this->getLen();
    } /* End of dumpToBinaryBuffer() */


    /** Does the same as the previous one but it stores the length of the
     *  return buffer on the memory pointed by the supplied int pointer.     */
    virtual u8 * getBinaryBuffer(int *len){
      u8 *buff = getBinaryBuffer();
      if( len != NULL )
         *len = getLen();
      return buff;
    } /* End of getBinaryBuffer() */


    /** Returns the lenght of this PacketElement + the length of all the
     *  PacketElements that are next to it (are linked trough the "next"
     *  attribute). So for example, if we have IPv4Header p1, linked to
     *  a TCPHeader p2, representing a simple TCP SYN with no options,
     *  a call to p1.getLen() will return 20 (IP header with no options) + 20
     *  (TCP header with no options) = 40 bytes.                             */
    virtual int getLen(){
        /* If we have some other packet element linked, get its length */
        if (next!=NULL)
            return length + next->getLen();
        else
            return length;
    } /* End of getLen() */


    /** Returns the address of the next PacketElement that is linked to this */
    virtual PacketElement *getNextElement(){
      return next;
    } /* End of getNextElement() */


    /** Sets attribute next with the supplied pointer value.
     *  @warning Supplied pointer must point to a PacketElement object or
     *  an object that inherits from it.                                     */
    virtual int setNextElement(PacketElement *n){
      next=n;
      return OP_SUCCESS;
    } /* End of setNextElement() */


    /** Returns the address of the previous PacketElement that is linked to
     *  this one.
     *  @warning In many cases this function will return NULL since there is
     *  a high probability that the user of this class does not link
     *  PacketElements in both directions. Normally one would set attribute
     *  "next" of an IPHeader object to the TCPHeader that follows it, but
     *  not the other way around. */
    virtual PacketElement *getPrevElement(){
      return prev;
    } /* End of getPrevElement() */

};

#endif
