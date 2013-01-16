//-------------------------------------------------------------------------------
//
// hack_library.c - A collection of tools used for SIP attack
//                                 tools. Developed for the Hacking
//                                 Exposed VoIP book.
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
//   Author: Mark D. Collier/Mark O'Brien - 02/17/2006  v1.0
//         www.securelogix.com - mark.collier@securelogix.com
//         www.hackingexposedvoip.com
//
//-------------------------------------------------------------------------------

#include "hack_library.h"

//-------------------------------------------------------------------------------
//
// Str2IP
//
// Called to convert a character string to an int IP address in network byte
// order. The string must be in dot notation. Note: This is a destructive call
// to the input string!
//
//-----------------------------------------------------------------------------

int  Str2IP ( char *str, int *ipNum )
{
    unsigned char  str_val[4];
    int           *int_val = (int*) str_val;
    int            i       = 0;
    int            val;
    char          *digits;
    char          *end = NULL;
    char          *ptr = str;

//
//  Skip leading spaces
//

    while ( *ptr == ' ' ) {
        ptr++;
    }
    digits = ptr;

//
//  Make sure the string is digits and '.'
//

    while ( *ptr != '\0' && *ptr != ' ' ) {
        if ( (!isdigit(*ptr)) && (*ptr != '.' ) ) {
            return ( EXIT_FAILURE );
        } else if ( *ptr == '.' ) {
            if ( i == 3 ) {
                return ( EXIT_FAILURE );
            } else {
                i++;
            }
            ptr++;
        } else {
            ptr++;
        }
    }
		
    if ( i != 3 ) {
        return ( EXIT_FAILURE );
    }

    ptr = digits;
    for ( i = 0; i < 4; i++ ) {
        if ( i<3 && (end = strchr(ptr,'.')) == NULL ) {
            return ( EXIT_FAILURE );
        }

        *end = '\0';
        val = atoi( ptr );
        if ( val > 255 || ! isdigit(*ptr) ) {
            return ( EXIT_FAILURE );
        }

        str_val[i] = (unsigned char) val;
        ptr        = end + 1;
    }
	
    *ipNum = *int_val;

    return ( EXIT_SUCCESS );
}

//-----------------------------------------------------------------------------
//
//   DumpPacket
//
//   Dump out the contents of the packet in a standard form.
//   The packetSize is the length in bytes. Output appears
//   in the following form:
//
//   0000 xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx
//   0010 xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx
//   0020 xx xx xx
//
//   where the 1st column is the offset from the beginning of the
//   packet for the next byte and each xx is a hex byte value.
//
//   return 0 for success, -1 for failure.
//
//-----------------------------------------------------------------------------

int  DumpPacket( char *psPacket, int packetSize )
{
    int lines   = packetSize / 16;
    int rem     = packetSize % 16;
    int m       = 0;
    int n       = 0;
    
    if ( ( !psPacket ) || ( packetSize < 0 ) ) {
        return -1;
    }
 
    printf( "\nPacket:" );
   
    for ( m = 0; m < lines; m++ ) {

//
//  Print first 8 bytes of current line
//
        
        printf( "\n%04.4x ", m * 16 );  // Row offset leader
        
        for ( ; n < ( m * 16 + 8 ); n++ ) {
            printf( " %02.2x", (unsigned char) psPacket[ n ] );
        }
        
        printf ( " " ); //  Extra space separating columns of 8
        
//
// Print last 8 bytes of current line
//
        
        for ( ; ( n < ( m + 1 ) * 16 ); n++ ) {
            printf( " %02.2x", (unsigned char) psPacket[ n ] );
        }
    }
    
//
//  Print remainder of bytes that do not form a full 16 byte line. Print up to
//  first 8 bytes of last line
//
        
    if ( n != packetSize ) {
        printf( "\n%4.4x ", m * 16 );  // Row offset leader
        
        for ( ; ( n < ( m * 16 + 8 ) ) && ( n < packetSize ); n++ ) {
            printf( " %02.2x", (unsigned char) psPacket[ n ] );
        }
        
        printf ( " " ); //  Extra space separating columns of 8
        
//
//      Print up to next 8 bytes of last line
//
     
        for ( ; ( n < ( ( m + 1 ) * 16 ) ) && ( n < packetSize ); n++ ) {
            printf( " %02.2x", (unsigned char) psPacket[ n ] );
        }
    }
    
    printf( "\n\n" );
    return ( 0 );
    
}  //  end DumpPacket()

//-----------------------------------------------------------------------------
//
// GetNextGuid
//
//   Generate a 36 character random ID. 
//
//-----------------------------------------------------------------------------

char *GetNextGuid ( void )
{
    char             *guid;
    int               r1;
    int               r2;
    int               r3;
    int               ur;
    struct timeval    tv;

    ur = open( "/dev/urandom", O_RDONLY );
    if ( ur < 0 ) {
        r1 = random();
        r2 = random();
        r3 = random();
    } else {
        if ( read( ur, &r1, sizeof( r1 ) ) < ( int )sizeof( r1 ) ) {
            r1 = random();
        }
        if ( read( ur, &r2, sizeof( r2 ) ) < ( int )sizeof( r2 ) ) {
            r2 = random();
        }
        if ( read( ur, &r3, sizeof( r3 ) ) < ( int )sizeof( r3 ) ) {
            r3 = random();
        }
        close( ur );
    }

    guid = (char *)malloc( 37 );
    if ( !guid ) {
        fprintf( stderr,
                 "GetNextGuid: out of memory",
                 __FILE__,
                 __LINE__ );
        return ( NULL );
    }

    gettimeofday( &tv, NULL );

    snprintf( guid, 37,
              "%1x%05x%02x-%04x-%04x-%04x-%08x%04x",
              ( unsigned int )  tv.tv_sec       & 0x0000000f,
              ( unsigned int )  tv.tv_usec      & 0x000fffff,
              ( unsigned int )  r3        >> 16 & 0x000000ff,
              ( unsigned int )  tv.tv_sec >>  4 & 0x0000ffff,
              ( unsigned int )( tv.tv_sec >> 20 & 0x00000fff ) | 0x00004000,
              ( unsigned int )( r1              & 0x00003fff ) | 0x00008000,
              ( unsigned int )  r2              & 0xffffffff,
              ( unsigned int )  r3              & 0x0000ffff                 );

    return ( guid );
}
