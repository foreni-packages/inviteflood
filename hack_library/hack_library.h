//-------------------------------------------------------------------------------
//
// hack_library.h - A collection of tools used for SIP attack
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

#ifndef __HACK_LIBRARY_H
#define __HACK_LIBRARY_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>

int   Str2IP ( char *str, int *ipNum );
int   DumpPacket ( char *psPacket, int packetSize );
char  *GetNextGuid ( void );

#endif  //  __HACK_LIBRARY_H
