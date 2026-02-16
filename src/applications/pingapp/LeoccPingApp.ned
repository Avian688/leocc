//
// Copyright (C) 2001 Monash University, Australia
// Copyright (C) 2012-2015 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

package leocc.applications.pingapp;

import inet.applications.pingapp.PingApp;

//
// Generates ping requests to several hosts (or rather, network interfaces),
// and calculates the packet loss and round trip times of the replies.
// It works exactly like 'ping' except that it is possible to specify
// several destination addresses as a space separated list of IP addresses
// or module names. (The L3AddressResolver class is used to resolve the address.)
// Specifying '*' allows pinging ALL configured network interfaces in the
// whole simulation. This is useful to check if a host can reach ALL other
// hosts in the network (i.e. routing tables were set up properly).
//
// Start/stop time, sendInterval etc. can be specified via parameters. An address
// may be given in the dotted decimal notation (or, for IPv6, in the usual
// notation with colons), or with the module name.
// (The L3AddressResolver class is used to resolve the address.)
//
// To specify the number of ping requests sent to a single destination address,
// use the 'count' parameter. After the specified number of ping requests was
// sent to a destination address, the application goes to sleep for 'sleepDuration'.
// Once the sleep timer has expired, the application switches to the next destination
// and starts pinging again. The application stops pinging once all destination
// addresses were tested or the simulation time reaches 'stopTime'.
//
// To disable send, specify empty destAddr.
//
// Every ping request is sent out with a sequence number, and replies are
// expected to arrive in the same order. Whenever there's a jump in the
// in the received ping responses' sequence number (e.g. 1, 2, 3, 5), then
// the missing pings (number 4 in this example) is counted as lost.
// Then if it still arrives later (that is, a reply with a sequence number
// smaller than the largest one received so far) it will be counted as
// out-of-sequence arrival. So the number of really lost pings will be
// "lost" minus "out-of-order" (assuming there's no duplicate or bogus reply).
//
// @see ~Icmp, ~Icmpv6
//
simple LeoccPingApp extends PingApp
{
	parameters:
    	@class("inet::LeoccPingApp");   
}

