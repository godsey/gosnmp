// Copyright 2012-2016 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"log"
	"net"
)

/***************************************************************
SNMP Traps

Most SNMP PDUType's (eg GetRequest, SetRequest) are synchronous ie
a "question" is sent and a "reply" is expected. Traps are
asynchronous ie an unsolicited "notification" is sent from an
Agent, without expectation that the "notification" will be received
by a Network Management System (NMS). Therefore trap code is in
this separate file.

From stackoverflow:

1. SNMP v1 defines a special TRAP message format, different from other
messages (such as GET).  http://tools.ietf.org/html/rfc1157#page-27
This message format is not used anymore in SNMP v2 and v3. If an SNMP
agent sends out such TRAP messages for v2 or v3, that should be a bug.
(... I know that some devices send the old format for SNMPv2 ... but
that should be treated as a bug in the firmware).

2. Since v2, TRAP starts to use the common message format (the same
as GET and so on). So it is called SNMPv2-Trap-PDU.
http://tools.ietf.org/search/rfc3416#page-22

3. SNMP v3 introduces the security model to all messages, so TRAP
receives such update too. It is still based on SNMPv2-Trap-PDU.

From O'Reilly Essential SNMP:

SNMPv2 defines traps in a slightly different way. In a MIB, Version 1
traps are defined as TRAP-TYPE, while Version 2 traps are defined as
NOTIFICATION-TYPE.  SNMPv2 also does away with the notion of generic
traps -- instead, it defines many specific traps (properly speaking,
notifications) in public MIBs. SNMPv3 traps, which are discussed
briefly in Appendix F, "SNMPv3", are simply SNMPv2 traps with added
authentication and privacy capabilities. Most SNMP implementations
support only Version 1.
***************************************************************/

//
// Sending Traps ie GoSNMP acting as an Agent
//

// TODO...

//
// Receiving Traps ie GoSNMP acting as an NMS
//
// GoSNMP.unmarshal() currently only handles SNMPV2Trap
//

// A TrapListener defineds parameters for running a SNMP Trap receiver.
// nil values will be replaced by default values.
type TrapListener struct {
	OnNewTrap func(s *SnmpPacket, u *net.UDPAddr)
	Params    *GoSNMP
}

// Listen listens on the UDP address addr and calls the OnNewTrap
// function specified in *TrapListener for every trap recieved.
func (t *TrapListener) Listen(addr string) (err error) {
	if t.Params == nil {
		t.Params = Default
	}

	if t.OnNewTrap == nil {
		t.OnNewTrap = debugTrapHandler
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	for {
		var buf [4096]byte
		rlen, remote, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			if t.Params.loggingEnabled {
				t.Params.Logger.Printf("TrapListener: error in read %s\n", err)
			}
		}

		msg := buf[:rlen]
		traps := t.Params.unmarshalTrap(msg)
		t.OnNewTrap(traps, remote)
	}
}

// Default trap handler
func debugTrapHandler(s *SnmpPacket, u *net.UDPAddr) {
	log.Printf("got trapdata from %+v: %+v\n", u, s)
}

// Unmarshal SNMP Trap
func (x *GoSNMP) unmarshalTrap(trap []byte) (result *SnmpPacket) {
	result = new(SnmpPacket)
	err := x.unmarshal(trap, result)
	if err != nil {
		if x.loggingEnabled {
			x.Logger.Printf("unmarshalTrap: %s\n", err)
		}
	}

	return result
}
