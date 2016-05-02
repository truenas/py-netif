#+
# Copyright 2015 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################


import array
import os
import socket
import ipaddress
import enum
import cython
from bsd import sysctl
cimport defs
from libc.errno cimport *
from libc.stdint cimport *
from libc.string cimport strcpy, strerror, memset, memcpy
from libc.stdlib cimport malloc, realloc, free


CLONED_PREFIXES = ['lo', 'tun', 'tap', 'bridge', 'epair', 'carp', 'vlan']


cdef extern from "ifmedia.h":
    cdef struct ifmedia_type_to_subtype:
        pass

    cdef extern defs.ifmedia_description* get_toptype_desc(int ifmw)
    cdef extern ifmedia_type_to_subtype* get_toptype_ttos(int ifmw)
    cdef extern defs.ifmedia_description* get_subtype_desc(int ifmw, ifmedia_type_to_subtype *ttos)
    cdef extern defs.ifmedia_description* get_mode_desc(int ifmw, ifmedia_type_to_subtype *ttos)
    cdef extern defs.ifmedia_description* get_subtype_by_name(const char *name, ifmedia_type_to_subtype *ttos)


class AddressFamily(enum.IntEnum):
    UNIX = defs.AF_UNIX
    INET = defs.AF_INET
    IMPLINK = defs.AF_IMPLINK
    PUP = defs.AF_PUP
    CHAOS = defs.AF_CHAOS
    NETBIOS = defs.AF_NETBIOS
    ISO = defs.AF_ISO
    OSI = defs.AF_OSI
    ECMA = defs.AF_ECMA
    DATAKIT = defs.AF_DATAKIT
    CCITT = defs.AF_CCITT
    SNA = defs.AF_SNA
    DECnet = defs.AF_DECnet
    DLI = defs.AF_DLI
    LAT = defs.AF_LAT
    HYLINK = defs.AF_HYLINK
    APPLETALK = defs.AF_APPLETALK
    ROUTE = defs.AF_ROUTE
    LINK = defs.AF_LINK
    COIP = defs.AF_COIP
    CNT = defs.AF_CNT
    IPX = defs.AF_IPX
    SIP = defs.AF_SIP
    ISDN = defs.AF_ISDN
    E164 = defs.AF_E164
    INET6 = defs.AF_INET6
    NATM = defs.AF_NATM
    ATM = defs.AF_ATM
    NETGRAPH = defs.AF_NETGRAPH
    SLOW = defs.AF_SLOW
    SCLUSTER = defs.AF_SCLUSTER
    ARP = defs.AF_ARP
    BLUETOOTH = defs.AF_BLUETOOTH
    IEEE80211 = defs.AF_IEEE80211
    INET_SDP = defs.AF_INET_SDP
    INET6_SDP = defs.AF_INET6_SDP


class RouteFlags(enum.IntEnum):
    UP = defs.RTF_UP
    GATEWAY = defs.RTF_GATEWAY
    HOST = defs.RTF_HOST
    REJECT = defs.RTF_REJECT
    DYNAMIC = defs.RTF_DYNAMIC
    MODIFIED = defs.RTF_MODIFIED
    DONE = defs.RTF_DONE
    XRESOLVE = defs.RTF_XRESOLVE
    LLINFO = defs.RTF_LLINFO
    LLDATA = defs.RTF_LLDATA
    STATIC = defs.RTF_STATIC
    BLACKHOLE = defs.RTF_BLACKHOLE
    PROTO1 = defs.RTF_PROTO1
    PROTO2 = defs.RTF_PROTO2
    PROTO3 = defs.RTF_PROTO3
    PINNED = defs.RTF_PINNED
    LOCAL = defs.RTF_LOCAL
    BROADCAST = defs.RTF_BROADCAST
    MULTICAST = defs.RTF_MULTICAST
    STICKY = defs.RTF_STICKY


class RoutingMessageType(enum.IntEnum):
    INVALID = 0
    ADD = defs.RTM_ADD
    DELETE = defs.RTM_DELETE
    CHANGE = defs.RTM_CHANGE
    GET = defs.RTM_GET
    LOSING = defs.RTM_LOSING
    REDIRECT = defs.RTM_REDIRECT
    MISS = defs.RTM_MISS
    LOCK = defs.RTM_LOCK
    RESOLVE = defs.RTM_RESOLVE
    NEWADDR = defs.RTM_NEWADDR
    DELADDR = defs.RTM_DELADDR
    IFINFO = defs.RTM_IFINFO
    NEWMADDR = defs.RTM_NEWMADDR
    DELMADDR = defs.RTM_DELMADDR
    IFANNOUNCE = defs.RTM_IFANNOUNCE
    IEEE80211 = defs.RTM_IEEE80211


class InterfaceFlags(enum.IntEnum):
    UP = defs.IFF_UP
    BROADCAST = defs.IFF_BROADCAST
    DEBUG = defs.IFF_DEBUG
    LOOPBACK = defs.IFF_LOOPBACK
    POINTOPOINT = defs.IFF_POINTOPOINT
    DRV_RUNNING = defs.IFF_DRV_RUNNING
    NOARP = defs.IFF_NOARP
    PROMISC = defs.IFF_PROMISC
    ALLMULTI = defs.IFF_ALLMULTI
    DRV_OACTIVE = defs.IFF_DRV_OACTIVE
    SIMPLEX = defs.IFF_SIMPLEX
    LINK0 = defs.IFF_LINK0
    LINK1 = defs.IFF_LINK1
    LINK2 = defs.IFF_LINK2
    MULTICAST = defs.IFF_MULTICAST
    CANTCONFIG = defs.IFF_CANTCONFIG
    PPROMISC = defs.IFF_PPROMISC
    MONITOR = defs.IFF_MONITOR
    STATICARP = defs.IFF_STATICARP
    DYING = defs.IFF_DYING
    RENAMING = defs.IFF_RENAMING
    
    
class InterfaceType(enum.IntEnum):
    OTHER = defs.IFT_OTHER
    I1822 = defs.IFT_1822
    HDH1822 = defs.IFT_HDH1822
    X25DDN = defs.IFT_X25DDN
    X25 = defs.IFT_X25
    ETHER = defs.IFT_ETHER
    ISO88023 = defs.IFT_ISO88023
    ISO88024 = defs.IFT_ISO88024
    ISO88025 = defs.IFT_ISO88025
    ISO88026 = defs.IFT_ISO88026
    STARLAN = defs.IFT_STARLAN
    P10 = defs.IFT_P10
    P80 = defs.IFT_P80
    HY = defs.IFT_HY
    FDDI = defs.IFT_FDDI
    LAPB = defs.IFT_LAPB
    SDLC = defs.IFT_SDLC
    T1 = defs.IFT_T1
    CEPT = defs.IFT_CEPT
    ISDNBASIC = defs.IFT_ISDNBASIC
    ISDNPRIMARY = defs.IFT_ISDNPRIMARY
    PTPSERIAL = defs.IFT_PTPSERIAL
    PPP = defs.IFT_PPP
    LOOP = defs.IFT_LOOP
    EON = defs.IFT_EON
    XETHER = defs.IFT_XETHER
    NSIP = defs.IFT_NSIP
    SLIP = defs.IFT_SLIP
    ULTRA = defs.IFT_ULTRA
    DS3 = defs.IFT_DS3
    SIP = defs.IFT_SIP
    FRELAY = defs.IFT_FRELAY
    RS232 = defs.IFT_RS232
    PARA = defs.IFT_PARA
    ARCNET = defs.IFT_ARCNET
    ARCNETPLUS = defs.IFT_ARCNETPLUS
    ATM = defs.IFT_ATM
    MIOX25 = defs.IFT_MIOX25
    SONET = defs.IFT_SONET
    X25PLE = defs.IFT_X25PLE
    ISO88022LLC = defs.IFT_ISO88022LLC
    LOCALTALK = defs.IFT_LOCALTALK
    SMDSDXI = defs.IFT_SMDSDXI
    FRELAYDCE = defs.IFT_FRELAYDCE
    V35 = defs.IFT_V35
    HSSI = defs.IFT_HSSI
    HIPPI = defs.IFT_HIPPI
    MODEM = defs.IFT_MODEM
    AAL5 = defs.IFT_AAL5
    SONETPATH = defs.IFT_SONETPATH
    SONETVT = defs.IFT_SONETVT
    SMDSICIP = defs.IFT_SMDSICIP
    PROPVIRTUAL = defs.IFT_PROPVIRTUAL
    PROPMUX = defs.IFT_PROPMUX
    IEEE80212 = defs.IFT_IEEE80212
    FIBRECHANNEL = defs.IFT_FIBRECHANNEL
    HIPPIINTERFACE = defs.IFT_HIPPIINTERFACE
    FRAMERELAYINTERCONNECT = defs.IFT_FRAMERELAYINTERCONNECT
    AFLANE8023 = defs.IFT_AFLANE8023
    AFLANE8025 = defs.IFT_AFLANE8025
    CCTEMUL = defs.IFT_CCTEMUL
    FASTETHER = defs.IFT_FASTETHER
    ISDN = defs.IFT_ISDN
    V11 = defs.IFT_V11
    V36 = defs.IFT_V36
    G703AT64K = defs.IFT_G703AT64K
    G703AT2MB = defs.IFT_G703AT2MB
    QLLC = defs.IFT_QLLC
    FASTETHERFX = defs.IFT_FASTETHERFX
    CHANNEL = defs.IFT_CHANNEL
    IEEE80211 = defs.IFT_IEEE80211
    IBM370PARCHAN = defs.IFT_IBM370PARCHAN
    ESCON = defs.IFT_ESCON
    DLSW = defs.IFT_DLSW
    ISDNS = defs.IFT_ISDNS
    ISDNU = defs.IFT_ISDNU
    LAPD = defs.IFT_LAPD
    IPSWITCH = defs.IFT_IPSWITCH
    RSRB = defs.IFT_RSRB
    ATMLOGICAL = defs.IFT_ATMLOGICAL
    DS0 = defs.IFT_DS0
    DS0BUNDLE = defs.IFT_DS0BUNDLE
    BSC = defs.IFT_BSC
    ASYNC = defs.IFT_ASYNC
    CNR = defs.IFT_CNR
    ISO88025DTR = defs.IFT_ISO88025DTR
    EPLRS = defs.IFT_EPLRS
    ARAP = defs.IFT_ARAP
    PROPCNLS = defs.IFT_PROPCNLS
    HOSTPAD = defs.IFT_HOSTPAD
    TERMPAD = defs.IFT_TERMPAD
    FRAMERELAYMPI = defs.IFT_FRAMERELAYMPI
    X213 = defs.IFT_X213
    ADSL = defs.IFT_ADSL
    RADSL = defs.IFT_RADSL
    SDSL = defs.IFT_SDSL
    VDSL = defs.IFT_VDSL
    ISO88025CRFPINT = defs.IFT_ISO88025CRFPINT
    MYRINET = defs.IFT_MYRINET
    VOICEEM = defs.IFT_VOICEEM
    VOICEFXO = defs.IFT_VOICEFXO
    VOICEFXS = defs.IFT_VOICEFXS
    VOICEENCAP = defs.IFT_VOICEENCAP
    VOICEOVERIP = defs.IFT_VOICEOVERIP
    ATMDXI = defs.IFT_ATMDXI
    ATMFUNI = defs.IFT_ATMFUNI
    ATMIMA = defs.IFT_ATMIMA
    PPPMULTILINKBUNDLE = defs.IFT_PPPMULTILINKBUNDLE
    IPOVERCDLC = defs.IFT_IPOVERCDLC
    IPOVERCLAW = defs.IFT_IPOVERCLAW
    STACKTOSTACK = defs.IFT_STACKTOSTACK
    VIRTUALIPADDRESS = defs.IFT_VIRTUALIPADDRESS
    MPC = defs.IFT_MPC
    IPOVERATM = defs.IFT_IPOVERATM
    ISO88025FIBER = defs.IFT_ISO88025FIBER
    TDLC = defs.IFT_TDLC
    GIGABITETHERNET = defs.IFT_GIGABITETHERNET
    HDLC = defs.IFT_HDLC
    LAPF = defs.IFT_LAPF
    V37 = defs.IFT_V37
    X25MLP = defs.IFT_X25MLP
    X25HUNTGROUP = defs.IFT_X25HUNTGROUP
    TRANSPHDLC = defs.IFT_TRANSPHDLC
    INTERLEAVE = defs.IFT_INTERLEAVE
    FAST = defs.IFT_FAST
    IP = defs.IFT_IP
    DOCSCABLEMACLAYER = defs.IFT_DOCSCABLEMACLAYER
    DOCSCABLEDOWNSTREAM = defs.IFT_DOCSCABLEDOWNSTREAM
    DOCSCABLEUPSTREAM = defs.IFT_DOCSCABLEUPSTREAM
    A12MPPSWITCH = defs.IFT_A12MPPSWITCH
    TUNNEL = defs.IFT_TUNNEL
    COFFEE = defs.IFT_COFFEE
    CES = defs.IFT_CES
    ATMSUBINTERFACE = defs.IFT_ATMSUBINTERFACE
    L2VLAN = defs.IFT_L2VLAN
    L3IPVLAN = defs.IFT_L3IPVLAN
    L3IPXVLAN = defs.IFT_L3IPXVLAN
    DIGITALPOWERLINE = defs.IFT_DIGITALPOWERLINE
    MEDIAMAILOVERIP = defs.IFT_MEDIAMAILOVERIP
    DTM = defs.IFT_DTM
    DCN = defs.IFT_DCN
    IPFORWARD = defs.IFT_IPFORWARD
    MSDSL = defs.IFT_MSDSL
    IEEE1394 = defs.IFT_IEEE1394
    IFGSN = defs.IFT_IFGSN
    DVBRCCMACLAYER = defs.IFT_DVBRCCMACLAYER
    DVBRCCDOWNSTREAM = defs.IFT_DVBRCCDOWNSTREAM
    DVBRCCUPSTREAM = defs.IFT_DVBRCCUPSTREAM
    ATMVIRTUAL = defs.IFT_ATMVIRTUAL
    MPLSTUNNEL = defs.IFT_MPLSTUNNEL
    SRP = defs.IFT_SRP
    VOICEOVERATM = defs.IFT_VOICEOVERATM
    VOICEOVERFRAMERELAY = defs.IFT_VOICEOVERFRAMERELAY
    IDSL = defs.IFT_IDSL
    COMPOSITELINK = defs.IFT_COMPOSITELINK
    SS7SIGLINK = defs.IFT_SS7SIGLINK
    PROPWIRELESSP2P = defs.IFT_PROPWIRELESSP2P
    FRFORWARD = defs.IFT_FRFORWARD
    RFC1483 = defs.IFT_RFC1483
    USB = defs.IFT_USB
    IEEE8023ADLAG = defs.IFT_IEEE8023ADLAG
    BGPPOLICYACCOUNTING = defs.IFT_BGPPOLICYACCOUNTING
    FRF16MFRBUNDLE = defs.IFT_FRF16MFRBUNDLE
    H323GATEKEEPER = defs.IFT_H323GATEKEEPER
    H323PROXY = defs.IFT_H323PROXY
    MPLS = defs.IFT_MPLS
    MFSIGLINK = defs.IFT_MFSIGLINK
    HDSL2 = defs.IFT_HDSL2
    SHDSL = defs.IFT_SHDSL
    DS1FDL = defs.IFT_DS1FDL
    POS = defs.IFT_POS
    DVBASILN = defs.IFT_DVBASILN
    DVBASIOUT = defs.IFT_DVBASIOUT
    PLC = defs.IFT_PLC
    NFAS = defs.IFT_NFAS
    TR008 = defs.IFT_TR008
    GR303RDT = defs.IFT_GR303RDT
    GR303IDT = defs.IFT_GR303IDT
    ISUP = defs.IFT_ISUP
    PROPDOCSWIRELESSMACLAYER = defs.IFT_PROPDOCSWIRELESSMACLAYER
    PROPDOCSWIRELESSDOWNSTREAM = defs.IFT_PROPDOCSWIRELESSDOWNSTREAM
    PROPDOCSWIRELESSUPSTREAM = defs.IFT_PROPDOCSWIRELESSUPSTREAM
    HIPERLAN2 = defs.IFT_HIPERLAN2
    PROPBWAP2MP = defs.IFT_PROPBWAP2MP
    SONETOVERHEADCHANNEL = defs.IFT_SONETOVERHEADCHANNEL
    DIGITALWRAPPEROVERHEADCHANNEL = defs.IFT_DIGITALWRAPPEROVERHEADCHANNEL
    AAL2 = defs.IFT_AAL2
    RADIOMAC = defs.IFT_RADIOMAC
    ATMRADIO = defs.IFT_ATMRADIO
    IMT = defs.IFT_IMT
    MVL = defs.IFT_MVL
    REACHDSL = defs.IFT_REACHDSL
    FRDLCIENDPT = defs.IFT_FRDLCIENDPT
    ATMVCIENDPT = defs.IFT_ATMVCIENDPT
    OPTICALCHANNEL = defs.IFT_OPTICALCHANNEL
    OPTICALTRANSPORT = defs.IFT_OPTICALTRANSPORT
    INFINIBAND = defs.IFT_INFINIBAND
    BRIDGE = defs.IFT_BRIDGE
    STF = defs.IFT_STF
    GIF = defs.IFT_GIF
    PVC = defs.IFT_PVC
    ENC = defs.IFT_ENC
    PFLOG = defs.IFT_PFLOG
    PFSYNC = defs.IFT_PFSYNC


class InterfaceLinkState(enum.IntEnum):
    LINK_STATE_UNKNOWN = defs.LINK_STATE_UNKNOWN
    LINK_STATE_DOWN = defs.LINK_STATE_DOWN
    LINK_STATE_UP = defs.LINK_STATE_UP


class InterfaceMediaOption(enum.IntEnum):
    AUTO = defs.IFM_AUTO
    MANUAL = defs.IFM_MANUAL
    NONE = defs.IFM_NONE
    FDX = defs.IFM_FDX
    HDX = defs.IFM_HDX
    FLOW = defs.IFM_FLOW
    FLAG0 = defs.IFM_FLAG0
    FLAG1 = defs.IFM_FLAG1
    FLAG2 = defs.IFM_FLAG2
    LOOP = defs.IFM_LOOP
    
    
class InterfaceCapability(enum.IntEnum):
    RXCSUM = defs.IFCAP_RXCSUM
    TXCSUM = defs.IFCAP_TXCSUM
    NETCONS = defs.IFCAP_NETCONS
    VLAN_MTU = defs.IFCAP_VLAN_MTU
    VLAN_HWTAGGING = defs.IFCAP_VLAN_HWTAGGING
    JUMBO_MTU = defs.IFCAP_JUMBO_MTU
    POLLING = defs.IFCAP_POLLING
    VLAN_HWCSUM = defs.IFCAP_VLAN_HWCSUM
    TSO4 = defs.IFCAP_TSO4
    TSO6 = defs.IFCAP_TSO6
    LRO = defs.IFCAP_LRO
    WOL_UCAST = defs.IFCAP_WOL_UCAST
    WOL_MCAST = defs.IFCAP_WOL_MCAST
    WOL_MAGIC = defs.IFCAP_WOL_MAGIC
    TOE4 = defs.IFCAP_TOE4
    TOE6 = defs.IFCAP_TOE6
    VLAN_HWFILTER = defs.IFCAP_VLAN_HWFILTER
    POLLING_NOCOUNT = defs.IFCAP_POLLING_NOCOUNT
    VLAN_HWTSO = defs.IFCAP_VLAN_HWTSO
    LINKSTATE = defs.IFCAP_LINKSTATE
    NETMAP = defs.IFCAP_NETMAP
    RXCSUM_IPV6 = defs.IFCAP_RXCSUM_IPV6
    TXCSUM_IPV6 = defs.IFCAP_TXCSUM_IPV6
    HWSTATS = defs.IFCAP_HWSTATS


class InterfaceAnnounceType(enum.IntEnum):
    ARRIVAL = defs.IFAN_ARRIVAL
    DEPARTURE = defs.IFAN_DEPARTURE


class AggregationProtocol(enum.IntEnum):
    NONE = defs.LAGG_PROTO_NONE
    ROUNDROBIN = defs.LAGG_PROTO_ROUNDROBIN
    FAILOVER = defs.LAGG_PROTO_FAILOVER
    LOADBALANCE = defs.LAGG_PROTO_LOADBALANCE
    LACP = defs.LAGG_PROTO_LACP
    IF FREEBSD_VERSION < 1100079:
        ETHERCHANNEL = defs.LAGG_PROTO_ETHERCHANNEL


class LaggPortFlags(enum.IntEnum):
    SLAVE = defs.LAGG_PORT_SLAVE
    MASTER = defs.LAGG_PORT_MASTER
    STACK = defs.LAGG_PORT_STACK
    ACTIVE = defs.LAGG_PORT_ACTIVE
    COLLECTING = defs.LAGG_PORT_COLLECTING
    DISTRIBUTING = defs.LAGG_PORT_DISTRIBUTING
    DISABLED = defs.LAGG_PORT_DISABLED


class NeighborDiscoveryFlags(enum.IntEnum):
    PERFORMNUD = defs.ND6_IFF_PERFORMNUD
    ACCEPT_RTADV = defs.ND6_IFF_ACCEPT_RTADV
    PREFER_SOURCE = defs.ND6_IFF_PREFER_SOURCE
    IFDISABLED = defs.ND6_IFF_IFDISABLED        
    DONT_SET_IFROUTE = defs.ND6_IFF_DONT_SET_IFROUTE
    AUTO_LINKLOCAL = defs.ND6_IFF_AUTO_LINKLOCAL
    NO_RADR = defs.ND6_IFF_NO_RADR
    NO_PREFER_IFACE = defs.ND6_IFF_NO_PREFER_IFACE


class In6AddrFlags(enum.IntEnum):
    ANYCAST = defs.IN6_IFF_ANYCAST
    TENTATIVE = defs.IN6_IFF_TENTATIVE
    DUPLICATED = defs.IN6_IFF_DUPLICATED
    DETACHED = defs.IN6_IFF_DETACHED
    DEPRECATED = defs.IN6_IFF_DEPRECATED
    AUTOCONF = defs.IN6_IFF_AUTOCONF
    TEMPORARY = defs.IN6_IFF_TEMPORARY
    PREFER_SOURCE = defs.IN6_IFF_PREFER_SOURCE


class LinkAddress(object):
    def __init__(self, ifname=None, address=None):
        self.ifname = ifname
        self.address = address

    def __str__(self):
        return self.address

    def __getstate__(self):
        return {
            'ifname': self.ifname,
            'address': self.address
        }

    def __hash__(self):
        return hash((self.ifname, self.address))

    def __eq__(self, other):
        return \
            self.ifname == other.ifname and \
            self.address == other.address

    def __ne__(self, other):
        return not self == other


class InterfaceAddress(object):
    def __init__(self, af=None, address=None):
        self.af = af

        if isinstance(address, (ipaddress.IPv4Interface, ipaddress.IPv6Interface)):
            self.address = address.ip
            self.netmask = address.netmask
            self.broadcast = address.network.broadcast_address
        else:
            self.address = address
            self.netmask = None
            self.broadcast = None

        self.dest_address = None
        self.scope = None
        self.ipv6_flags = None

    def __str__(self):
        return u'{0}/{1}'.format(self.address, self.netmask)

    def __hash__(self):
        return hash((self.af, self.address, self.netmask, self.broadcast, self.dest_address))

    def __getstate__(self):
        ret = {
            'type': self.af.name,
            'address': self.address.address if type(self.address) is LinkAddress else str(self.address)
        }

        if self.netmask:
            # XXX yuck!
            ret['netmask'] = bin(int(self.netmask)).count('1')

        if self.broadcast:
            ret['broadcast'] = str(self.broadcast)

        return ret

    def __eq__(self, other):
        return \
            self.af == other.af and \
            self.address == other.address and \
            self.netmask == other.netmask and \
            self.broadcast == other.broadcast and \
            self.dest_address == other.dest_address

    def __ne__(self, other):
        return not self == other

# wrap socket.socket on python2 so that we can use "with"
if not hasattr(socket.socket, '__enter__'):
    class WrapSocket(socket.socket):
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc_val, exc_frame):
            self.close()

    sock3 = WrapSocket
else:
    sock3 = socket.socket

cdef class NetworkInterface(object):
    cdef readonly object name
    cdef object nameb
    cdef public object type
    cdef readonly object addresses

    def __init__(self, name):
        self.name = name
        self.nameb = name.encode('ascii')
        self.addresses = []

    def __str__(self):
        return "<netif.{0} name '{1}' type '{2}'>".format(self.__class__.__name__, self.name, self.type.name)

    def __repr__(self):
        return str(self)

    cdef int query_media(self, defs.ifmediareq* ifm):
        memset(ifm, 0, cython.sizeof(defs.ifmediareq))
        strcpy(ifm.ifm_name, self.nameb)
        if self.ioctl(defs.SIOCGIFMEDIA, <void*>ifm) == -1:
            return False

        return True

    cdef int ioctl(self, uint32_t cmd, void* args, af=socket.AF_INET):
        cdef int result
        with sock3(af, socket.SOCK_DGRAM) as s:
            result = defs.ioctl(s.fileno(), cmd, args)
        return result

    cdef aliasreq(self, address, uint32_t cmd):
        cdef defs.sockaddr_in *sin
        cdef defs.sockaddr_in6 *sin6
        cdef defs.ifaliasreq req
        cdef defs.in6_aliasreq req6

        if address.af == AddressFamily.INET:
            memset(&req, 0, cython.sizeof(req))
            strcpy(req.ifra_name, self.nameb)

            # Address
            sin = <defs.sockaddr_in*>&req.ifra_addr
            sin.sin_family = defs.AF_INET
            sin.sin_len = cython.sizeof(defs.sockaddr_in)
            sin.sin_addr.s_addr = socket.ntohl(int(address.address))

            # Netmask
            sin = <defs.sockaddr_in*>&req.ifra_mask
            sin.sin_family = defs.AF_INET
            sin.sin_len = cython.sizeof(defs.sockaddr_in)
            sin.sin_addr.s_addr = socket.ntohl(int(address.netmask))

            # Broadcast
            if address.broadcast:
                sin = <defs.sockaddr_in*>&req.ifra_broadaddr
                sin.sin_family = defs.AF_INET
                sin.sin_len = cython.sizeof(defs.sockaddr_in)
                sin.sin_addr.s_addr = socket.ntohl(int(address.broadcast))

            if self.ioctl(cmd, <void*>&req) == -1:
                raise OSError(errno, strerror(errno))

        elif address.af == AddressFamily.INET6:
            memset(&req6, 0, cython.sizeof(req6))
            strcpy(req6.ifra_name, self.nameb)
            req6.ifra_lifetime.ia6t_vltime = defs.ND6_INFINITE_LIFETIME
            req6.ifra_lifetime.ia6t_pltime = defs.ND6_INFINITE_LIFETIME

            # Address
            packed = address.address.packed[:16]
            sin6 = <defs.sockaddr_in6*>&req6.ifra_addr
            sin6.sin6_family = defs.AF_INET6
            sin6.sin6_len = cython.sizeof(defs.sockaddr_in6)
            memcpy(sin6.sin6_addr.s6_addr, <void*><char*>packed, 16)

            # Netmask
            packed = address.netmask.packed[:16]
            sin6 = <defs.sockaddr_in6*>&req6.ifra_prefixmask
            sin6.sin6_family = defs.AF_INET6
            sin6.sin6_len = cython.sizeof(defs.sockaddr_in6)
            memcpy(sin6.sin6_addr.s6_addr, <void*><char*>packed, 16)

            if self.ioctl(cmd, <void*>&req6, socket.AF_INET6) == -1:
                raise OSError(errno, strerror(errno))

        else:
            raise NotImplementedError()

    def __getstate__(self):
        return {
            'name': self.name,
            'mtu': self.mtu,
            'cloned': self.cloned,
            'flags': [i.name for i in self.flags],
            'nd6_flags': [i.name for i in self.nd6_flags],
            'capabilities': [i.name for i in self.capabilities],
            'link_state': self.link_state.name,
            'media_type': self.media_type,
            'media_subtype': self.media_subtype,
            'media_options': [i.name for i in self.media_options] if self.media_options is not None else None,
            'link_address': self.link_address.address.address,
            'aliases': [i.__getstate__() for i in self.addresses]
        }

    cdef uint32_t __get_flags(self) except? -1:
        cdef defs.ifreq ifr
        memset(&ifr, 0, cython.sizeof(ifr))
        strcpy(ifr.ifr_name, self.nameb)

        if self.ioctl(defs.SIOCGIFFLAGS, <void*>&ifr) == -1:
            raise OSError(errno, strerror(errno))

        return ifr.ifr_ifru.ifru_flags[0]

    cdef uint32_t __rw_nd6_flags(self, value=None) except? -1:
        cdef defs.in6_ndireq nd;
        memset(&nd, 0, cython.sizeof(nd))
        strcpy(nd.ifname, self.nameb)

        if self.ioctl(defs.SIOCGIFINFO_IN6, <void*>&nd, af=AddressFamily.INET6) == -1:
            raise OSError(errno, strerror(errno))

        if value is None:
            return nd.ndi.flags

        nd.ndi.flags = value
        if self.ioctl(defs.SIOCSIFINFO_IN6, <void*>&nd, af=AddressFamily.INET6) == -1:
            raise OSError(errno, strerror(errno))

    property cloned:
        def __get__(self):
            for i in CLONED_PREFIXES:
                if self.name.startswith(i):
                    return True

            return False

    property flags:
        def __get__(self):
            return bitmask_to_set(self.__get_flags(), InterfaceFlags)

    property nd6_flags:
        def __get__(self):
            return bitmask_to_set(self.__rw_nd6_flags(), NeighborDiscoveryFlags)

        def __set__(self, flags):
            self.__rw_nd6_flags(set_to_bitmask(flags))

    property mtu:
        def __get__(self):
            cdef defs.ifreq ifr
            memset(&ifr, 0, cython.sizeof(ifr))
            strcpy(ifr.ifr_name, self.nameb)
            if self.ioctl(defs.SIOCGIFMTU, <void*>&ifr) == -1:
                raise OSError(errno, strerror(errno))
            return ifr.ifr_ifru.ifru_mtu

        def __set__(self, mtu):
            cdef defs.ifreq ifr
            memset(&ifr, 0, cython.sizeof(ifr))
            strcpy(ifr.ifr_name, self.nameb)
            ifr.ifr_ifru.ifru_mtu = mtu
            if self.ioctl(defs.SIOCSIFMTU, <void*>&ifr) == -1:
                raise OSError(errno, strerror(errno))

    property capabilities:
        def __get__(self):
            cdef defs.ifreq ifr
            memset(&ifr, 0, cython.sizeof(ifr))
            strcpy(ifr.ifr_name, self.nameb)
            if self.ioctl(defs.SIOCGIFCAP, <void*>&ifr) == -1:
                raise OSError(errno, strerror(errno))

            return bitmask_to_set(ifr.ifr_ifru.ifru_cap[1], InterfaceCapability)

        def __set__(self, value):
            cdef defs.ifreq ifr
            memset(&ifr, 0, cython.sizeof(ifr))
            strcpy(ifr.ifr_name, self.nameb)
            ifr.ifr_ifru.ifru_cap[0] = set_to_bitmask(value)
            if self.ioctl(defs.SIOCSIFCAP, <void*>&ifr) == -1:
                raise OSError(errno, strerror(errno))

    property link_state:
        def __get__(self):
            cdef defs.ifmediareq ifm
            memset(&ifm, 0, cython.sizeof(ifm))
            strcpy(ifm.ifm_name, self.nameb)
            if self.ioctl(defs.SIOCGIFMEDIA, <void*>&ifm) == -1:
                if errno != 22: # Invalid argument
                    raise OSError(errno, strerror(errno))

            if ifm.ifm_status & defs.IFM_AVALID:
                if ifm.ifm_status & defs.IFM_ACTIVE:
                    return InterfaceLinkState.LINK_STATE_UP
                else:
                    return InterfaceLinkState.LINK_STATE_DOWN
            else:
                return InterfaceLinkState.LINK_STATE_UNKNOWN

    property link_address:
        def __get__(self):
            return list(filter(lambda x: x.af == defs.AF_LINK, self.addresses)).pop()

        def __set__(self, address):
            raise NotImplementedError()

    property media_type:
        def __get__(self):
            cdef defs.ifmediareq ifm
            cdef defs.ifmedia_description* ifmt
            if not self.query_media(&ifm):
                if errno == 22: # Invalid argument
                    return None

                raise OSError(errno, strerror(errno))

            ifmt = get_toptype_desc(ifm.ifm_current)
            return ifmt.ifmt_string.decode('ascii')

    property media_subtype:
        def __get__(self):
            cdef defs.ifmediareq ifm
            cdef defs.ifmedia_description* ifmt
            cdef ifmedia_type_to_subtype* ttos

            if not self.query_media(&ifm):
                if errno == 22: # Invalid argument
                    return None

                raise OSError(errno, strerror(errno))

            ttos = get_toptype_ttos(ifm.ifm_current)
            ifmt = get_subtype_desc(ifm.ifm_current, ttos)
            return ifmt.ifmt_string.decode('ascii')

        def __set__(self, value):
            cdef defs.ifreq ifr
            cdef defs.ifmediareq ifm
            cdef defs.ifmedia_description* ifmt
            cdef ifmedia_type_to_subtype* ttos

            if not self.query_media(&ifm):
                raise OSError(errno, strerror(errno))

            ttos = get_toptype_ttos(ifm.ifm_current)
            ifmt = get_subtype_by_name(value, ttos)

            memset(&ifr, 0, cython.sizeof(ifr))
            strcpy(ifr.ifr_name, self.nameb)
            ifr.ifr_ifru.ifru_media = ifmt.ifmt_word
            if self.ioctl(defs.SIOCSIFMEDIA, <void*>&ifr) == -1:
                raise OSError(errno, strerror(errno))

    property media_options:
        def __get__(self):
            cdef defs.ifmediareq ifm
            cdef defs.ifmedia_description* ifmt
            cdef ifmedia_type_to_subtype* ttos

            if not self.query_media(&ifm):
                if errno == 22: # Invalid argument
                    return set()

                raise OSError(errno, strerror(errno))

            return bitmask_to_set(ifm.ifm_current, InterfaceMediaOption)

        def __set__(self, value):
            cdef defs.ifmediareq ifm
            cdef defs.ifmedia_description* ifmt
            cdef ifmedia_type_to_subtype* ttos

            ifm.ifm_current = set_to_bitmask(value)

            if not self.query_media(&ifm):
                raise OSError(errno, strerror(errno))

    property description:
        def __get__(self):
            cdef defs.ifreq ifr
            cdef char buffer[1024]

            memset(&ifr, 0, cython.sizeof(ifr))
            strcpy(ifr.ifr_name, self.nameb)
            ifr.ifr_ifru.ifru_buffer.length = cython.sizeof(buffer)
            ifr.ifr_ifru.ifru_buffer.buffer = buffer

            if self.ioctl(defs.SIOCGIFDESCR, <void*>&ifr) == -1:
                raise OSError(errno, strerror(errno))

            return buffer.decode('utf-8')

        def __set__(self, descr):
            cdef defs.ifreq ifr
            cdef char buffer[1024]

            memset(&ifr, 0, cython.sizeof(ifr))
            strcpy(ifr.ifr_name, self.nameb)
            strcpy(buffer, descr.encode('utf-8'))
            ifr.ifr_ifru.ifru_buffer.length = cython.sizeof(buffer)
            ifr.ifr_ifru.ifru_buffer.buffer = buffer

            if self.ioctl(defs.SIOCSIFDESCR, <void*>&ifr) == -1:
                raise OSError(errno, strerror(errno))

    def add_address(self, address):
        if address.af == AddressFamily.INET6:
            self.aliasreq(address, defs.SIOCAIFADDR_IN6)
        elif address.af == AddressFamily.INET:
            self.aliasreq(address, defs.SIOCAIFADDR)

    def remove_address(self, address):
        if address.af == AddressFamily.INET6:
            self.aliasreq(address, defs.SIOCDIFADDR_IN6)
        elif address.af == AddressFamily.INET:
            self.aliasreq(address, defs.SIOCDIFADDR)

    def down(self):
        cdef defs.ifreq ifr
        memset(&ifr, 0, cython.sizeof(ifr))
        strcpy(ifr.ifr_name, self.nameb)
        ifr.ifr_ifru.ifru_flags[0] = self.__get_flags() & ~defs.IFF_UP
        if self.ioctl(defs.SIOCSIFFLAGS, <void*>&ifr) == -1:
            raise OSError(errno, strerror(errno))

    def up(self):
        cdef defs.ifreq ifr
        memset(&ifr, 0, cython.sizeof(ifr))
        strcpy(ifr.ifr_name, self.nameb)
        ifr.ifr_ifru.ifru_flags[0] = self.__get_flags() | defs.IFF_UP
        if self.ioctl(defs.SIOCSIFFLAGS, <void*>&ifr) == -1:
            raise OSError(errno, strerror(errno))

    def rename(self, name):
        cdef defs.ifreq ifr
        cdef char newname[defs.IFNAMSIZ]

        memset(&ifr, 0, cython.sizeof(ifr))
        strcpy(ifr.ifr_name, self.nameb)
        strcpy(newname, name.encode('ascii'))
        ifr.ifr_ifru.ifru_data = <defs.caddr_t><void*>newname

        if self.ioctl(defs.SIOCSIFNAME, <void*>&ifr) == -1:
            raise OSError(errno, strerror(errno))

        self.name = name
        self.nameb = name.encode('ascii')


cdef class LaggInterface(NetworkInterface):
    def __getstate__(self):
        state = super(LaggInterface, self).__getstate__()
        state.update({
            'protocol': self.protocol.name,
            'ports': [{'name': p, 'flags': [x.name for x in f]} for p, f in self.ports]
        })

        return state

    def add_port(self, name):
        cdef defs.lagg_reqport lreq
        memset(&lreq, 0, cython.sizeof(lreq))
        strcpy(lreq.rp_ifname, self.nameb)
        strcpy(lreq.rp_portname, name.encode('ascii'))
        if self.ioctl(defs.SIOCSLAGGPORT, <void*>&lreq) == -1:
            raise OSError(errno, strerror(errno))

    def delete_port(self, name):
        cdef defs.lagg_reqport lreq
        memset(&lreq, 0, cython.sizeof(lreq))
        strcpy(lreq.rp_ifname, self.nameb)
        strcpy(lreq.rp_portname, name.encode('ascii'))
        if self.ioctl(defs.SIOCSLAGGDELPORT, <void*>&lreq) == -1:
            raise OSError(errno, strerror(errno))

    property protocol:
        def __get__(self):
            cdef defs.lagg_reqall lreq
            memset(&lreq, 0, cython.sizeof(lreq))
            strcpy(lreq.ra_ifname, self.nameb)
            if self.ioctl(defs.SIOCGLAGG, <void*>&lreq) == -1:
                raise OSError(errno, strerror(errno))

            return AggregationProtocol(lreq.ra_proto)

        def __set__(self, value):
            cdef defs.lagg_reqall lreq
            memset(&lreq, 0, cython.sizeof(lreq))
            strcpy(lreq.ra_ifname, self.nameb)
            lreq.ra_proto = value.value
            if self.ioctl(defs.SIOCSLAGG, <void*>&lreq) == -1:
                raise OSError(errno, strerror(errno))

    property ports:
        def __get__(self):
            cdef defs.lagg_reqall lreq
            cdef defs.lagg_reqport lport[16]
            memset(&lreq, 0, cython.sizeof(lreq))
            memset(lport, 0, cython.sizeof(lport))
            strcpy(lreq.ra_ifname, self.nameb)
            lreq.ra_size = cython.sizeof(lport)
            lreq.ra_port = lport

            if self.ioctl(defs.SIOCGLAGG, <void*>&lreq) == -1:
                raise OSError(errno, strerror(errno))

            for i in range(0, lreq.ra_ports):
                yield lport[i].rp_portname.decode('ascii'), bitmask_to_set(lport[i].rp_flags, LaggPortFlags)


cdef class BridgeInterface(NetworkInterface):
    def __getstate__(self):
        state = super(BridgeInterface, self).__getstate__()
        state.update({
            'members': list(self.members)
        })

        return state

    def add_member(self, name):
        cdef defs.ifbreq ifbr

        strcpy(ifbr.ifbr_ifsname, name.encode('ascii'))
        self.bridge_cmd(defs.BRDGADD, &ifbr, cython.sizeof(ifbr), True)

    def delete_member(self, name):
        cdef defs.ifbreq ifbr

        strcpy(ifbr.ifbr_ifsname, name.encode('ascii'))
        self.bridge_cmd(defs.BRDGDEL, &ifbr, cython.sizeof(ifbr), True)

    cdef bridge_cmd(self, cmd, void* arg, size_t size, int set):
        cdef defs.ifdrv ifd

        memset(&ifd, 0, cython.sizeof(ifd))
        strcpy(ifd.ifd_name, self.nameb)
        ifd.ifd_cmd = cmd
        ifd.ifd_len = size
        ifd.ifd_data = arg

        if self.ioctl(defs.SIOCSDRVSPEC if set else defs.SIOCGDRVSPEC, <void*>&ifd) == -1:
            raise OSError(errno, strerror(errno))

    property members:
        def __get__(self):
            cdef defs.ifbreq* ifbr = NULL
            cdef defs.ifbifconf ifbc
            cdef char *buf
            cdef int size = 8192

            while True:
                buf = <char*>realloc(buf, size)
                ifbc.ifbic_len = size
                ifbc.ifbic_buf = <defs.caddr_t>buf

                self.bridge_cmd(defs.BRDGGIFS, &ifbc, cython.sizeof(ifbc), False)

                if (ifbc.ifbic_len + cython.sizeof(ifbr)) < size:
                    break

                size *= 2

            for i in range(0, ifbc.ifbic_len / cython.sizeof(defs.ifbreq)):
                ifbr = &ifbc.ifbic_req[i]
                yield ifbr.ifbr_ifsname.decode('ascii')


cdef class VlanInterface(NetworkInterface):
    def __getstate__(self):
        state = super(VlanInterface, self).__getstate__()
        state.update({
            'parent': self.parent,
            'tag': self.tag
        })

        return state

    cdef get_vlan(self):
        cdef defs.ifreq ifr
        cdef defs.vlanreq vlr

        memset(&vlr, 0, cython.sizeof(ifr))
        strcpy(ifr.ifr_name, self.nameb)
        ifr.ifr_ifru.ifru_data = <defs.caddr_t>&vlr

        if self.ioctl(defs.SIOCGETVLAN, <void*>&ifr) == -1:
            raise OSError(errno, strerror(errno))

        return vlr.vlr_parent, vlr.vlr_tag

    def configure(self, parent, tag):
        cdef defs.ifreq ifr
        cdef defs.vlanreq vlr

        memset(&vlr, 0, cython.sizeof(ifr))
        strcpy(ifr.ifr_name, self.nameb)
        strcpy(vlr.vlr_parent, parent.encode('ascii'))
        vlr.vlr_tag = tag
        ifr.ifr_ifru.ifru_data = <defs.caddr_t>&vlr

        if self.ioctl(defs.SIOCSETVLAN, <void*>&ifr) == -1:
            raise OSError(errno, strerror(errno))

    def unconfigure(self):
        cdef defs.ifreq ifr
        cdef defs.vlanreq vlr

        memset(&vlr, 0, cython.sizeof(ifr))
        strcpy(ifr.ifr_name, self.nameb)
        strcpy(vlr.vlr_parent, '\0')
        vlr.vlr_tag = 0
        ifr.ifr_ifru.ifru_data = <defs.caddr_t>&vlr

        if self.ioctl(defs.SIOCSETVLAN, <void*>&ifr) == -1:
            raise OSError(errno, strerror(errno))

    property parent:
        def __get__(self):
            return self.get_vlan()[0]

    property tag:
        def __get__(self):
            return self.get_vlan()[1]


cdef class RoutingPacket(object):
    cdef readonly object data
    cdef char *buffer
    cdef size_t bufsize
    cdef defs.rt_msghdr *rt_msg

    def __init__(self, data=None):
        if data:
            self.data = data
            self.bufsize = len(data)
            self.buffer = <char*>data

        self.rt_msg = <defs.rt_msghdr*>self.buffer

    def __getstate__(self):
        return {
            'type': self.type.name,
            'version': self.version,
            'length': self.length
        }

    cdef _grow(self, amount):
        self.bufsize += amount
        self.buffer = <char*>realloc(self.buffer, self.bufsize)
        self.rt_msg = <defs.rt_msghdr*>self.buffer

    cdef _align_sa_len(self, int length):
        return 1 + ((length - 1) | (cython.sizeof(long) - 1))

    cdef _parse_sockaddr_dl(self, defs.sockaddr_dl* sdl):
        cdef char ifname[defs.IFNAMSIZ]

        result = LinkAddress(sdl.sdl_data[:sdl.sdl_nlen])
        if not result.ifname:
            if defs.if_indextoname(sdl.sdl_index, ifname) != NULL:
                result.ifname = ifname.decode('ascii')

        result.address = ':'.join(['{0:02x}'.format(x) for x in bytearray(sdl.sdl_data[sdl.sdl_nlen:sdl.sdl_nlen+sdl.sdl_alen])])
        return result

    cdef _parse_sockaddrs(self, int start_offset, int mask):
        cdef defs.sockaddr* sa
        cdef defs.sockaddr_in* sin
        cdef defs.sockaddr_in6* sin6
        cdef char netmask[16]

        addr_sa_family = None
        ptr = start_offset
        result = {}

        for i in range(0, 7):
            if not mask & (1 << i):
                continue

            sa = <defs.sockaddr*>&self.buffer[ptr]
            ptr += self._align_sa_len(sa.sa_len)

            if sa.sa_family == defs.AF_INET:
                addr_sa_family = sa.sa_family
                sin = <defs.sockaddr_in*>sa
                result[i] = ipaddress.ip_address(socket.ntohl(sin.sin_addr.s_addr))

            elif sa.sa_family == defs.AF_INET6:
                addr_sa_family = sa.sa_family
                sin6 = <defs.sockaddr_in6*>sa
                result[i] = ipaddress.ip_address(sin6.sin6_addr.s6_addr[:16])

            elif sa.sa_family == defs.AF_LINK:
                sdl = <defs.sockaddr_dl*>sa
                result[i] = self._parse_sockaddr_dl(sdl)

            elif sa.sa_family in (0x00, 0xff) and i == defs.RTAX_NETMASK:
                # Hack for getting netmask information when parsing route messages
                # obtained via sysctl(3). I don't know why netmask sockaddrs are malformed.
                if sa.sa_len == 0:
                    # default route
                    if addr_sa_family == defs.AF_INET:
                        result[i] = ipaddress.ip_address('0.0.0.0')

                    if addr_sa_family == defs.AF_INET6:
                        result[i] = ipaddress.ip_address('::')

                else:
                    if addr_sa_family == defs.AF_INET:
                        result[i] = ipaddress.ip_address(sa.sa_data[2:6])

                    if addr_sa_family == defs.AF_INET6:
                        sin6 = <defs.sockaddr_in6*>sa
                        memset(netmask, 0, sizeof(netmask))
                        memcpy(netmask, sin6.sin6_addr.s6_addr, min(16, sa.sa_len - 8))
                        result[i] = ipaddress.ip_address(netmask[:16])

        return result

    cdef _pack_sockaddrs(self, int start_offset, addrs):
        cdef defs.sockaddr_dl* sdl
        cdef defs.sockaddr_in* sin
        cdef defs.sockaddr_in6* sin6
        cdef int ptr
        cdef int mask

        mask = 0
        ptr = start_offset

        for rtax, i in addrs.items():
            if not i:
                continue

            mask |= (1 << rtax)

            if type(i) is LinkAddress:
                sa_size = self._align_sa_len(sizeof(defs.sockaddr_dl))
                self._grow(sa_size)
                sdl = <defs.sockaddr_dl*>&self.buffer[ptr]
                memset(sdl, 0, sa_size)
                sdl.sdl_family = defs.AF_LINK
                sdl.sdl_len = cython.sizeof(defs.sockaddr_dl)
                sdl.sdl_index = defs.if_nametoindex(i.ifname)
                ptr += sa_size

            elif i.version == 4:
                sa_size = self._align_sa_len(sizeof(defs.sockaddr_in))
                self._grow(sa_size)
                sin = <defs.sockaddr_in*>&self.buffer[ptr]
                memset(sin, 0, sa_size)
                sin.sin_family = defs.AF_INET
                sin.sin_len = cython.sizeof(defs.sockaddr_in)
                sin.sin_addr.s_addr = socket.htonl(int(i))
                ptr += sa_size

            elif i.version == 6:
                sa_size = self._align_sa_len(sizeof(defs.sockaddr_in6))
                self._grow(sa_size)
                sin6 = <defs.sockaddr_in6*>&self.buffer[ptr]
                memset(sin6, 0, sa_size)
                sin6.sin6_family = defs.AF_INET6
                sin6.sin6_len = cython.sizeof(defs.sockaddr_in6)
                memcpy(&sin6.sin6_addr, <char*>i.packed, 16)
                ptr += sa_size

        return mask

    property type:
        def __get__(self):
            return RoutingMessageType(self.rt_msg.rtm_type)

        def __set__(self, value):
            self.rt_msg.rtm_type = value

    property version:
        def __get__(self):
            return self.rt_msg.rtm_version

    property length:
        def __get__(self):
            return self.rt_msg.rtm_msglen


cdef class InterfaceAnnounceMessage(RoutingPacket):
    cdef defs.if_announcemsghdr* header

    def __init__(self, packet):
        super(InterfaceAnnounceMessage, self).__init__(packet)
        self.header = <defs.if_announcemsghdr*>self.buffer

    def __getstate__(self):
        state = super(InterfaceAnnounceMessage, self).__getstate__()
        state.update({
            'interface': self.interface,
            'type': self.type
        })

        return state

    property interface:
        def __get__(self):
            return self.header.ifan_name.decode('ascii')

    property type:
        def __get__(self):
            return InterfaceAnnounceType(self.header.ifan_what)


cdef class InterfaceInfoMessage(RoutingPacket):
    cdef defs.if_msghdr* header
    cdef readonly object addrs
    cdef int addrs_mask

    def __init__(self, packet):
        super(InterfaceInfoMessage, self).__init__(packet)
        self.header = <defs.if_msghdr*>self.buffer
        self.addrs_mask = self.header.ifm_addrs
        self.addrs = self._parse_sockaddrs(cython.sizeof(defs.if_msghdr), self.addrs_mask)

    def __getstate__(self):
        state = super(InterfaceInfoMessage, self).__getstate__()
        state.update({
            'flags': self.flags,
            'interface': self.interface,
            'link-state': self.link_state
        })

        return state

    property flags:
        def __get__(self):
            return bitmask_to_set(self.header.ifm_flags, InterfaceFlags)

    property link_state:
        def __get__(self):
            return InterfaceLinkState(self.header.ifm_data.ifi_link_state)

    property mtu:
        def __get__(self):
            return self.header.ifm_data.ifi_mtu

    property interface:
        def __get__(self):
            cdef char ifname[defs.IFNAMSIZ]
            if defs.if_indextoname(self.header.ifm_index, ifname) != NULL:
                return ifname.decode('ascii')

            return None

cdef class InterfaceAddrMessage(RoutingPacket):
    cdef defs.ifa_msghdr* header
    cdef readonly object addrs
    cdef int addrs_mask

    def __init__(self, packet):
        super(InterfaceAddrMessage, self).__init__(packet)
        self.header = <defs.ifa_msghdr*>self.buffer
        self.addrs_mask = self.header.ifam_addrs
        self.addrs = self._parse_sockaddrs(cython.sizeof(defs.ifa_msghdr), self.addrs_mask)

    def __getstate__(self):
        state = super(InterfaceAddrMessage, self).__getstate__()
        state.update({
            'flags': self.flags,
            'interface': self.interface,
        })

        if self.address:
            state['address'] = str(self.address)

        if self.netmask:
            state['netmask'] = str(self.netmask)

        if self.dest_address:
            state['dest-address'] = str(self.dest_address)

        return state

    property address:
        def __get__(self):
            if defs.RTAX_IFA in self.addrs:
                return self.addrs[defs.RTAX_IFA]

            return None

    property netmask:
        def __get__(self):
            if defs.RTAX_NETMASK in self.addrs:
                return self.addrs[defs.RTAX_NETMASK]

            return None

    property dest_address:
        def __get__(self):
            if defs.RTAX_BRD in self.addrs:
                return self.addrs[defs.RTAX_BRD]

            return None

    property flags:
        def __get__(self):
            return bitmask_to_set(self.header.ifam_flags, InterfaceFlags)

    property interface:
        def __get__(self):
            cdef char ifname[defs.IFNAMSIZ]
            if defs.if_indextoname(self.header.ifam_index, ifname) != NULL:
                return ifname.decode('ascii')

            return None


cdef class RoutingMessage(RoutingPacket):
    cdef readonly object addrs
    cdef int addrs_mask
    cdef int free

    def __init__(self, packet=None):
        if not packet:
            self.free = True
            self.bufsize = cython.sizeof(defs.rt_msghdr)
            self.buffer = <char*>malloc(self.bufsize)
            memset(self.buffer, 0, self.bufsize)
        else:
            self.free = False

        super(RoutingMessage, self).__init__(packet)
        self.addrs_mask = self.rt_msg.rtm_addrs
        self.addrs = self._parse_sockaddrs(cython.sizeof(defs.rt_msghdr), self.addrs_mask)

    def __dealloc__(self):
        if self.free:
            free(self.buffer)

    def __getstate__(self):
        state = super(RoutingMessage, self).__getstate__()
        gateway = None
        if self.gateway is not None:
            gateway = self.gateway.__getstate__() if type(self.gateway) is LinkAddress else str(self.gateway)

        state.update({
            'errno': self.errno,
            'flags': [x.name for x in self.flags],
            'interface': self.interface,
            'network': str(self.network),
            'gateway': gateway
        })

        if self.netmask:
            state['netmask'] = str(self.netmask)

        return state

    def as_buffer(self):
        self.rt_msg.rtm_version = 5
        self.rt_msg.rtm_addrs = self._pack_sockaddrs(cython.sizeof(defs.rt_msghdr), self.addrs)
        self.rt_msg.rtm_msglen = self.bufsize
        return self.buffer[:self.bufsize]

    property errno:
        def __get__(self):
            return self.rt_msg.rtm_errno

    property flags:
        def __get__(self):
            return bitmask_to_set(self.rt_msg.rtm_flags, RouteFlags)

        def __set__(self, value):
            self.rt_msg.rtm_flags = set_to_bitmask(value)

    property interface:
        def __get__(self):
            cdef char ifname[defs.IFNAMSIZ]
            cdef char* result
            result = defs.if_indextoname(self.rt_msg.rtm_index, ifname)
            return result.decode('ascii') if result != NULL else None

        def __set__(self, value):
            self.rt_msg.rtm_index = defs.if_nametoindex(value.encode('ascii'))

    property network:
        def __get__(self):
            if defs.RTAX_DST in self.addrs:
                return self.addrs[defs.RTAX_DST]

            return None

        def __set__(self, value):
            self.addrs[defs.RTAX_DST] = value

    property netmask:
        def __get__(self):
            if defs.RTAX_NETMASK in self.addrs:
                return self.addrs[defs.RTAX_NETMASK]

            return None

        def __set__(self, value):
            self.addrs[defs.RTAX_NETMASK] = value

    property gateway:
        def __get__(self):
            if defs.RTAX_GATEWAY in self.addrs:
                return self.addrs[defs.RTAX_GATEWAY]

            return None

        def __set__(self, value):
            self.addrs[defs.RTAX_GATEWAY] = value

    property route:
        def __get__(self):
            result = Route(
                self.network,
                self.netmask,
                self.gateway,
                self.interface
            )

            result.flags = self.flags
            return result

        def __set__(self, route):
            self.network = route.network
            self.netmask = route.netmask
            self.gateway = route.gateway
            self.flags = route.flags & {RouteFlags.STATIC, RouteFlags.GATEWAY, RouteFlags.HOST}
            if route.interface:
                self.interface = route.interface


class Route(object):
    def __init__(self, network, netmask, gateway=None, interface=None):
        self.network = ipaddress.ip_address(network)
        self.netmask = None
        self.gateway = None
        self.interface = None
        self.flags = set()

        if netmask:
            self.netmask = ipaddress.ip_address(netmask)

        if gateway:
            if type(gateway) is LinkAddress:
                self.gateway = gateway.ifname
            else:
                self.gateway = ipaddress.ip_address(gateway)

        if interface:
            self.interface = interface

    @property
    def af(self):
        if not self.network:
            return None

        if self.network.version == 4:
            return AddressFamily.INET

        if self.network.version == 6:
            return AddressFamily.INET6

        return None

    def __getstate__(self):
        return {
            'network': str(self.network),
            'netmask': str(self.netmask) if self.netmask else None,
            'gateway': str(self.gateway) if self.gateway else None,
            'interface': self.interface or None,
            'flags': [x.name for x in self.flags]
        }

    def __eq__(self, other):
        return self.network == other.network and \
            self.netmask == other.netmask and \
            self.gateway == other.gateway

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((
            self.network,
            self.netmask,
            self.gateway
        ))


class RoutingTable(object):
    def __init__(self):
        pass

    def __send_message(self, msg):
        if msg.type == RoutingMessageType.DELETE:
            msg.gateway = None

        sock = RoutingSocket()
        sock.open()
        sock.write_message(msg)
        sock.close()

    def __send_route(self, type, route):
        msg = RoutingMessage()
        msg.type = type
        msg.route = route
        self.__send_message(msg)

    @property
    def default_route_ipv4(self):
        f = list(filter(lambda r: int(r.network) == 0 and int(r.netmask) == 0 and r.af == AddressFamily.INET, self.routes))
        return f[0] if len(f) > 0 else None

    @property
    def default_route_ipv6(self):
        f = list(filter(lambda r: int(r.network) == 0 and int(r.netmask) == 0 and r.af == AddressFamily.INET6, self.routes))
        return f[0] if len(f) > 0 else None

    @property
    def routes(self):
        cdef char* buf
        cdef defs.rt_msghdr* rt_msg

        data = sysctl.sysctl([defs.CTL_NET, defs.AF_ROUTE, 0, 0, defs.NET_RT_DUMP, 0])
        data = array.array('b', data).tostring()
        buf = data
        ptr = 0

        while ptr < len(data):
            rt_msg = <defs.rt_msghdr*>&buf[ptr]
            msg = RoutingMessage(data[ptr:ptr+rt_msg.rtm_msglen])
            ptr += rt_msg.rtm_msglen
            yield msg.route

    @property
    def default_route(self):
        f = list(filter(lambda r: r.network == ipaddress.ip_address(u'0.0.0.0'), self.routes))
        return f[0] if f else None

    @property
    def static_routes(self):
        return list(filter(lambda r: RouteFlags.STATIC in r.flags and r.network != ipaddress.ip_address(u'0.0.0.0'), self.routes))

    def add(self, route):
        self.__send_route(RoutingMessageType.ADD, route)

    def delete(self, route):
        self.__send_route(RoutingMessageType.DELETE, route)

    def change(self, route):
        self.__send_route(RoutingMessageType.CHANGE, route)


class RoutingSocket(object):
    def __init__(self):
        self.socket = None

    def open(self):
         self.socket = socket.socket(socket.AF_ROUTE, socket.SOCK_RAW, 0)

    def close(self):
        self.socket.close()

    def read_message(self):
        cdef char* buffer
        cdef defs.rt_msghdr* rt_msg

        packet = os.read(self.socket.fileno(), 1024)

        if packet is None:
            return None

        buffer = <char*>packet
        rt_msg = <defs.rt_msghdr*>buffer

        if rt_msg.rtm_type in (RoutingMessageType.IFANNOUNCE, RoutingMessageType.IEEE80211):
            return InterfaceAnnounceMessage(packet)

        if rt_msg.rtm_type == RoutingMessageType.IFINFO:
            return InterfaceInfoMessage(packet)

        if rt_msg.rtm_type in (RoutingMessageType.NEWADDR, RoutingMessageType.DELADDR):
            return InterfaceAddrMessage(packet)

        return RoutingMessage(packet)

    def write_message(self, message):
        buf = message.as_buffer()
        os.write(self.socket.fileno(), buf)

def get_ifgroup(groupname):
    """Given group name such as vnet or bridge, get group members"""
    cdef defs.ifgroupreq ifgr
    cdef defs.ifg_req *ifg
    cdef int len
    cdef char *mem

    groupname = groupname.encode('ascii')
    result = []
    with sock3(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
        memset(&ifgr, 0, cython.sizeof(ifgr))
        strcpy(ifgr.ifgr_name, groupname)
        if defs.ioctl(s.fileno(), defs.SIOCGIFGMEMB, <void*>&ifgr) == -1:
            if errno in (EINVAL, ENOTTY, ENOENT):
                return result
            raise OSError(errno, strerror(errno))
        len = ifgr.ifgr_len
        mem = NULL
        try:
            mem = <char*>malloc(len)
            memset(mem, 0, len)
            ifgr.ifgr_ifgru.ifgru_groups = <defs.ifg_req*>mem
            if defs.ioctl(s.fileno(), defs.SIOCGIFGMEMB, <void*>&ifgr) == -1:
                raise OSError(errno, strerror(errno))
            ifg = ifgr.ifgr_ifgru.ifgru_groups
            while len >= cython.sizeof(defs.ifg_req):
                result.append(ifg.ifgrq_ifgrqu.ifgrqu_member.decode('ascii'))
                ifg += 1
                len -= cython.sizeof(defs.ifg_req)
        finally:
            if mem:
                free(mem)
    return result

cdef int _get_in6_ifa_flags(char* name, defs.sockaddr_in6* sin6):
    cdef defs.in6_ifreq ifr6

    memset(&ifr6, 0, cython.sizeof(ifr6))
    strcpy(ifr6.ifr_name, name)
    ifr6.ifr_ifru.ifru_addr = sin6[0]
    with sock3(socket.AF_INET6, socket.SOCK_DGRAM) as s:
        if defs.ioctl(s.fileno(), defs.SIOCGIFAFLAG_IN6, <void*>&ifr6) == -1:
            return -1
        # Might want to get ifa lifetime here too, while
        # we have ifr6 set up, and socket s.  But not yet.
    return ifr6.ifr_ifru.ifru_flags6

cdef list_interfaces_internal(names, typemap, defs.ifaddrs* ifa):
    cdef defs.sockaddr_in* sin
    cdef defs.sockaddr_in6* sin6
    cdef defs.sockaddr_dl* sdl
    cdef defs.sockaddr* sa
    cdef NetworkInterface iface
    cdef object itype
    cdef int ia6_flags

    if typemap is None:
        # NB: we assume no vlan is a lagg, etc.  If someone has
        # erroneously shoved an interface into multiple groups,
        # the last one here overrides due to the update().
        typemap = {}
        typemap.update(dict((i, VlanInterface) for i in get_ifgroup('vlan')))
        typemap.update(dict((i, LaggInterface) for i in get_ifgroup('lagg')))
        typemap.update(dict((i, BridgeInterface)
                            for i in get_ifgroup('bridge')))

    result = {}
    while ifa:
        name = ifa.ifa_name.decode('ascii')
        if names is not None and name not in names:
            ifa = ifa.ifa_next
            continue

        if name not in result:
            itype = typemap.get(name, NetworkInterface)
            iface = itype.__new__(itype)

            iface.name = name
            iface.nameb = name.encode('ascii')
            iface.addresses = []
            result[name] = iface

        nic = result[name]
        sa = ifa.ifa_addr
        addr = InterfaceAddress(AddressFamily(sa.sa_family))

        if sa.sa_family == defs.AF_INET:
            if ifa.ifa_addr != NULL:
                sin = <defs.sockaddr_in*>ifa.ifa_addr
                addr.address = ipaddress.ip_address(socket.ntohl(sin.sin_addr.s_addr))

            if ifa.ifa_netmask != NULL:
                sin = <defs.sockaddr_in*>ifa.ifa_netmask
                addr.netmask = ipaddress.ip_address(socket.ntohl(sin.sin_addr.s_addr))

            if ifa.ifa_broadaddr != NULL:
                sin = <defs.sockaddr_in*>ifa.ifa_broadaddr
                addr.broadcast = ipaddress.ip_address(socket.ntohl(sin.sin_addr.s_addr))

            elif ifa.ifa_dstaddr != NULL:
                sin = <defs.sockaddr_in*>ifa.ifa_dstaddr
                addr.dest_address = ipaddress.ip_address(socket.ntohl(sin.sin_addr.s_addr))

        if sa.sa_family == defs.AF_INET6:
            if ifa.ifa_addr != NULL:
                sin6 = <defs.sockaddr_in6*>ifa.ifa_addr
                addr.address = ipaddress.ip_address(sin6.sin6_addr.s6_addr[:16])
                # Get flags for this address.  Note that they're
                # stored via the interface address (which is what
                # we just got from the kernel) but it's possible that
                # we lost a race and the address is gone already.
                # It's not clear what to do in this case (ignore
                # the address?).  For now, we leave addr.ipv6_flags
                # set to None.
                ia6_flags = _get_in6_ifa_flags(iface.nameb, sin6)
                if ia6_flags != -1:
                    addr.ipv6_flags = bitmask_to_set(ia6_flags, In6AddrFlags)
                if str(addr.address).startswith('fe80:'):
                    addr.scope = sin6.sin6_scope_id

            if ifa.ifa_netmask != NULL:
                sin6 = <defs.sockaddr_in6*>ifa.ifa_netmask
                addr.netmask = ipaddress.ip_address(sin6.sin6_addr.s6_addr[:16])

            if ifa.ifa_broadaddr != NULL:
                sin6 = <defs.sockaddr_in6*>ifa.ifa_broadaddr
                addr.broadcast = ipaddress.ip_address(sin6.sin6_addr.s6_addr[:16])

            if ifa.ifa_dstaddr != NULL:
                sin6 = <defs.sockaddr_in6*>ifa.ifa_dstaddr
                addr.dest_address = ipaddress.ip_address(sin6.sin6_addr.s6_addr[:16])

        if sa.sa_family == defs.AF_LINK:
            if ifa.ifa_addr != NULL:
                sdl = <defs.sockaddr_dl*>ifa.ifa_addr
                nic.type = InterfaceType(sdl.sdl_type)
                addr.address = LinkAddress(
                    sdl.sdl_data[:sdl.sdl_nlen],
                    ':'.join(['{0:02x}'.format(x) for x in bytearray(sdl.sdl_data[sdl.sdl_nlen:sdl.sdl_nlen+sdl.sdl_alen])]))

        nic.addresses.append(addr)

        ifa = ifa.ifa_next

    return result

def list_interfaces(names=None, typemap=None):
    """
    Return a dictionary of all interfaces in the system.

    If you supply a list (or anything indexable, really) of names
    and a type-map we'll only return interfaces that are in that
    list and we'll use the type-mapper to make their instances.
    This is mostly for internal use, in get_interface(), but it's
    valid for any caller, e.g.:

        result = list_interfaces(names=['em0', 'lo0'])

    to get information on just those two interfaces, or:

        result = list_interfaces(names=['mgmt0'],
                                 typemap={'mgmt0': BridgeInterface})

    to get information on mgmt0.  Note that the latter is
    basically the same as:

        get_interface('mgmt0', force_type='bridge')

    but will return an empty dictionary if the interface doesn't
    exist.
    """
    cdef defs.ifaddrs* ifa

    if defs.getifaddrs(&ifa) != 0:
        return None
    try:
        return list_interfaces_internal(names, typemap, ifa)
    finally:
        defs.freeifaddrs(ifa)

def bitmask_to_set(n, enumeration):
    result = set()
    while n:
        b = n & (~n+1)
        try:
            result.add(enumeration(b))
        except ValueError:
            pass

        n ^= b

    return result


def set_to_bitmask(value):
    result = 0
    for i in value:
        result |= int(i)

    return result


def get_interface(name, force_type=None, **kwargs):
    """
    Get the given interface.  Raises KeyError if interface does
    not exist.  If force_type is provided it should be a string
    in ('bridge', 'lagg', 'vlan') and it sets the type of the
    interface.

    For compatibility we temporarily allow bridge=True as a
    keyword argument that sets force_type='bridge'.
    """
    typemap = None
    if kwargs.pop('bridge', False):
        force_type = 'bridge'
    if kwargs:
        raise TypeError('get_interface() got an unexpected keyword '
                        'argument: ' + kwargs.popitem()[0])
    if force_type is not None:
        itype = {
            'vlan': VlanInterface,
            'lagg': LaggInterface,
            'bridge': BridgeInterface,
        }[force_type]
        typemap = {name: itype}
    return list_interfaces([name], typemap)[name]


def create_interface(name):
    """create new cloned interface (vlan, lagg, bridge)"""
    name = name.encode('ascii')
    cdef defs.ifreq ifr
    with sock3(socket.AF_INET, socket.SOCK_STREAM) as s:
        strcpy(ifr.ifr_name, name)
        if defs.ioctl(s.fileno(), defs.SIOCIFCREATE, <void*>&ifr) == -1:
            raise OSError(errno, strerror(errno))
    return ifr.ifr_name.decode('ascii')


def destroy_interface(name):
    """destroy specified interface (probably should only use on clones)"""
    name = name.encode('ascii')
    cdef defs.ifreq ifr
    with sock3(socket.AF_INET, socket.SOCK_STREAM) as s:
        strcpy(ifr.ifr_name, name)
        if defs.ioctl(s.fileno(), defs.SIOCIFDESTROY, <void*>&ifr) == -1:
            raise OSError(errno, strerror(errno))
    return ifr.ifr_name.decode('ascii')


def get_hostname():
    cdef char buf[defs._SC_HOST_NAME_MAX]

    if defs.gethostname(buf, cython.sizeof(buf)) != 0:
        raise OSError(errno, strerror(errno))


def set_hostname(newhostname):
    newhostname = newhostname.encode('ascii')
    if defs.sethostname(newhostname, len(newhostname)) != 0:
        raise OSError(errno, strerror(errno))
