#!/usr/bin/env python

import os,sys,struct,time,random
from fcntl import ioctl
from subprocess import call
from select import select

from construct import *
from construct.protocols.layer3.ipv4 import ipv4_header
from construct.protocols.layer3.icmpv4 import icmp_header
from construct.protocols.layer3.ipv6 import ipv6_header,Ipv6Address,Ipv6AddressAdapter
from construct.protocols.layer3.icmpv6 import icmpv6_header
from construct.protocols.layer4.tcp import tcp_header


tun_header = Struct("tun_header",
	UBInt16("flags"),
	Enum(UBInt16("type"),
		IPv4 = 0x0800,
		ARP = 0x0806,
		RARP = 0x8035,
		X25 = 0x0805,
		IPX = 0x8137,
		IPv6 = 0x86DD,
		_default_ = Pass,
	),
)

layer4_tcp = Struct("layer4_tcp",
	Rename("header", tcp_header),
	HexDumpAdapter(
		Field("next", lambda ctx: 
			ctx["_"]["header"].payload_length - ctx["header"].header_length
		)   
	),  
)


layer3_payload = Switch("next", lambda ctx: ctx["header"].protocol,
	{
		"ICMP" : icmp_header,
		"ICMPv6" : icmpv6_header,
		"TCP" : layer4_tcp,

	},
	default = Pass
)

layer3_ipv4 = Struct("layer3_ipv4",
	Rename("header", ipv4_header),
	layer3_payload,
)
layer3_ipv6 = Struct("layer3_ipv6",
	Rename("header", ipv6_header),
	layer3_payload,
)

layer2_tun = Struct("layer2_tun",
	Rename("header", tun_header),
	Switch("next", lambda ctx: ctx["header"].type,
		{
			"IPv4" : layer3_ipv4,
			"IPv6" : layer3_ipv6,
		},
		default = Pass,
	)
)

TUNSETIFF	= 0x400454ca
IFF_TUN		= 0x0001
IFF_TAP		= 0x0002
TUN_NOCHECKSUM	= 0x0020
class NoMapping(Exception):
	pass
class BindingInformationBase:
	def __init__(self,src_ips):
		self.src_ip_pool=src_ips
		self.bibs={
			'TCP':{},
			'UDP':{},
			'ICMP':{}
		}
	def get_free_src(self,proto):

		while True:
			src_ip=random.choice(self.src_ip_pool)
			src_port=random.randint(1024,65535)
			if not (src_ip,src_port) in self.bibs[proto]:
				return (src_ip,src_port)
	def get_map(self,proto,src_ip,src_port,no_create=False):
		t=time.time()
		if (src_ip,src_port) in self.bibs[proto]:
			nat_ip=self.bibs[proto][(src_ip,src_port)][0]
			nat_port=self.bibs[proto][(src_ip,src_port)][1]
		else:
			if no_create:
				raise NoMapping()
			(nat_ip,nat_port)=self.get_free_src(proto)
		self.bibs[proto][(src_ip,src_port)]=(nat_ip,nat_port,t)
		self.bibs[proto][(nat_ip,nat_port)]=(src_ip,src_port,t)
		return (nat_ip,nat_port)
		



class Skel:
	pass

def build_h4_from_h6(h6):
	# RFC 6145 5.1
	x=Skel()
	x.version=4
	x.header_length=20
	x.tos=h6.traffic_class
	x.total_length=h6.payload_length+x.header_length
	x.payload_length=h6.payload_length
	x.identification=0
	x.flags=Skel()
	x.flags.dont_fragment=1
	x.flags.more_fragments=0
	x.frame_offset=0
	x.ttl=h6.hoplimit
	x.protocol=h6.protocol	# FIXME
	x.checksum=0		# FIXME
	x.source="0.0.0.0"	# FIXME
	dst="".join(part.decode("hex") for part in h6.destination.split(":"))[-4:]
	x.destination=".".join(str(ord(b)) for b in dst)
	x.options=''
	return x		# FIXME

def build_h6_from_h4(h4,v6prefix):
	# RFC 6145 4.1
	x=Skel()
	x.version=6
	x.traffic_class=h4.tos
	x.flow_label=0
	x.payload_length=h4.payload_length
	x.protocol=h4.protocol  # FIXME
	x.hoplimit=h4.ttl
	x.ttl=h4.ttl
	a6=[("%x" % int(t)) for t in h4.source.split(".")]
	#x.source=v6prefix+a6[0]+a6[1]+":"+a6[2]+a6[3] - FIXME - tak jest poprawnie, ale jest zly adapter
	x.source=v6prefix+":".join(a6)
	return x
def fix_checksum(data,start,stop,cs_loc):
	checksum=0
	csdata=data
	if (len(csdata) & 1) == 1:
		csdata+=chr(0)
	for i in range(start,stop,2):
		checksum += (ord(csdata[i]) << 8)+ord(csdata[i+1])
	while (checksum>>16) > 0 :
		checksum = (checksum & 0xffff) + (checksum >> 16);
	checksum = (~checksum & 0xffff);
	return data[:cs_loc]+chr(checksum >> 8)+chr(checksum & 0xff)+data[(cs_loc+2):]

def fix_ipv4_checksum(data,ip_offset=4):
	return fix_checksum(data,start=ip_offset,stop=ip_offset+20,cs_loc=ip_offset+10)

def fix_tcpv4_checksum(data,ip_offset=4,ip_hl=20):
	tl=len(data[ip_offset+ip_hl:])
	tcpph=data[ip_offset+12:ip_offset+20]+chr(0)+data[ip_offset+9]+chr( (tl>>8) & 0xff)+chr(tl & 0xff)+data[ip_offset+ip_hl:]
#	print "tcp cs=%x" % ( (ord(tcpph[28])<<8) + ord(tcpph[29]) )
	tcpph=fix_checksum(tcpph,0,len(tcpph),28)
#	print "tcp cs=%x" % ( (ord(tcpph[28])<<8) + ord(tcpph[29]) )
	return data[:ip_offset+ip_hl+16]+tcpph[28]+tcpph[29]+data[ip_offset+ip_hl+18:]

def fix_tcpv6_checksum(data,ip_offset=4,tcp_offset=40):
	tl=len(data[ip_offset+tcp_offset:])
#	print "tl=%d" % tl
	tcpph=data[ip_offset+8:ip_offset+40]+	\
		chr( (tl>>24) & 0xff)+chr( (tl>>16) & 0xff)+chr( (tl>>8) & 0xff)+chr(tl & 0xff)+	\
		chr(0)+chr(0)+chr(0)+chr(6)+	\
		data[ip_offset+tcp_offset:]
#	print "tcp cs=%x" % ( (ord(tcpph[56])<<8) + ord(tcpph[57]) )
	tcpph=fix_checksum(tcpph,0,len(tcpph),56)
#	print "tcp cs=%x" % ( (ord(tcpph[56])<<8) + ord(tcpph[57]) )
	return data[:ip_offset+tcp_offset+16]+tcpph[56]+tcpph[57]+data[ip_offset+tcp_offset+18:]

def print_packet(packet,prefix="\t"):
	pt=packet.header.type
	proto=packet.next.header.protocol
	src='['+packet.next.header.source+']'
	dst='['+packet.next.header.destination+']'
	add_info=''
	if pt == 'IPv4':
		add_info+=' TTL=%d' % packet.next.header.ttl
		add_info+=' IPCS=%x' % packet.next.header.checksum
	elif pt == 'IPv6':
		add_info+=' HL=%d' % packet.next.header.hoplimit
	if proto == 'TCP':
		src+=':%d' % packet.next.next.header.source
		dst+=':%d' % packet.next.next.header.destination
		add_info+=' TCPCS=%x' % packet.next.next.header.checksum
	print "%s[%s] %s -> %s%s" % (prefix, packet.header.type, src, dst, add_info)

f4 = os.open("/dev/net/tun", os.O_RDWR)
ifs = ioctl(f4, TUNSETIFF, struct.pack("16sH", "nat64_v4_%d", IFF_TUN|TUN_NOCHECKSUM))
if4name = ifs[:16].strip("\x00")

f6 = os.open("/dev/net/tun", os.O_RDWR)
ifs = ioctl(f6, TUNSETIFF, struct.pack("16sH", "nat64_v6_%d", IFF_TUN|TUN_NOCHECKSUM))
if6name = ifs[:16].strip("\x00")


src_ips=[ "173.255.206.201" ]


print "Uzywam interfejsu v4: %s, v6: %s." % (if4name, if6name)

call("ip link set dev %s up" % if4name, shell=True)
call("ip link set dev %s up" % if6name, shell=True)

for src_ip in src_ips:
	call("ip route add %s dev %s" % (src_ip,if4name), shell=True)
call("ip route add 2001:470:1f0f:4dc:0:1::/96 dev %s" % if6name, shell=True)

bib=BindingInformationBase(src_ips)

while (1):
	r = select([f4,f6],[],[],1)[0]
	if f4 in r:
		print "New packet on v4 interface"
		buf4=os.read(f4,1600)
		p4=layer2_tun.parse(buf4)

		print_packet(p4,"\t ORIG ")

		if p4.header.type != 'IPv4':
			print "\t[IPv4] DROP: Wrong protocol (%s)" % p4.header.type
			continue

		p4.next.header.ttl-=1
		if p4.next.header.ttl == 0:
			print "\t[IPv4] DROP: hoplimit==0"
			continue

		#print p4
		src_ip=p4.next.header.source
		dst_ip=p4.next.header.destination
		proto=p4.next.header.protocol
		src_port=0
		dst_port=0
		if proto == 'TCP':
			src_port=p4.next.next.header.source
			dst_port=p4.next.next.header.destination
		else:
			print "\t[IPv4] DROP: Unknow transport protocol (%s)" % proto
			continue
		#print bib.bibs
		#print "src_ip=%s, dst_ip=%s, proto=%s, src_port=%d, dst_port=%d" % (src_ip,dst_ip,proto,src_port,dst_port)
		try:
			(nat_ip,nat_port)=bib.get_map(proto,dst_ip,dst_port,True)
		except NoMapping as e:
			print "\t[IPv4] DROP: No mapping in BIB"
			continue

		#print "nat_ip=%s, nat_port=%d" % (nat_ip,nat_port)

		h6=build_h6_from_h4(p4.next.header,"20:01:04:70:1f:0f:04:dc:00:00:00:01:")

		p6=Skel()
		p6.header=Skel()
		p6.header.flags=0
		p6.header.type='IPv6'
		p6.next=Skel()
		p6.next.header=h6
		p6.next.header.destination=nat_ip
		p6.next.next=p4.next.next
		if proto == 'TCP':
			p4.next.next.header.destination=nat_port
			p4.next.next.header.checksum=0
		tmp=layer2_tun.build(p6)
		if proto == 'TCP':
			tmp=fix_tcpv6_checksum(tmp)
		os.write(f6,tmp)
		tmp6=layer2_tun.parse(tmp)
		#print tmp6
		print_packet(tmp6,"\t NAT ")
	if f6 in r:
		print "New packet on v6 interface"
		buf6=os.read(f6,1600)
		p6=layer2_tun.parse(buf6)
		print_packet(p6,"\t ORIG ")

		if p6.header.type != 'IPv6':
			print "\t[IPv6] DROP: Wrong protocol (%s)" % p6.header.type
			continue

		p6.next.header.hoplimit-=1		
		if p6.next.header.hoplimit == 0:
			print "\t[IPv6] DROP: hoplimit==0"
			continue
		
		#print p6
		src_ip=p6.next.header.source
		proto=p6.next.header.protocol
		src_port=0
		if proto == 'TCP':
			src_port=p6.next.next.header.source
		else:
			print "\t[IPv6] DROP: Unknow transport protocol (%s)" % proto
			continue
		(nat_ip,nat_port)=bib.get_map(proto,src_ip,src_port)
		#print nat_ip,nat_port
		#print src_port

		h4=build_h4_from_h6(p6.next.header)
		
		p4=Skel()
		p4.header=Skel()
		p4.header.flags=0
		p4.header.type='IPv4'
		p4.next=Skel()
		p4.next.header=h4
		p4.next.header.source=nat_ip
		p4.next.next=p6.next.next
		if proto == 'TCP':
			p4.next.next.header.source=nat_port
			p4.next.next.header.checksum=0

		tmp=layer2_tun.build(p4)
		tmp=fix_ipv4_checksum(tmp)
		if proto == 'TCP':
			tmp=fix_tcpv4_checksum(tmp)
		os.write(f4,tmp)
		tmp4=layer2_tun.parse(tmp)
		#print tmp4 
		print_packet(tmp4,"\t NAT ")
		#print bib.bibs

