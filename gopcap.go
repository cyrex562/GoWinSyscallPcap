package main

import (
	"errors"
	"flag"
	"fmt"
	"syscall"
	unsafe "unsafe"
)

func abort(funcName string, err error) {
	panic(fmt.Sprintf("%s failed: %v", funcName, err))
}

var (
	wpcap, _           = syscall.LoadLibrary("wpcap.dll")
	pcapFindAllDevs, _ = syscall.GetProcAddress(wpcap, "pcap_findalldevs")
	pcapFreeAllDevs, _ = syscall.GetProcAddress(wpcap, "pcap_freealldevs")
)

var ifNameFlag string
var ifAddrFlag string

func init() {
	flag.StringVar(&ifNameFlag, "ifname", "", "interface name to search for and capture traffic from")
	flag.StringVar(&ifAddrFlag, "ifaddr", "", "ip address of interface to capture from")
}

const (
	AF_UNSPEC    = 0
	AF_INET      = 2
	AF_IPX       = 6
	AF_APPLETALK = 16
	AF_NETBIOS   = 17
	AF_INET6     = 23
	AF_IRDA      = 26
	AF_BTH       = 32
)

/* struct timeval

time_t tv_sec seconds
subseconds_t tv_usec microseconds

*/
type TimeVal struct {
	TVSec  int32
	TVUSec int32
}

/*
00126 struct pcap_pkthdr {
00127     struct timeval ts;
00128     bpf_u_int32 caplen;
00129     bpf_u_int32 len;
00130 };
*/
type PcapPktHdr struct {
	TS     TimeVal
	CapLen uint32
	Len    uint32
}

/*

struct in_addr {
    unsigned long s_addr;  // load with inet_aton()
};

*/
type InAddr struct {
	SAddr uint32
}

/*
http://www.retran.com/beej/sockaddr_inman.html
struct sockaddr_in {
    short            sin_family;   // e.g. AF_INET
    unsigned short   sin_port;     // e.g. htons(3490)
    struct in_addr   sin_addr;     // see struct in_addr, below
    char             sin_zero[8];  // zero this if you want to
};
*/
type SockAddr struct {
	SAFamily uint16
	SAData   [14]byte
}

/*
00161 struct pcap_addr {
00162     struct pcap_addr *next;
00163     struct sockaddr *addr;
00164     struct sockaddr *netmask;
00165     struct sockaddr *broadaddr;
00166     struct sockaddr *dstaddr;
00167 };
*/
type PCAPAddr struct {
	Next          *PCAPAddr
	Addr          *SockAddr
	Netmask       *SockAddr
	BroadcastAddr *SockAddr
	DataAddr      *SockAddr
}

/*
 struct pcap_if {
 	struct pcap_if *next;
    char *name;
    char *description;
    struct pcap_addr *addresses;
    u_int flags;
 };
*/
type PCAPIf struct {
	Next        *PCAPIf
	Name        *byte
	Description *byte
	Addresses   *PCAPAddr
	Flags       uint
}

type InterfaceAddress struct {
	Address   SockAddr
	Netmask   SockAddr
	BcastAddr SockAddr
	DataAddr  SockAddr
}

type InterfaceInfo struct {
	Name        string
	Description string
	Addresses   []InterfaceAddress
}

/* IPv4 header */
type IPHeader struct {
	VerIHL     uint8  // ver: 4b, ihl: 4b
	TOS        uint8  // type of svc, dscp: 6b, ecn: 2b
	TotLen     uint16 // total length
	ID         uint16 // IP ID
	FlagsFO    uint16 // flags: 3b, frag off: 13 bits
	TTL        uint8  // Time to Live
	Proto      uint8  // Protocol
	HeaderCsum uint16 // Header Checksum
	SrcAddr    uint32 // Source IP Addr
	DstAddr    uint32 // Destination IP Addr
}

/*
	UDP header
	src_port: 2B
	dst_port: 2B
	length: 2B
	checksum: 2B
*/
type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	DgramLen uint16
	Csum     uint16
}

/* prototype of the packet handler */
//void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

func ntohs(in uint16) uint16 {
	var origHiByte = in & 0xff00
	var origLoByte = in & 0x00ff
	var newUshort = origLoByte<<16 | origHiByte
	return newUshort
}

func uint32ToIPv4Bytes(in uint32) [4]uint8 {
	var byte1 uint8 = (uint8)(in & 0xff000000)
	var byte2 uint8 = (uint8)(in & 0x00ff0000)
	var byte3 uint8 = (uint8)(in & 0x0000ff00)
	var byte4 uint8 = (uint8)(in & 0x000000ff)
	return [4]uint8{byte1, byte2, byte3, byte4}
}

func getStringTerm(in []byte) (idx int, ok bool) {
	idx = -1
	for i := 0; i < 4096; i++ {
		if in[i] == 0x0 {
			idx = i
			break
		}
	}
	ok = false
	if idx != -1 {
		ok = true
	}
	return idx, ok
}

func rawToString(in *byte) (out string, ok bool) {
	var middle []byte
	var tail int = -1
	for i := 0; i < 4096; i++ {
		currByte := (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(in)) + uintptr(i)))
		middle = append(middle, *currByte)
		tail = i
		if *currByte == 0 {
			break
		}
	}
	if tail == 4095 {
		ok = false
	} else {
		ok = true
		out = string(middle)
	}

	return out, ok
}

func isValidPtr(in uintptr) (ok bool) {
	//fmt.Printf("pointer address: %#x\n", in)
	ok = true
	if in == 0 {
		ok = false
	} else if in == 0xbaadf00d00000000 {
		ok = false
	} else if in == 0xfeeefeeefeeefeee {
		ok = false
	}
	return ok
}

/*
	void pcap_freealldevs( pcap_if_t * alldevsp)
*/
func PCAPFreeAllDevs(pcapIf *PCAPIf) {
	fmt.Println("freeing device list")

	_, _, callErr := syscall.Syscall(
		pcapFreeAllDevs,
		1,
		uintptr(unsafe.Pointer(pcapIf)),
		0,
		0)

	if callErr != 0 {
		abort("Call PCAPFreeAllDevs", callErr)
	}
}

/*
int pcap_findalldevs(pcap_if_t **alldevsp,
                     char      *errbuf)
*/
func PcapFindAllDevs() (interfaces []InterfaceInfo) {
	errBufBytes := [256]byte{}
	var allDevsPtr uint

	fmt.Println("getting list of interfaces using syscall")
	ret, _, callErr := syscall.Syscall(
		pcapFindAllDevs,
		2,
		uintptr(unsafe.Pointer(&allDevsPtr)),
		uintptr(unsafe.Pointer(&errBufBytes)),
		0)
	if callErr != 0 {
		abort("Call findalldevs", callErr)
	}
	// ret: -1 = failure
	if ret != 0 {
		abort("Call findalldevs failed", errors.New(string(errBufBytes[:])))
	}
	// ret: 0 = success
	var iface *PCAPIf
	iface = (*PCAPIf)(unsafe.Pointer(uintptr(allDevsPtr)))
	for {
		var outInterface InterfaceInfo
		fmt.Printf("iface: %#x\n", uintptr(allDevsPtr))
		ifaceNextPtr := uintptr(unsafe.Pointer(iface.Next))
		fmt.Printf("\tnext: %#x\n", ifaceNextPtr)

		namePtr := uintptr(unsafe.Pointer(iface.Name))
		if isValidPtr(namePtr) {
			// TODO: handle errors
			nameStr, _ := rawToString(iface.Name)
			fmt.Printf("\tname: (%#x), %s\n", namePtr, nameStr)
			outInterface.Name = nameStr
		}

		descPtr := uintptr(unsafe.Pointer(iface.Description))
		if isValidPtr(descPtr) {
			// TODO: handle errors
			descStr, _ := rawToString(iface.Description)
			fmt.Printf("\tdesc: (%#x) %s\n", descPtr, descStr)
			outInterface.Description = descStr
		}

		addrPtr := uintptr(unsafe.Pointer(iface.Addresses))
		if isValidPtr(addrPtr) {
			fmt.Printf("\taddresses: %#x\n", addrPtr)
			fmt.Println("traversing address list")
			var addr *PCAPAddr = iface.Addresses
			for {
				var outAddress InterfaceAddress
				// Next
				fmt.Printf("\t\taddress: %#x\n", addr)
				addrNextPtr := uintptr(unsafe.Pointer(addr.Next))
				fmt.Printf("\t\t\taddr->next: %#x\n", addrNextPtr)
				// Addr
				addrPtr := uintptr(unsafe.Pointer(addr.Addr))
				fmt.Printf("\t\t\taddr->addr: %#x", addrPtr)
				if isValidPtr(addrPtr) {
					fmt.Printf("\t\t\taddr->addr: %v", addr.Addr)
					outAddress.Address = *addr.Addr
				}
				// NetMask
				maskPtr := uintptr(unsafe.Pointer(addr.Netmask))
				fmt.Printf("\t\t\taddr->netmask: %#x", maskPtr)
				if isValidPtr(maskPtr) {
					fmt.Printf("\t\t\taddr->mask: %v", addr.Netmask)
					outAddress.Netmask = *addr.Netmask
				}

				// BroadcastAddr
				bcastPtr := uintptr(unsafe.Pointer(addr.BroadcastAddr))
				fmt.Printf("\t\t\taddr->bcast: %#x", bcastPtr)
				if isValidPtr(bcastPtr) {
					fmt.Printf("\t\t\taddr->bcast: %v", addr.BroadcastAddr)
					outAddress.BcastAddr = *addr.BroadcastAddr
				}

				// DataAddr
				dataPtr := uintptr(unsafe.Pointer(addr.DataAddr))
				fmt.Printf("\t\t\taddr->data: %#x", dataPtr)
				if isValidPtr(dataPtr) {
					fmt.Printf("\t\t\taddr->data: %v", addr.DataAddr)
					outAddress.DataAddr = *addr.DataAddr
				}

				outInterface.Addresses = append(outInterface.Addresses, outAddress)

				if isValidPtr(addrNextPtr) {
					addr = addr.Next
				} else {
					fmt.Println("end of address list reached")
					break
				}
			}
		}

		interfaces = append(interfaces, outInterface)

		if uintptr(unsafe.Pointer(iface.Next)) == 0 {
			fmt.Println("end of pcap interface list reached")
			break
		}
		iface = iface.Next

	}

	if allDevsPtr != 0 {
		PCAPFreeAllDevs((*PCAPIf)(unsafe.Pointer(uintptr(allDevsPtr))))
	}

	return interfaces
}

/* Callback function invoked by libpcap for every incoming packet */
/*
void packet_handler(u_char *param,
                    const struct pcap_pkthdr *header,
                    const u_char *pkt_data) {
	struct tm *ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport,dport;
	time_t local_tv_sec;

	(VOID)(param);

	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	ih = (ip_header *) (pkt_data + 14); //length of ethernet header
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *) ((u_char*)ih + ip_len);

	sport = ntohs( uh->sport );
	dport = ntohs( uh->dport );

    printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
    ih->saddr.byte1,
    ih->saddr.byte2,
    ih->saddr.byte3,
    ih->saddr.byte4,
    sport,
    ih->daddr.byte1,
    ih->daddr.byte2,
    ih->daddr.byte3,
    ih->daddr.byte4,
    dport);
}

*/
func packetHandler(
	param *byte, // u_char *param
	header *PcapPktHdr, // const struct pcap_pkthdr *header
	pktData *byte) { // const u_char *pkt_data
	//var tm TimeVal
	//var localTVSec int32
	//var pcapPktHdr = (*PcapPktHdr)(unsafe.Pointer(header))
	//var ipHdr IPHeader
	//var udpHeader UDPHeader

	//localTVSec = pcapPktHdr.TS.TVSec
	pktDataPtr := uintptr(unsafe.Pointer(pktData))
	ipHdrPtr := pktDataPtr + uintptr(14)
	var ipHdr = (*IPHeader)(unsafe.Pointer(uintptr(ipHdrPtr)))
	var ipLen = (ipHdr.VerIHL & 0xf) * 4

	udpHeaderPtr := ipHdrPtr + uintptr(ipLen)
	var udpHeader = (*UDPHeader)(unsafe.Pointer(udpHeaderPtr))
	var sport = ntohs(udpHeader.SrcPort)
	var dport = ntohs(udpHeader.DstPort)
	fmt.Printf("ip len: %d, sport: %d, dport: %d", ipLen, sport, dport)
}

func parseCommandLine() {

}

func main() {
	defer syscall.FreeLibrary(wpcap)

	var getUserInput = false
	if ifNameFlag == "" && ifAddrFlag == "" {
		fmt.Println("no interface or ip address chosen")
		getUserInput = true
	}

	interfaces := PcapFindAllDevs()
	fmt.Println("interfaces: %v", interfaces)

	for i := 0; i < len(interfaces); i++ {
		iface := interfaces[i]

	}

	// TODO: pick a specific adapter to user
	// TODO: should we use a command line interpreter?
	// TODO: check interface properties
	///* Retrieve the mask of the first address of the interface */
	//netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	//else
	///* If the interface is without addresses we suppose to be in a C class network */
	//netmask=0xffffff;
	// TODO: support a pcap filter
	//if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
	//{
	//fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
	////set the filter
	//if (pcap_setfilter(adhandle, &fcode)<0)
	//{
	// TODO: open the interface for capture
	//if ((adhandle= pcap_open_live(d->name,	// name of the device
	//65536,			// portion of the packet to capture.
	//// 65536 grants that the whole packet will be captured on all the MACs.
	//1,				// promiscuous mode (nonzero means promiscuous)
	//1000,			// read timeout
	//errbuf			// error buffer
	//)) == NULL)
	// TODO: capture data
	//pcap_loop(adhandle, 0, packet_handler, NULL);
}
