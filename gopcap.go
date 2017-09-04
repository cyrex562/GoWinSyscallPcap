package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"reflect"
	"strings"
	"syscall"
	"unsafe"
)

func abort(funcName string, err error) {
	panic(fmt.Sprintf("%s failed: %v", funcName, err))
}

var (
	wpcap, _             = syscall.LoadLibrary("wpcap.dll")
	pcapFindAllDevsEx, _ = syscall.GetProcAddress(wpcap, "pcap_findalldevs_ex")
	pcapFreeAllDevs, _   = syscall.GetProcAddress(wpcap, "pcap_freealldevs")
	pcapOpenLive, _      = syscall.GetProcAddress(wpcap, "pcap_open_live")
	pcapNextEx, _        = syscall.GetProcAddress(wpcap, "pcap_next_ex")
)

var ifNameFlag string

//var ifAddrFlag string

func init() {
	flag.StringVar(&ifNameFlag, "ifname", "", "interface name to search for and capture traffic from")
	//flag.StringVar(&ifAddrFlag, "ifaddr", "", "ip address of interface to capture from")
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
type PCAPPktHdr struct {
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

type EthernetHeader struct {
	DstMac    [6]byte
	SrcMac    [6]byte
	EtherType uint16
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
		tail = i
		if *currByte == 0 {
			break
		}
		middle = append(middle, *currByte)

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
	fmt.Printf("pointer address: %#x\n", in)
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
		log.Fatal(callErr)
	}
}

/*

pcap_t* pcap_open_live(	const char * 	device,
						int 	snaplen,
						int 	promisc,
						int 	to_ms,
						char * 	ebuf)
*/
func PCAPOpenLive(device string, snaplen int, promisc int, timeout int) uintptr {
	fmt.Println("opening PCAP device for capturing")

	errBuf := [256]byte{}

	var devBytes *byte
	var err error
	devBytes, err = syscall.BytePtrFromString(device)
	if err != nil {
		log.Fatal(err)
	}

	ret, _, callErr := syscall.Syscall6(
		pcapOpenLive,
		5,
		uintptr(unsafe.Pointer(devBytes)),
		uintptr(snaplen),
		uintptr(promisc),
		uintptr(timeout),
		uintptr(unsafe.Pointer(&errBuf)),
		0)
	if callErr != 0 {
		abort("pcap_open_live", callErr)
	}
	// ret: -1 = failure
	if isValidPtr(ret) == false {
		// TODO: print contents of err buf
		abort("pcap_open_live", errors.New(string(errBuf[:])))
	}

	return ret
}

/*
int pcap_findalldevs(char*                source,
					 struct pcap_rmtauth* auth,
                     pcap_if_t**          alldevsp,
                     char*                errbuf)
*/
func PcapFindAllDevs() (interfaces []InterfaceInfo) {
	errBufBytes := [256]byte{}
	var allDevsPtr uint
	var source string = "rpcap://"
	var sourceBytes *byte
	var err error

	sourceBytes, err = syscall.BytePtrFromString(source)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("getting list of interfaces using syscall")
	ret, _, callErr := syscall.Syscall6(
		pcapFindAllDevsEx,
		4,
		uintptr(unsafe.Pointer(sourceBytes)),
		0,
		uintptr(unsafe.Pointer(&allDevsPtr)),
		uintptr(unsafe.Pointer(&errBufBytes)),
		0,
		0)
	if callErr != 0 {
		log.Fatal(callErr)
	}
	// ret: -1 = failure
	if ret != 0 {
		log.Fatal(errors.New(string(errBufBytes[:])))
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

/*
int pcap_next_ex	(	pcap_t * 	p,
struct pcap_pkthdr ** 	pkt_header,
const u_char ** 	pkt_data
)
*/
func PCAPNextEx(pcapHandle uintptr) (pktHdr *PCAPPktHdr, pktData []byte, retcode int) {
	var pktHdrPtr uint
	var pktDataPtr uint

	ret, _, callErr := syscall.Syscall(
		pcapNextEx,
		3,
		uintptr(pcapHandle),
		uintptr(unsafe.Pointer(&pktHdrPtr)),
		uintptr(unsafe.Pointer(&pktDataPtr)))
	if callErr != 0 {
		log.Fatal(callErr)
	}
	// ret = 1: ok
	// ret = 0: timeout
	// ret = -1: error
	// ret = -2: EOF

	// (*PCAPIf)(unsafe.Pointer(uintptr(allDevsPtr)))

	pktHdr = (*PCAPPktHdr)(unsafe.Pointer(uintptr(pktHdrPtr)))

	var pktDataBytes []byte
	sliceHeader := (*reflect.SliceHeader)(unsafe.Pointer(&pktDataBytes))
	sliceHeader.Cap = (int)(pktHdr.Len)
	sliceHeader.Len = (int)(pktHdr.Len)
	sliceHeader.Data = uintptr(unsafe.Pointer(uintptr(pktHdrPtr)))

	retcode = (int)(ret)
	return pktHdr, pktDataBytes, retcode
}

func main() {
	defer syscall.FreeLibrary(wpcap)

	//var getUserInput = false
	//if ifNameFlag == "" && ifAddrFlag == "" {
	//if ifNameFlag == "" {
	//	fmt.Println("no interface name provided!")
	//	return
	//}

	var ifNameFlag = "61BDEB"

	interfaces := PcapFindAllDevs()
	fmt.Println("interfaces: %v", interfaces)

	var outIdx int = -1
	for i := 0; i < len(interfaces); i++ {
		iface := interfaces[i]
		if strings.Contains(iface.Name, ifNameFlag) {
			outIdx = i
			break
		} else if strings.Contains(iface.Description, ifNameFlag) {
			outIdx = i
			break
		}
	}

	if outIdx == -1 {
		log.Fatal(errors.New("interface not found"))
	}

	// TODO: pick a specific adapter to user
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
	pcapHandle := PCAPOpenLive(interfaces[outIdx].Name, 0xffff, 1, 1000)

	// TODO: capture data
	//pcap_loop(adhandle, 0, packet_handler, NULL);

	var retCode int
	var pktData []byte
	var pktHdr *PCAPPktHdr
	//var err error

	for {
		pktHdr, pktData, retCode = PCAPNextEx(pcapHandle)
		if retCode == 1 {
			fmt.Printf("pktHdr: %#v\n", pktHdr)
			fmt.Printf("pktData: % 02x\n", pktData)
			srcMac := [6]byte{pktData[0], pktData[1], pktData[2], pktData[3], pktData[4], pktData[5]}
			fmt.Printf("srcMac: %02x:%02x:%02x:%02x:%02x:%02x, ", srcMac[0], srcMac[1], srcMac[2], srcMac[3],
				srcMac[4], srcMac[5])
			dstMac := [6]byte{pktData[6], pktData[7], pktData[8], pktData[9], pktData[10], pktData[11]}
			fmt.Printf("dstMac: %02x:%02x:%02x:%02x:%02x:%02x, ", dstMac[0], dstMac[1], dstMac[2], dstMac[3],
				dstMac[4], dstMac[5])
			//etherTypeBytes := [2]byte{pktData[12], pktData[13]}
			var etherType uint16 = (uint16)(pktData[13] << 8 | pktData[12])
			//err = binary.Read(bytes.NewReader(etherTypeBytes[:2]), binary.BigEndian, etherType)
			//if err != nil {
			//	log.Fatal(err)
			//}
			fmt.Printf("etherType: %0x\n", etherType)

			if etherType <= 1500 {
				fmt.Println("ethernet frame is a Novell raw 802.3, IEEE 802.2 LLC, or IEEE 802.2 SNAP frame")
				fmt.Printf("payload start bytes: %02x", pktData[14:16])
				if pktData[14] == 0xff && pktData[15] == 0xff {
					fmt.Println("ETH frame type = Novell raw 802.3")
				} else if pktData[14] == 0xAA && pktData[15] == 0xAA {
					fmt.Println("ETH frame type = IEEE 802.2 SNAP frame")
				} else {
					fmt.Println("ETH frame type = IEEE 802.2 LLC Frame")
					fmt.Printf("DSAP: %02x, SSAP: %02x\n", pktData[14], pktData[15])
				}
			} else if etherType >= 1536 {
				fmt.Println("ethernet frame type is Ethernet II")
			} else {
				log.Fatal("unknown ethernet type, etherType is %d", etherType)
			}

		} else if retCode == 0 {
			fmt.Println("timeout occurred")
		} else if retCode == -1 {
			log.Fatal(errors.New("error occurred calling PCAPNextEx"))
		} else if retCode == -2 {
			fmt.Println("EOF")
			break
		} else {
			fmt.Printf("unknown error code: %d\n", retCode)
			log.Fatal(errors.New(fmt.Sprint("unknown error code: %d", retCode)))
			return
		}
	}
}
