//-----------------------------------------------------------------------------
// {C} Copyright 2023 AMD Inc. All rights reserved
//-----------------------------------------------------------------------------

package utils

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"

	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	uuid "github.com/satori/go.uuid"

	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/pds"
)

const (
	PipelineJson = "/nic/conf/pipeline.json"
)

const (
	IP_AF_IPV4 = 0
	IP_AF_IPV6 = 1
)

const (
	ENCAP_TYPE_NONE  = 0
	ENCAP_TYPE_VXLAN = 1
	ENCAP_TYPE_IPSEC = 2
)

func CmdSendRecv(udsPath string, cmd []byte, fds ...int) ([]byte, error) {
	c, err := net.Dial("unix", udsPath)
	if err != nil {
		fmt.Printf("Could not connect to unix domain socket\n")
		return nil, err
	}
	defer c.Close()

	udsConn := c.(*net.UnixConn)
	udsFile, err := udsConn.File()
	if err != nil {
		return nil, err
	}
	socket := int(udsFile.Fd())
	defer udsFile.Close()

	var rights []byte
	rights = nil
	if fds[0] >= 0 {
		rights = syscall.UnixRights(fds...)
	}
	err = syscall.Sendmsg(socket, cmd, rights, nil, 0)
	if err != nil {
		fmt.Printf("Sendmsg failed with error %v\n", err)
		return nil, err
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)
	go func(f *os.File) {
		<-signalChannel // Wait for interrupt signal
		f.Close()
		os.Exit(0)
	}(udsFile)

	// rcvMsg will hold the entire response
	// resp is the temporary buffer used
	var rcvMsg bytes.Buffer
	resp := make([]byte, 20480)
	for {
		n, _, _, _, err := syscall.Recvmsg(socket, resp, nil, 0)
		if err != nil {
			// read failed
			fmt.Printf("Recvmsg failed with error %v\n", err)
			return nil, err
		} else if n == 0 {
			// entire response has been read
			return rcvMsg.Bytes(), nil
		}

		// append what is read to rcvMsg
		rcvMsg.Write(resp[:n])
	}
}

func IsUUIDValid(u string) error {
	_, err := uuid.FromString(u)
	if err != nil {
		return fmt.Errorf("Incorrect id %v", u)
	}
	return nil
}

// IdToStr converts uuid to readable string
func IdToStr(id []byte) string {
	str := "-"
	if id != nil {
		if !bytes.Equal(id, make([]byte, len(id))) {
			str = uuid.FromBytesOrNil(id).String()
		}
	}
	return str
}

// GetOperdMetricsKeyFromMac generates key of type []byte from mac address
func GetOperdMetricsKeyFromMac(objval int, mac, delimiter string) []byte {
	output := make([]byte, 10)
	output[0] = byte(objval)
	output[8] = 0x42
	output[9] = 0x42
	macBytes, err := hex.DecodeString(strings.ReplaceAll(mac, delimiter, ""))
	if err != nil {
		fmt.Errorf("Operd metrics key generation failed, err %v", err)
		return output
	}
	output = append(output, macBytes...)
	return output
}

func MaxInSlice(values []int) int {
	if values == nil {
		return 0
	}
	max := values[0]
	for _, value := range values {
		if max < value {
			max = value
		}
	}
	return max
}

// InternalCmdExec runs command and captures output/error
func InternalCmdExec(cmd string) error {
	execCmd := exec.Command("sh", "-c", cmd)
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	err := execCmd.Run()
	if err != nil {
		return fmt.Errorf("Failed to run internal cmd %s, err %s\n", cmd, err)
	}
	return nil
}

// MactoStr converts a uint64 to a MAC string
func MactoStr(mac uint64) string {
	var bytes [6]byte

	if mac == 0 {
		return "-"
	} else {
		bytes[0] = byte(mac & 0xFF)
		bytes[1] = byte((mac >> 8) & 0xFF)
		bytes[2] = byte((mac >> 16) & 0xFF)
		bytes[3] = byte((mac >> 24) & 0xFF)
		bytes[4] = byte((mac >> 32) & 0xFF)
		bytes[5] = byte((mac >> 40) & 0xFF)
		macStr := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			bytes[5], bytes[4], bytes[3],
			bytes[2], bytes[1], bytes[0])
		return macStr
	}
}

// MACAddrStrToUint64 converts string MAC address to uint64
func MACAddrStrToUint64(mac string) uint64 {
	var addr [6]uint64
	var maddr uint64

	if strings.Contains(mac, ":") {
		fmt.Sscanf(mac, "%x:%x:%x:%x:%x:%x", &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5])
		maddr = ((addr[0] << 40) | (addr[1] << 32) | (addr[2] << 24) | (addr[3] << 16) | (addr[4] << 8) | (addr[5]))
	} else if strings.Contains(mac, ".") {
		fmt.Sscanf(mac, "%x.%x.%x", &addr[0], &addr[1], &addr[2])
		maddr = ((addr[0] << 32) | (addr[1] << 16) | (addr[2]))
	} else if strings.Contains(mac, "-") {
		fmt.Sscanf(mac, "%x-%x-%x-%x-%x-%x", &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5])
		maddr = ((addr[0] << 40) | (addr[1] << 32) | (addr[2] << 24) | (addr[3] << 16) | (addr[4] << 8) | (addr[5]))
	}
	return maddr
}

// IPPrefixToStr converts prefix to string
func IPPrefixToStr(pfx *pds.IPPrefix) string {
	pfxStr := IPAddrToStr(pfx.GetAddr())
	if pfxStr == "-" {
		return "-/-"
	}
	return fmt.Sprintf("%s/%d", pfxStr, pfx.GetLen())
}

// IPAddrToStr converts PDS proto IP address to string
func IPAddrToStr(ipAddr *pds.IPAddress) string {
	if ipAddr == nil {
		return "-"
	}
	if ipAddr.GetAf() == pds.IPAF_IP_AF_INET {
		v4Addr := ipAddr.GetV4Addr()
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, v4Addr)
		return ip.String()
	} else if ipAddr.GetAf() == pds.IPAF_IP_AF_INET6 {
		v6Addr := ipAddr.GetV6Addr()
		ip := make(net.IP, 16)
		copy(ip, v6Addr)
		return ip.String()
	} else {
		return "-"
	}

}

type PipelineInfo struct {
	P4ProgramName string `json:"p4_program"`
}

// GetP4ProgramName parses pipeline.json file and returns p4_program name.
// if the pipeline.json file is not present or has parsing errors or doesn't
// have p4_program keyword in it, this API returns an empty string, meaning
// that the p4_program checks will not have any impact in case of any error
// w.r.t. pipeline json fle
func GetP4ProgramName() string {
	jFile, err := os.Open(PipelineJson)
	if err != nil {
		fmt.Printf("Failed to open %v, err %v\n", PipelineJson, err)
		return ""
	}
	defer jFile.Close()

	var pipelineInfo PipelineInfo
	err = json.NewDecoder(jFile).Decode(&pipelineInfo)
	if err != nil {
		fmt.Printf("Failed to parse %v, err %v\n", PipelineJson, err)
		return ""
	}
	return pipelineInfo.P4ProgramName
}

// MacAddrByteToStr converts byte array MAC to string
func MacAddrByteToStr(orig []byte) string {
	if len(orig) != 6 {
		return ""
	}
	zeromac := make([]byte, 6)
	if bytes.Equal(orig, zeromac) == true {
		return "-"
	}

	var addr string
	f := hex.EncodeToString(orig[:1])
	e := hex.EncodeToString(orig[1:2])
	d := hex.EncodeToString(orig[2:3])
	c := hex.EncodeToString(orig[3:4])
	b := hex.EncodeToString(orig[4:5])
	a := hex.EncodeToString(orig[5:6])
	addr = a + ":" + b + ":" + c + ":" + d + ":" + e + ":" + f
	return addr
}

// MacAddrByteToStr converts uint64 MAC to string
func MacAddrIntToStr(orig uint64) string {
	var addr string

	if orig == 0 {
		return "-"
	}

	macHexStr := fmt.Sprintf("%012x", orig)
	a := macHexStr[0:2]
	b := macHexStr[2:4]
	c := macHexStr[4:6]
	d := macHexStr[6:8]
	e := macHexStr[8:10]
	f := macHexStr[10:12]
	addr = a + ":" + b + ":" + c + ":" + d + ":" + e + ":" + f
	return addr
}

// Reverse the bytes in uint64
func ReverseUint64(val uint64) uint64 {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, val)
	return binary.BigEndian.Uint64(b)
}

// Reverse the Byte array
func ReverseArray(addr []byte) []byte {
	for i, j := 0, len(addr)-1; i < j; i, j = i+1, j-1 {
		addr[i], addr[j] = addr[j], addr[i]
	}
	return addr
}

// IPv6AddrByteToStr converts byte array IPv6 to string
func IPv6AddrByteToStr(addr []byte) string {
	ip := make(net.IP, 16)
	ReverseArray(addr)
	copy(ip, addr)
	return ip.String()
}

// IPv4AddrByteToStr converts byte array IPv4 to string
func IPv4AddrByteToStr(addr []byte) string {
	ip := net.IPv4(addr[3], addr[2], addr[1], addr[0])
	return ip.String()
}

func IPAddrByteToStr(addr []byte, ipType string) string {
	if ipType == "IPv4" {
		return IPv4AddrByteToStr(addr)
	} else if ipType == "IPv6" {
		return IPv6AddrByteToStr(addr)
	} else {
		var addrStr string = ""
		for i := len(addr) - 1; i >= 0; i = i - 1 {
			addrStr += hex.EncodeToString(addr[i : i+1])
		}
		return addrStr
	}
}

// IPPrototoStr converts ip proto to string
func IPProtoToStr(proto uint32) string {
	switch proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprint(proto)
	}
}
