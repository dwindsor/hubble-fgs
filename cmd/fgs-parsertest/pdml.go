package main

import (
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
)

//
// To capture a PDML:
// tshark -T pdml -J "tcp dns" -P port 53
// tshark -T pdml -J "tcp http" -P port 80
//
// "tcp" needed to read the src and dst ports, which
// is needed to figure out if it's an EGRESS or INGRESS packet.

type Field struct {
	Name     string  `xml:"name,attr"`
	Show     string  `xml:"show,attr"`
	Showname string  `xml:"showname,attr"`
	Value    string  `xml:"value,attr"`
	Size     int     `xml:"size,attr"`
	Hide     string  `xml:"hide,attr"`
	Fields   []Field `xml:"field"`
}

type Proto struct {
	Name     string  `xml:"name,attr"`
	Showname string  `xml:"showname,attr"`
	Fields   []Field `xml:"field"`
}

type Packet struct {
	Protos []Proto `xml:"proto"`
}

type PDML struct {
	Packets []Packet `xml:"packet"`
	Time    string   `xml:"attr"`
}

var (
	// List of protocols known to be text
	textProtos = []string{
		"http",
		"smtp",
		"data-text-lines",
	}
)

func isTextProto(proto string) bool {
	for _, p := range textProtos {
		if p == proto {
			return true
		}
	}
	return false
}

const MaxHexLineLen = 48

func prettyHex(w io.Writer, maxSingleHexLineLen int, showname, value string) {
	multiline := len(value) > MaxHexLineLen

	if multiline && showname != "" {
		fmt.Fprintf(w, "\n  ## %s\n", showname)
	}
	fmt.Fprint(w, "  $")
	for i := 0; i < len(value); i += 2 {
		if i != 0 && (i%MaxHexLineLen) == 0 {
			fmt.Fprint(w, "\n  $")
		}
		fmt.Fprintf(w, " %s", value[i:i+2])
	}

	if showname != "" && !multiline {
		indent := ""
		thisLineLen := len(value) + len(value)/2 - 1
		if maxSingleHexLineLen != 0 && thisLineLen < maxSingleHexLineLen {
			indent = strings.Repeat(" ", maxSingleHexLineLen-thisLineLen)
		}
		fmt.Fprintf(w, "%s # %s", indent, showname)
	}
	fmt.Fprint(w, "\n")
}

func prettyFieldValue(w io.Writer, maxSingleHexLineLen int, proto string, showname string, field Field) {
	if isTextProto(proto) {
		v, _ := hex.DecodeString(field.Value)
		fmt.Fprintf(w, "  %q\n", v)
	} else {
		prettyHex(w, maxSingleHexLineLen, showname, field.Value)
	}
}

func dumpField(w io.Writer, maxSingleHexLineLen int, proto string, field Field) {
	if field.Hide == "yes" || field.Size == 0 {
		return
	}

	// Truncate showname if it's very long.
	if len(field.Showname) > 64 {
		field.Showname = field.Showname[:64] + "..."
	} else if len(field.Showname) == 0 {
		field.Showname = field.Show
	}

	if field.Value != "" {
		if len(field.Fields) > 1 {
			fmt.Fprintf(w, "  ## %s\n", field.Showname)
			for _, f := range field.Fields {
				if strings.HasPrefix(field.Name, "_ws") {
					continue
				}
				if f.Showname != "" {
					fmt.Fprintf(w, "  # %s\n", f.Showname)
				} else {
					fmt.Fprintf(w, "  # %s\n", f.Show)
				}
			}
			prettyFieldValue(w, maxSingleHexLineLen, proto, "", field)
		} else {
			prettyFieldValue(w, maxSingleHexLineLen, proto, field.Showname, field)
		}
	} else {
		fmt.Fprintf(w, "  ### %s\n", field.Showname)

		lineLenSearchPos := -1
		maxSingleHexLineLen := 0
		for i, f := range field.Fields {
			// Try to indent adjacent single hex line comments consistently
			// by looking ahead for the longest line.
			if i > lineLenSearchPos {
				for j, f := range field.Fields[i:] {
					lineLenSearchPos = i + j
					if len(f.Value) == 0 || len(f.Value) >= MaxHexLineLen {
						// A multiline hex value, or container, stop here.
						break
					}
					lineLen := len(f.Value) + len(f.Value)/2 - 1 /* the spaces */
					if lineLen > maxSingleHexLineLen {
						maxSingleHexLineLen = lineLen
					}
				}
			}
			if len(f.Value) >= MaxHexLineLen {
				maxSingleHexLineLen = 0
			}
			dumpField(w, maxSingleHexLineLen, proto, f)
		}
	}
}

// PDMLToTestCase converts a Wireshark "Packet Details Markup Language"
// into a FGS parser test-case.
func PDMLToTestCase(pdmlFile string, w io.Writer) error {
	data, err := ioutil.ReadFile(pdmlFile)
	if err != nil {
		return err
	}

	pdml := PDML{}
	if err = xml.Unmarshal(data, &pdml); err != nil {
		return err
	}

	dstPort := uint16(0)

	for pktIndex, pkt := range pdml.Packets {

		for i, proto := range pkt.Protos {
			// Seek until we find UDP or TCP proto
			if proto.Name != "udp" && proto.Name != "tcp" {
				continue
			}

			// Extract the dstport
			portString := ""
			for _, field := range proto.Fields {
				if field.Name == "udp.dstport" || field.Name == "tcp.dstport" {
					portString = field.Show
					break
				}
			}
			var pktDstPort uint16
			if portString == "" {
				fmt.Fprintf(w, "# WARNING: no dstport in tcp proto, cannot deduce EGRESS/INGRESS. Did you include 'tcp' in '-J' flag?\n")
			} else {
				if n, err := strconv.ParseUint(portString, 10, 16); err != nil {
					panic(err)
				} else {
					pktDstPort = uint16(n)
				}
				if pktIndex == 0 {
					dstPort = pktDstPort
				}
			}

			// Now process the upper layer protocols.
			upperProtos := pkt.Protos[i+1:]
			if len(upperProtos) > 0 {
				if pktDstPort == dstPort {
					fmt.Fprint(w, "EGRESS\n")
				} else {
					fmt.Fprint(w, "INGRESS\n")
				}
				for _, proto := range upperProtos {
					for _, field := range proto.Fields {
						dumpField(w, 0, proto.Name, field)
					}
				}
				fmt.Fprint(w, "END\n")
			}
			break
		}
	}
	return nil

}
