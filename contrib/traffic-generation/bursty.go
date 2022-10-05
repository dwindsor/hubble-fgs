package main

import (
	"bufio"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/tetragon/pkg/timer"
)

const (
	baseline = 0
)

var (
	rates        [3]int
	buf          []byte
	sampPerSec   int
	socket       net.Conn
	sendTimer    = timer.NewPeriodicTimer("Send timer", sendData, false)
	rate         = 0
	bytesPerSamp int
	sampOver     int
	sampIndex    int
)

func sendStep() {
	sendTimer.Stop()
	bytesPerSamp = rates[rate] / sampPerSec
	sampOver = rates[rate] - (bytesPerSamp * sampPerSec)
	rate++
	if rate > 2 {
		rate = 0
	}
	sampIndex = 0
	sendTimer.Start(time.Second / time.Duration(sampPerSec))
}

func sendData() {
	bytesToSend := bytesPerSamp
	if sampIndex < sampOver {
		bytesToSend++
	}
	socket.Write(buf[0:bytesToSend])
	sampIndex++
	if sampIndex >= sampPerSec {
		sampIndex = 0
	}
}

func main() {
	if len(os.Args) != 9 {
		fmt.Fprintf(os.Stderr, "usage: %s <protocol> <hostname> <port> <baseline rate (bps)> <rate 2 (bps)> <rate 3 (bps)> <step duration> <samples per second>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Traffic rates are specified in bytes per second.\n")
		fmt.Fprintf(os.Stderr, "'samples per second' indicates how many packets to send each second\n")
		os.Exit(1)
	}

	protocol := strings.ToLower(os.Args[1])
	hostname := os.Args[2]
	portno, _ := strconv.Atoi(os.Args[3])
	rates[baseline], _ = strconv.Atoi(os.Args[4])
	rates[1], _ = strconv.Atoi(os.Args[5])
	rates[2], _ = strconv.Atoi(os.Args[6])
	stepDuration, _ := strconv.Atoi(os.Args[7])
	sampPerSec, _ = strconv.Atoi(os.Args[8])

	if protocol != "tcp" && protocol != "udp" {
		fmt.Fprintf(os.Stderr, "Error, protocol must be 'tcp' or 'udp'\n")
		os.Exit(2)
	}

	if rates[0] <= 0 || rates[1] <= 0 || rates[2] <= 0 {
		fmt.Fprintf(os.Stderr, "Error, traffic rates must be > 0\n")
		os.Exit(3)
	}

	if stepDuration <= 0 {
		fmt.Fprintf(os.Stderr, "Error, step duration must be > 0\n")
		os.Exit(4)
	}

	if sampPerSec <= 0 {
		fmt.Fprintf(os.Stderr, "Error, samples per second must be > 0\n")
		os.Exit(5)
	}

	if sampPerSec > rates[baseline] || sampPerSec > rates[1] || sampPerSec > rates[2] {
		fmt.Fprintf(os.Stderr, "Error, samples per second must be fewer than all traffic rates\n")
		os.Exit(6)
	}

	maxRate := rates[baseline]
	if rates[1] > maxRate {
		maxRate = rates[1]
	}
	if rates[2] > maxRate {
		maxRate = rates[2]
	}

	maxSend := int(math.Ceil(float64(maxRate) / float64(sampPerSec)))

	randFile, err := os.Open("/dev/urandom")
	if err != nil {
		fmt.Printf("Error, opening urandom\n")
		os.Exit(7)
	}

	buf = make([]byte, maxSend)
	randReader := bufio.NewReader(randFile)
	_, err = randReader.Read(buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error, reading urandom\n")
		os.Exit(8)
	}
	randFile.Close()

	socket, _ = net.Dial(protocol, fmt.Sprintf("%s:%d", hostname, portno))

	stepTimer := timer.NewPeriodicTimer("Step timer", sendStep, false)
	stepTimer.Start(time.Duration(time.Second * time.Duration(stepDuration)))
	sendStep() // Need to run the sender while waiting for first tick.

	select {} // Wait forever.
}
