package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/isovalent/hubble-fgs/pkg/javaattach"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: javaattach-smoke <pid> <native-agent> <manifest>")
		os.Exit(2)
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil { fatal(err) }
	if err := javaattach.LoadNativeAgent(pid, os.Args[2], os.Args[3]); err != nil { fatal(err) }
	fmt.Printf("ATTACH_REDEFINE_OK pid=%d manifest=%s\n", pid, os.Args[3])
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ATTACH_REDEFINE_FAILED:", err)
	os.Exit(1)
}
