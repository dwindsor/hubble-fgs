package main

import (
	"fmt"
	"os"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/jsonchecker"
	"github.com/isovalent/hubble-fgs/tests"

	"github.com/sirupsen/logrus"
)

func main() {
	log := logger.GetLogger().(*logrus.Logger)

	if len(os.Args) < 3 {
		fmt.Printf("Usage: go run jobs.trace.go JSON_FILE KERNEL_VERSION")
	}

	jsonFile, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("🔥 opening json file failed: %s", err)
		os.Exit(1)
	}

	kernelVersion := os.Args[2]

	jsonFile.Seek(0, 0)
	if err := jsonchecker.JsonCheck(jsonFile, tests.DemoAppChecker(kernelVersion), log); err != nil {
		fmt.Printf("🔥 Demo app check failed: no dice: %s\n", err)
		os.Exit(1)
	}

	jsonFile.Seek(0, 0)
	if err := jsonchecker.JsonCheck(jsonFile, tests.TlsChecker(kernelVersion), log); err != nil {
		fmt.Printf("🔥 TLS check failed: no dice: %s\n", err)
		os.Exit(1)
	}

	jsonFile.Seek(0, 0)
	if err := jsonchecker.JsonCheck(jsonFile, tests.HttpChecker(kernelVersion), log); err != nil {
		fmt.Printf("🔥 HTTP check failed: no dice: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("🚢 Passed: ship it\n")
	os.Exit(0)
}
