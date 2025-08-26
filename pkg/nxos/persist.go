package nxos

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
)

const (
	RootPersist  = "/iox_data"
	rootStates   = RootPersist + "/states"
	rootVolatile = "/data/volatile"
	agentFname   = rootStates + "/agent.json"
	ctrlrFname   = rootStates + "/ctrlr.json"
	haFname      = rootStates + "/ha.json"
	allocFname   = rootVolatile + "/alloc.json"
	PolFname     = RootPersist + "/policy.json"
	OtpFname     = RootPersist + "/.otp"
	updateFname  = RootPersist + "/update.json"
	ConfFname    = RootPersist + "/config"
)

//func (n *Nxos) getFnames(_ context.Context, prefix string) ([]string, error) {
//	files, err := filepath.Glob("/data/nxos/" + prefix + "*.json")
//	if err != nil {
//		logger.GetLogger().Error("Fail to glob", logfields.Error, err, "prefix", prefix)
//	}
//	return files, err
//}

func (n *Nxos) load(_ context.Context, fname string, content interface{}) error {
	c, err := ioutil.ReadFile(fname)
	if err != nil {
		logger.GetLogger().Debug("Fail to read file", "fname", fname, logfields.Error, err)
		return err
	}
	err = json.Unmarshal(c, content)
	if err != nil {
		logger.GetLogger().Error("Fail to unmarshal", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) store(_ context.Context, fname string, content interface{}) error {
	c, err := json.Marshal(content)
	if err != nil {
		logger.GetLogger().Error("Fail to marshal", logfields.Error, err)
		return err
	}

	err = ioutil.WriteFile(fname, c, 0644)
	if err != nil {
		logger.GetLogger().Error("Fail to write file", logfields.Error, err, "file", fname)
	}
	return err
}

func (n *Nxos) remove(_ context.Context, fname string) error {
	err := os.Remove(fname)
	if err != nil {
		logger.GetLogger().Error("Fail to delete file", logfields.Error, err, "file", fname)
	}
	return err
}
