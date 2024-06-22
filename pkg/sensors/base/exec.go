package base

import (
	"fmt"

	"github.com/xlab/treeprint"
)

var processTreeMap = "process_tree_map"
var tree = treeprint.New()

type binary struct {
	Length int64
	Path   [256]byte
}

type processTreeKey struct {
	Self   binary
	Parent binary
}

type processTreeValue struct {
	KtimeFirstExec uint64
	KtimeLastExec  uint64
}

func (k *processTreeKey) String() string {
	return fmt.Sprintf("Key: %s->%s\n", k.Parent.Path, k.Self.Path)
}

func (v *processTreeValue) String() string {
	return fmt.Sprintf("Value: %d:%d", v.KtimeFirstExec, v.KtimeLastExec)
}
