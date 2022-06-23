package eventchecker

// simple wrappers to avoid replacing calls

import (
	oss "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
)

func NewProcessChecker() *oss.ProcessChecker {
	return oss.NewProcessChecker()
}

func NewContainerChecker() *oss.ContainerChecker {
	return oss.NewContainerChecker()
}

func NewPodChecker() *oss.PodChecker {
	return oss.NewPodChecker()
}

func NewImageChecker() *oss.ImageChecker {
	return oss.NewImageChecker()
}

func NewNamespacesChecker() *oss.NamespacesChecker {
	return oss.NewNamespacesChecker()
}
