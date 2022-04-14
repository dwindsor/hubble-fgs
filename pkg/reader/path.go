package reader

import "path/filepath"

func GetBinaryAbsolutePath(binary string, cwd string) string {
	if filepath.IsAbs(binary) {
		return binary
	}
	return filepath.Join(cwd, binary)
}
