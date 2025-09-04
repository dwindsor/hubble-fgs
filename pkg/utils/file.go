package utils

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	BUFSIZE = 4096
)

func SanitizePath(path string, validPaths []string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	for _, validPath := range validPaths {
		absValidPath, err := filepath.Abs(validPath)
		if err != nil {
			return err
		}

		if strings.HasPrefix(absPath, absValidPath) {
			return nil
		}
	}
	return fmt.Errorf("path %s is not within any valid working paths", path)
}

func CopyFile(src string, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}

	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	err = os.Chmod(dst, srcInfo.Mode())
	if err != nil {
		return err
	}
	return nil
}

func CopyDir(src string, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	err = os.MkdirAll(dst, srcInfo.Mode())
	if err != nil {
		return err
	}

	files, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, f := range files {
		srcPath := filepath.Join(src, f.Name())
		dstPath := filepath.Join(dst, f.Name())

		if f.IsDir() {
			err = CopyDir(srcPath, dstPath)
			if err != nil {
				return err
			}
		} else {
			err = CopyFile(srcPath, dstPath)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func DownloadFile(_ context.Context, path string, data []byte) error {
	// Create file
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0664)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write byte fragments to file
	for i := 0; i < len(data)/BUFSIZE+1; i++ {
		if i == len(data)/BUFSIZE {
			_, err = file.Write(data[i*BUFSIZE:])
			if err != nil {
				return err
			}
			break
		}
		_, err = file.Write(data[i*BUFSIZE : (i+1)*BUFSIZE])
		if err != nil {
			return err
		}
	}
	return nil
}

func DecompressGz(_ context.Context, path string) error {
	// Checking valid file name
	if !regexp.MustCompile(`^.+.gz$`).MatchString(path) {
		return fmt.Errorf("invalid file name")
	}
	newPath := path[:len(path)-3]

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	newFile, err := os.Create(newPath)
	if err != nil {
		return err
	}
	defer newFile.Close()

	_, err = io.Copy(newFile, gzipReader)
	if err != nil {
		return err
	}
	return nil
}

func ExtractTar(_ context.Context, path string, target string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create target directory if it doesn't exist
	_, err = os.Stat(target)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(target, os.FileMode(0755)); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	tarReader := tar.NewReader(file)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		} else if header == nil {
			continue
		}

		// Creating directories and files
		out := filepath.Join(target, header.Name)
		err = SanitizePath(out, []string{target})
		if err != nil {
			return errors.Join(err, fmt.Errorf("tar file contains malicious path"))
		}

		// Ensure parent directory exists
		parentDir := filepath.Dir(out)
		if _, err := os.Stat(parentDir); os.IsNotExist(err) {
			if err := os.MkdirAll(parentDir, 0755); err != nil {
				return fmt.Errorf("failed to create parent directory %s: %w", parentDir, err)
			}
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if _, err := os.Stat(out); err != nil {
				if err := os.MkdirAll(out, os.FileMode(header.Mode)); err != nil {
					return err
				}
			}
		case tar.TypeReg:
			f, err := os.OpenFile(out, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				// If we can't create the file, just skip it
				continue
			}
			if _, err := io.Copy(f, tarReader); err != nil {
				f.Close()
				return err
			}
			f.Close()
		default:
			// Skip other types of files (symlinks, devices, etc.)
		}
	}
}

func CreateGz(_ context.Context, path string, sourceFile string) error {
	// Create the gzip file
	gzipFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer gzipFile.Close()

	// Open the source file
	source, err := os.Open(sourceFile)
	if err != nil {
		return err
	}
	defer source.Close()

	// Create a new gzip writer
	gzipWriter := gzip.NewWriter(gzipFile)
	defer gzipWriter.Close()

	// Copy the source file into the gzip writer
	_, err = io.Copy(gzipWriter, source)
	if err != nil {
		return err
	}

	return nil
}

func CreateTar(_ context.Context, path string, sourceDir string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	tarWriter := tar.NewWriter(file)

	err = filepath.WalkDir(sourceDir, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(sourceDir, filePath)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(relPath)

		err = tarWriter.WriteHeader(header)
		if err != nil {
			return err
		}

		if !info.IsDir() {
			file, err := os.Open(filePath)
			if err != nil {
				return err
			}
			defer file.Close()

			_, err = io.Copy(tarWriter, file)
			if err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return err
	}

	err = tarWriter.Close()
	if err != nil {
		return err
	}

	return nil
}

// StoreJsonFile stores an object in JSON format to a file
//
// Parameters:
//   - ctx: context
//   - path: path to the JSON file
//   - data: object to store
//   - mode: file mode
func StoreJsonFile(_ context.Context, path string, data interface{}, mode fs.FileMode) error {
	c, err := json.Marshal(data)
	if err != nil {
		return err
	}
	err = os.WriteFile(path, c, mode)
	if err != nil {
		return err
	}
	return nil
}

// LoadJsonFile loads an object from JSON format in a file
//
// Parameters:
//   - ctx: context
//   - path: path to the JSON file
//   - data: object to load
func LoadJsonFile(_ context.Context, path string, data interface{}) error {
	c, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	err = json.Unmarshal(c, data)
	if err != nil {
		return err
	}
	return nil
}

// DecompressGzAndExtractTar decompresses a gzip file and extracts the tar file
func DecompressGzAndExtractTar(_ context.Context, path string, target string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	// Create target directory if it doesn't exist
	_, err = os.Stat(target)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(target, os.FileMode(0755)); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		} else if header == nil {
			continue
		}

		// Creating directories and files
		out := filepath.Join(target, header.Name)
		err = SanitizePath(out, []string{target})
		if err != nil {
			return errors.Join(err, fmt.Errorf("tar file contains malicious path"))
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if _, err := os.Stat(out); err != nil {
				if err := os.MkdirAll(out, os.FileMode(header.Mode)); err != nil {
					return err
				}
			}
		case tar.TypeReg:
			f, err := os.OpenFile(out, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tarReader); err != nil {
				return err
			}
			f.Close()
		}
	}
}
