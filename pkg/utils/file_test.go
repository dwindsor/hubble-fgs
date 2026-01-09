// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package utils

import (
	"compress/gzip"
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func startup() {
	// Delete and create the testdata directory
	cleanup()
	err := os.MkdirAll("testdata", 0755)
	if err != nil {
		log.Fatal(err)
	}
}

func cleanup() {
	// Delete the testdata directory
	err := os.RemoveAll("testdata")
	if err != nil {
		log.Fatal(err)
	}
}

func TestSanitizePath(t *testing.T) {
	startup()
	defer cleanup()

	validPaths := []string{"testdata/valid", "testdata/another_valid"}

	tests := []struct {
		path       string
		validPaths []string
		expectErr  bool
	}{
		{"testdata/valid/file.txt", validPaths, false},
		{"testdata/another_valid/file.txt", validPaths, false},
		{"testdata/invalid/file.txt", validPaths, true},
		{"testdata/valid/../another_valid/file.txt", validPaths, false},
	}

	for _, tt := range tests {
		err := SanitizePath(tt.path, tt.validPaths)
		if tt.expectErr && err == nil {
			t.Errorf("expected error for path %s, but got none", tt.path)
		} else if !tt.expectErr && err != nil {
			t.Errorf("did not expect error for path %s, but got: %v", tt.path, err)
		}
	}
}

func TestCopyFile(t *testing.T) {
	startup()
	defer cleanup()

	src := "testdata/source.txt"
	dst := "testdata/destination.txt"

	// Create a temporary source file
	err := os.WriteFile(src, []byte("Hello, World!"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(src)

	// Call the copyFile function
	err = CopyFile(src, dst)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that the destination file exists and has the same content as the source file
	content, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}

	expected := "Hello, World!"
	actual := string(content)
	if actual != expected {
		t.Errorf("Expected content: %s, but got: %s", expected, actual)
	}
}

func TestCopyDir(t *testing.T) {
	startup()
	defer cleanup()

	src := "testdata/source"
	dst := "testdata/destination"

	// Create a temporary source directory with some files
	err := os.MkdirAll(filepath.Join(src, "subdir"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(src)

	err = os.WriteFile(filepath.Join(src, "file1.txt"), []byte("File 1"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(src, "subdir", "file2.txt"), []byte("File 2"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Call the copyDir function
	err = CopyDir(src, dst)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that the destination directory and files exist
	_, err = os.Stat(filepath.Join(dst, "file1.txt"))
	if err != nil {
		t.Errorf("Failed to copy file1.txt: %v", err)
	}

	_, err = os.Stat(filepath.Join(dst, "subdir", "file2.txt"))
	if err != nil {
		t.Errorf("Failed to copy file2.txt: %v", err)
	}
}

func TestDownloadFile(t *testing.T) {
	startup()
	defer cleanup()

	path := "testdata/downloaded_file.txt"
	data := []byte("Hello, World!")

	// Call the downloadFile function
	err := DownloadFile(context.Background(), path, data)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that the downloaded file exists and has the correct content
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	expected := "Hello, World!"
	actual := string(content)
	if actual != expected {
		t.Errorf("Expected content: %s, but got: %s", expected, actual)
	}
}

func TestDecompressGz(t *testing.T) {
	startup()
	defer cleanup()

	// Create a compressed file using CreateGz
	compressedFilePath := "testdata/compressed_file.gz"
	fileContent := []byte("This is a test file\n")
	sourceFilePath := "testdata/source_file.txt"

	// Write the file content to the source file
	err := os.WriteFile(sourceFilePath, fileContent, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(sourceFilePath)

	err = CreateGz(context.Background(), compressedFilePath, sourceFilePath)
	if err != nil {
		t.Fatal(err)
	}

	// Call the decompressGz function
	err = DecompressGz(context.Background(), compressedFilePath)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that the decompressed file exists and matches the original file
	newPath := "testdata/compressed_file"
	content, err := os.ReadFile(newPath)
	if err != nil {
		t.Errorf("Failed to read decompressed file: %v", err)
	}

	if string(content) != string(fileContent) {
		t.Errorf("Decompressed file content does not match original file content")
	}
}

func TestTar(t *testing.T) {
	startup()
	defer cleanup()

	path := "testdata/archive.tar"
	target := "testdata/extracted"

	// Create a temporary tar archive with some files
	err := os.MkdirAll(filepath.Join(target, "subdir"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(target)
	err = os.WriteFile(filepath.Join(target, "file1.txt"), []byte("File 1"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(target, ".wh..wh..opq"), []byte("File 1"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(target, "subdir", "file2.txt"), []byte("File 2"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = CreateTar(context.Background(), path, target)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)

	// Call the extractTar function
	err = ExtractTar(context.Background(), path, target)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that the extracted files exist
	_, err = os.Stat(filepath.Join(target, "file1.txt"))
	if err != nil {
		t.Errorf("Failed to extract file1.txt: %v", err)
	}
	_, err = os.Stat(filepath.Join(target, ".wh..wh..opq"))
	if err != nil {
		t.Errorf("Failed to extract .wh..wh..opq: %v", err)
	}
	_, err = os.Stat(filepath.Join(target, "subdir", "file2.txt"))
	if err != nil {
		t.Errorf("Failed to extract file2.txt: %v", err)
	}
}

func TestStoreLoadJsonFile(t *testing.T) {
	startup()
	defer cleanup()

	type TestData struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	testData := TestData{
		Name:  "Test",
		Value: 123,
	}

	path := "testdata/test.json"

	// Store the JSON file first
	err := StoreJsonFile(context.Background(), path, testData, 0644)
	if err != nil {
		t.Fatalf("Failed to store JSON file: %v", err)
	}

	// Load the JSON file
	var loadedData TestData
	err = LoadJsonFile(context.Background(), path, &loadedData)
	if err != nil {
		t.Fatalf("Failed to load JSON file: %v", err)
	}

	// Verify that the loaded data matches the original data
	if loadedData != testData {
		t.Errorf("Expected data: %+v, but got: %+v", testData, loadedData)
	}
}
func TestDecompressGzAndExtractTar(t *testing.T) {
	startup()
	defer cleanup()

	// Create a compressed tar file
	compressedFilePath := "testdata/compressed_tar_file.gz"
	tarFilePath := "testdata/tar_file.tar"
	sourceDir := "testdata/before"
	targetDir := "testdata/after"

	// Create a temporary source directory with some files
	err := os.MkdirAll(filepath.Join(sourceDir, "subdir"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sourceDir)

	err = os.WriteFile(filepath.Join(sourceDir, "file1.txt"), []byte("File 1"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(sourceDir, "subdir", "file2.txt"), []byte("File 2"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Create a tar file from the source directory
	err = CreateTar(context.Background(), tarFilePath, sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tarFilePath)

	// Compress the tar file
	tarFile, err := os.Open(tarFilePath)
	if err != nil {
		t.Fatal(err)
	}
	defer tarFile.Close()

	compressedFile, err := os.Create(compressedFilePath)
	if err != nil {
		t.Fatal(err)
	}
	defer compressedFile.Close()

	gzipWriter := gzip.NewWriter(compressedFile)
	defer gzipWriter.Close()

	_, err = io.Copy(gzipWriter, tarFile)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter.Close()
	compressedFile.Close()

	// Call the DecompressGzAndExtractTar function
	err = DecompressGzAndExtractTar(context.Background(), compressedFilePath, targetDir)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that the extracted files exist
	_, err = os.Stat(filepath.Join(targetDir, "file1.txt"))
	if err != nil {
		t.Errorf("Failed to extract file1.txt: %v", err)
	}

	_, err = os.Stat(filepath.Join(targetDir, "subdir", "file2.txt"))
	if err != nil {
		t.Errorf("Failed to extract file2.txt: %v", err)
	}
}
