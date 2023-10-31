// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package annex

import (
	"errors"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"time"
)

// UntilFileDeletedReader is a io.Reader that reads from reader until the file at path
// is deleted and reader does not return any new bytes.
type UntilFileDeletedReader struct {
	path   string
	reader io.Reader
}

func NewUntilFileDeletedReader(path string, reader io.Reader) UntilFileDeletedReader {
	return UntilFileDeletedReader{path, reader}
}

func (r UntilFileDeletedReader) Read(buf []byte) (n int, err error) {
	n, err = r.reader.Read(buf)
	if err != io.EOF {
		return n, err
	}
	if n != 0 {
		return n, nil
	}
	_, err = os.Stat(r.path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, io.EOF
	}
	// Avoid hammering Read when there is no data, sleep for 0 to 1 seconds
	time.Sleep(time.Duration(rand.Intn(int(time.Second))))
	return 0, nil
}
