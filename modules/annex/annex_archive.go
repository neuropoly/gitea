// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package annex

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"code.gitea.io/gitea/modules/git"
)

func createArchiveTargz(ctx context.Context, repo *git.Repository, target io.Writer, prefix, commitID string) error {
	// create a plain git tar archive
	var tarB bytes.Buffer
	err := repo.CreateArchive(ctx, git.TAR, &tarB, prefix != "", commitID)
	if err != nil {
		return err
	}

	gitFilesR := tar.NewReader(&tarB)

	gzipW := gzip.NewWriter(target)
	defer gzipW.Close()
	tarW := tar.NewWriter(gzipW)
	defer tarW.Close()

	tree, err := repo.GetTree(commitID)
	if err != nil {
		return err
	}

	for {
		oldHeader, err := gitFilesR.Next()
		// TODO: handle non-local names in tar archives?
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		// default to copying the current file from the archive created by repo.CreateArchive
		header := oldHeader
		dataR := io.Reader(gitFilesR)

		// if we can get a annex content location for the file we use that instead
		te, err := tree.GetTreeEntryByPath(strings.TrimPrefix(oldHeader.Name, prefix))
		if err == nil && (te.IsRegular() || te.IsExecutable() || te.IsLink()) {
			blob := te.Blob()
			annexPath, err := ContentLocation(blob)
			if err == nil {
				// blob corresponds to an annexed file

				// build a tar header for the annexed file
				file, err := os.Open(annexPath)
				if err != nil {
					return fmt.Errorf("opening %s failed: %w", annexPath, err)
				}
				stat, err := file.Stat()
				if err != nil {
					return fmt.Errorf("getting FileInfo for %s failed: %w", file.Name(), err)
				}

				// https://pkg.go.dev/archive/tar#Header:
				// > For forward compatibility, users that retrieve a Header from Reader.Next,
				// > mutate it in some ways, and then pass it back to Writer.WriteHeader should
				// > do so by creating a new Header and copying the fields that they are interested in preserving.
				header, err = tar.FileInfoHeader(stat, "")
				if err != nil {
					return fmt.Errorf("creating header failed: %w", err)
				}

				header.Size = stat.Size()
				if te.IsExecutable() || (te.IsLink() && (stat.Mode().Perm()&0o100) != 0) {
					// If the file is executable in git, or is a symlink to an annexed executable
					// file, archive it with permissions 0775, as `git archive` would do for
					// executables as well.
					header.Mode = int64(fs.FileMode(0o775))
				} else if te.IsRegular() || (te.IsLink() && (stat.Mode().Perm()&0o100) == 0) {
					// If the file is not executable in git (i.e. a regular file), or a symlink to
					// an annexed file that is not executable, archive it with permissions 0664.
					header.Mode = int64(fs.FileMode(0o664))
				}

				// preserve these
				header.Name = oldHeader.Name
				header.Linkname = oldHeader.Linkname
				header.Uid = oldHeader.Uid
				header.Gid = oldHeader.Gid
				header.Uname = oldHeader.Uname
				header.Gname = oldHeader.Gname
				header.ModTime = oldHeader.ModTime
				header.AccessTime = oldHeader.AccessTime
				header.ChangeTime = oldHeader.ChangeTime
				header.PAXRecords = oldHeader.PAXRecords
				header.Format = oldHeader.Format

				// set the data reader
				dataR = file
			}
		}

		// write header
		err = tarW.WriteHeader(header)
		if err != nil {
			return fmt.Errorf("writing header for %s failed: %w", header.Name, err)
		}

		// write data
		_, err = io.Copy(tarW, dataR)
		if err != nil {
			return fmt.Errorf("writing data for %s failed: %w", header.Name, err)
		}
	}

	return nil
}

func createArchiveZip(ctx context.Context, repo *git.Repository, target io.Writer, prefix, commitID string) error {
	// create a plain git zip archive
	var zipB bytes.Buffer
	err := repo.CreateArchive(ctx, git.ZIP, &zipB, prefix != "", commitID)
	if err != nil {
		return err
	}

	gitFilesR, err := zip.NewReader(bytes.NewReader(zipB.Bytes()), int64(zipB.Len()))
	if err != nil {
		return err
	}

	tree, err := repo.GetTree(commitID)
	if err != nil {
		return err
	}

	zipW := zip.NewWriter(target)
	defer zipW.Close()

	err = zipW.SetComment(gitFilesR.Comment)
	if err != nil {
		return fmt.Errorf("setting archive comment field failed: %w", err)
	}

	for _, f := range gitFilesR.File {
		oldHeader := f.FileHeader

		// default to copying the current file from the archive created by repo.CreateArchive
		// dataR is set later to avoid unnecessarily opening a file here
		header := &oldHeader
		dataR := io.Reader(nil)

		te, err := tree.GetTreeEntryByPath(strings.TrimPrefix(oldHeader.Name, prefix))
		if err == nil && (te.IsRegular() || te.IsExecutable() || te.IsLink()) {
			blob := te.Blob()
			annexPath, err := ContentLocation(blob)
			if err == nil {
				// blob corresponds to an annexed file

				// build a zip header for the file
				file, err := os.Open(annexPath)
				if err != nil {
					return fmt.Errorf("opening %s failed: %w", annexPath, err)
				}
				stat, err := file.Stat()
				if err != nil {
					return fmt.Errorf("getting FileInfo for %s failed: %w", file.Name(), err)
				}
				header, err = zip.FileInfoHeader(stat)
				if err != nil {
					return fmt.Errorf("creating header failed: %w", err)
				}
				header.Name = oldHeader.Name
				header.Method = zip.Deflate

				if te.IsExecutable() || (te.IsLink() && (stat.Mode().Perm()&0o100) != 0) {
					// If the file is executable in git, or is a symlink to an annexed executable
					// file, archive it with permissions 0775, as `git archive` would do for
					// executables as well.
					header.SetMode(fs.FileMode(0o755))
				} else if te.IsRegular() || (te.IsLink() && (stat.Mode().Perm()&0o100) == 0) {
					// If the file is not executable in git (i.e. a regular file), or a symlink to
					// an annexed file that is not executable, archive it with the "FAT creator"
					// in zip and set rw permissions through the external attrs.
					// `git archive` does the same for regular files.
					header.CreatorVersion = 0
					header.ExternalAttrs = 0
				}

				// set the data reader
				dataR = file
			}
		}

		if dataR == nil {
			// data reader was not yet set, take the data from the archive created by repo.CreateArchive
			file, err := f.Open()
			if err != nil {
				return fmt.Errorf("opening %s failed: %w", f.Name, err)
			}
			dataR = file
		}

		// write header
		fileW, err := zipW.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("writing header for %s failed: %w", header.Name, err)
		}

		// write data
		_, err = io.Copy(fileW, dataR)
		if err != nil {
			return fmt.Errorf("writing data for %s failed: %w", header.Name, err)
		}
	}

	return nil
}

// CreateArchive creates an archive of format from repo at commitID and writes it to target.
// Files in the archive are prefixed with the repositories name if usePrefix is true.
// It is an annex-aware alternative to Repository.CreateArchive in the git package.
func CreateArchive(ctx context.Context, repo *git.Repository, format git.ArchiveType, target io.Writer, usePrefix bool, commitID string) error {
	if format.String() == "unknown" {
		return fmt.Errorf("unknown format: %v", format)
	}

	var prefix string
	if usePrefix {
		prefix = filepath.Base(strings.TrimSuffix(repo.Path, ".git")) + "/"
	} else {
		prefix = ""
	}

	var err error
	if format == git.TARGZ {
		err = createArchiveTargz(ctx, repo, target, prefix, commitID)
	} else if format == git.ZIP {
		err = createArchiveZip(ctx, repo, target, prefix, commitID)
	} else {
		return fmt.Errorf("unsupported format: %v", format)
	}
	if err != nil {
		return fmt.Errorf("failed to create archive: %w", err)
	}

	return nil
}
