// Copyright 2022 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

// Unlike modules/lfs, which operates mainly on git.Blobs, this operates on git.TreeEntrys.
// The motivation for this is that TreeEntrys have an easy pointer to the on-disk repo path,
// while blobs do not (in fact, if building with TAGS=gogit, blobs might exist only in a mock
// filesystem, living only in process RAM). We must have the on-disk path to do anything
// useful with git-annex because all of its interesting data is on-disk under .git/annex/.

package annex

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"code.gitea.io/gitea/modules/git"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/util"
)

const (
	// > The maximum size of a pointer file is 32 kb.
	// - https://git-annex.branchable.com/internals/pointer_file/
	// It's unclear if that's kilobytes or kibibytes; assuming kibibytes:
	blobSizeCutoff = 32 * 1024
)

// ErrInvalidPointer occurs if the pointer's value doesn't parse
var ErrInvalidPointer = errors.New("Not a git-annex pointer")

// Gets the content of the blob as raw text, up to n bytes.
// (the pre-existing blob.GetBlobContent() has a hardcoded 1024-byte limit)
func getBlobContent(b *git.Blob, n int) (string, error) {
	dataRc, err := b.DataAsync()
	if err != nil {
		return "", err
	}
	defer dataRc.Close()
	buf := make([]byte, n)
	n, _ = util.ReadAtMost(dataRc, buf)
	buf = buf[:n]
	return string(buf), nil
}

func Pointer(blob *git.Blob) (string, error) {
	// git-annex doesn't seem fully spec what its pointer are, but
	// the fullest description is here:
	// https://git-annex.branchable.com/internals/pointer_file/

	// a pointer can be:
	// the original format, generated by `git annex add`: a symlink to '.git/annex/objects/$HASHDIR/$HASHDIR2/$KEY/$KEY'
	// the newer, git-lfs influenced, format, generated by `git annex smudge`: a text file containing '/annex/objects/$KEY'
	//
	// in either case we can extract the $KEY the same way, and we need not actually know if it's a symlink or not because
	// git.Blob.DataAsync() works like open() + readlink(), handling both cases in one.

	if blob.Size() > blobSizeCutoff {
		// > The maximum size of a pointer file is 32 kb. If it is any longer, it is not considered to be a valid pointer file.
		// https://git-annex.branchable.com/internals/pointer_file/

		// It's unclear to me whether the same size limit applies to symlink-pointers, but it seems sensible to limit them too.
		return "", ErrInvalidPointer
	}

	pointer, err := getBlobContent(blob, blobSizeCutoff)
	if err != nil {
		return "", fmt.Errorf("error reading %s: %w", blob.Name(), err)
	}

	// the spec says a pointer file can contain multiple lines each with a pointer in them
	// but that makes no sense to me, so I'm just ignoring all but the first
	lines := strings.Split(pointer, "\n")
	if len(lines) < 1 {
		return "", ErrInvalidPointer
	}
	pointer = lines[0]

	// in both the symlink and pointer-file formats, the pointer must have "/annex/" somewhere in it
	if !strings.Contains(pointer, "/annex/") {
		return "", ErrInvalidPointer
	}

	// extract $KEY
	pointer = path.Base(strings.TrimSpace(pointer))

	// ask git-annex's opinion on $KEY
	// XXX: this is probably a bit slow, especially if this operation gets run often
	//      and examinekey is not that strict:
	//      - it doesn't enforce that the "BACKEND" tag is one it knows,
	//      - it doesn't enforce that the fields and their format fit the "BACKEND" tag
	//      so maybe this is a wasteful step
	_, examineStderr, err := git.NewCommandContextNoGlobals(git.DefaultContext, "annex", "examinekey").AddDynamicArguments(pointer).RunStdString(&git.RunOpts{Dir: blob.Repo().Path})
	if err != nil {
		// TODO: make ErrInvalidPointer into a type capable of wrapping err
		if strings.TrimSpace(examineStderr) == "git-annex: bad key" {
			return "", ErrInvalidPointer
		}
		return "", err
	}

	return pointer, nil
}

// return the absolute path of the content pointed to by the annex pointer stored in the git object
// errors if the content is not found in this repo
func ContentLocation(blob *git.Blob) (string, error) {
	pointer, err := Pointer(blob)
	if err != nil {
		return "", err
	}

	contentLocation, _, err := git.NewCommandContextNoGlobals(git.DefaultContext, "annex", "contentlocation").AddDynamicArguments(pointer).RunStdString(&git.RunOpts{Dir: blob.Repo().Path})
	if err != nil {
		return "", fmt.Errorf("in %s: %s does not seem to be a valid annexed file: %w", blob.Repo().Path, pointer, err)
	}
	contentLocation = strings.TrimSpace(contentLocation)
	contentLocation = path.Clean("/" + contentLocation)[1:] // prevent directory traversals
	contentLocation = path.Join(blob.Repo().Path, contentLocation)

	return contentLocation, nil
}

// returns a stream open to the annex content
func Content(blob *git.Blob) (*os.File, error) {
	contentLocation, err := ContentLocation(blob)
	if err != nil {
		return nil, err
	}

	return os.Open(contentLocation)
}

// whether the object appears to be a valid annex pointer
// does *not* verify if the content is actually in this repo;
// for that, use ContentLocation()
func IsAnnexed(blob *git.Blob) (bool, error) {
	if !setting.Annex.Enabled {
		return false, nil
	}

	// Pointer() is written to only return well-formed pointers
	// so the test is just to see if it errors
	_, err := Pointer(blob)
	if err != nil {
		if errors.Is(err, ErrInvalidPointer) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
