// Copyright 2023 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package integration

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"testing"

	auth_model "code.gitea.io/gitea/models/auth"
	"code.gitea.io/gitea/modules/annex"
	"code.gitea.io/gitea/modules/git"
	"code.gitea.io/gitea/modules/setting"

	"github.com/stretchr/testify/require"
)

type record struct {
	name        string
	isAnnexed   bool
	annexedMode fs.FileMode
	gitMode     git.EntryMode
	content     []byte
}

func TestGitAnnexArchive(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		ctx := NewAPITestContext(t, "user2", "annex-archive-test", auth_model.AccessTokenScopeWriteRepository)
		require.NoError(t, doCreateRemoteAnnexRepository(t, u, ctx, false))
		req := NewRequest(t, "GET", u.String())
		_ = ctx.Session.MakeRequest(t, req, http.StatusOK)

		remoteRepoPath := path.Join(setting.RepoRootPath, ctx.GitPath())

		// get the commitID of the master branch
		repo, err := git.OpenRepository(git.DefaultContext, remoteRepoPath)
		require.NoError(t, err)
		commitID, err := repo.GetBranchCommitID("master")
		require.NoError(t, err)
		tree, err := repo.GetTree("master")
		require.NoError(t, err)
		entries, err := tree.ListEntriesRecursiveFast()
		require.NoError(t, err)
		filesInGit := make(map[string]record, len(entries))
		var annexedMode fs.FileMode
		for _, entry := range entries {
			if !entry.IsDir() {
				name := entry.Name()
				blob := entry.Blob()
				isAnnexed, err := annex.IsAnnexed(blob)
				require.NoError(t, err)
				var r io.Reader
				if isAnnexed {
					fa, err := annex.Content(blob)
					require.NoError(t, err)
					defer fa.Close()
					r = fa
					stat, err := fa.Stat()
					require.NoError(t, err)
					annexedMode = stat.Mode()
				} else {
					// standard git file
					br, err := blob.DataAsync()
					require.NoError(t, err)
					defer br.Close()
					r = br
				}
				expectedContent, err := io.ReadAll(r)
				require.NoError(t, err)
				filesInGit[name] = record{
					name:        name,
					isAnnexed:   isAnnexed,
					annexedMode: annexedMode,
					gitMode:     entry.Mode(),
					content:     expectedContent,
				}
			}
		}

		t.Run("api-v1", func(t *testing.T) {
			urlBase := fmt.Sprintf("/api/v1/repos/%s/%s/archive/master", ctx.Username, ctx.Reponame)
			doTestArchive(t, ctx, urlBase, commitID, filesInGit)
		})

		t.Run("web", func(t *testing.T) {
			urlBase := fmt.Sprintf("/%s/%s/archive/master", ctx.Username, ctx.Reponame)
			doTestArchive(t, ctx, urlBase, commitID, filesInGit)
		})
	})
}

func doTestArchive(t *testing.T, ctx APITestContext, urlBase, commitID string, filesInGit map[string]record) {
	// cleanup previously generated archives
	adminSession := loginUser(t, "user1")
	adminToken := getTokenForLoggedInUser(t, adminSession, auth_model.AccessTokenScopeWriteAdmin)
	link, _ := url.Parse("/api/v1/admin/cron/delete_repo_archives")
	link.RawQuery = url.Values{"token": {adminToken}}.Encode()
	resp := adminSession.MakeRequest(t, NewRequest(t, "POST", link.String()), http.StatusNoContent)
	bs, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Len(t, bs, 0)

	t.Run("TARGZ", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				doTestTarGzArchive(t, urlBase+".tar.gz", ctx, commitID, filesInGit)
			}()
		}
		wg.Wait()
	})
	t.Run("ZIP", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				doTestZipArchive(t, urlBase+".zip", ctx, commitID, filesInGit)
			}()
		}
		wg.Wait()
	})
}

func getArchiveFromEndpoint(t *testing.T, ctx APITestContext, endpointURL string) []byte {
	link, _ := url.Parse(endpointURL)
	resp := ctx.Session.MakeRequest(t, NewRequest(t, "GET", link.String()), http.StatusOK)
	bs, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return bs
}

func doTestTarGzArchive(t *testing.T, endpointURL string, ctx APITestContext, commitID string, filesInGit map[string]record) {
	// request a tar.gz archive of the repo
	bs := getArchiveFromEndpoint(t, ctx, endpointURL)

	// open the archive for reading
	gzrd, err := gzip.NewReader(bytes.NewReader(bs))
	require.NoError(t, err)
	defer gzrd.Close()
	rd := tar.NewReader(gzrd)

	var filesInArchive []string
	for {
		header, err := rd.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		// skip directories
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// check that the pax_global_header comment field is correctly set
		if path.Base(header.Name) == "pax_global_header" {
			require.Equal(t, commitID, header.PAXRecords["comment"])
			continue // skip the remaining checks since this file does not exist in git
		}

		name := strings.TrimPrefix(header.Name, ctx.Reponame+"/")
		filesInArchive = append(filesInArchive, name)

		// make sure all files are the same as in the repo itself
		actualContent, err := io.ReadAll(rd)
		require.NoError(t, err)
		actualFileMode := header.FileInfo().Mode()
		compareToGitRecord(t, git.TARGZ, filesInGit[name], actualContent, actualFileMode)
	}
	// check that all files that are in git are also present in the archive
	compareListOfStrings(t, mapKeys(filesInGit), filesInArchive)
}

func doTestZipArchive(t *testing.T, endpointURL string, ctx APITestContext, commitID string, filesInGit map[string]record) {
	// request a zip archive of the repo
	bs := getArchiveFromEndpoint(t, ctx, endpointURL)

	// open the archive for reading
	r, err := zip.NewReader(bytes.NewReader(bs), int64(len(bs)))
	require.NoError(t, err)

	// check that the comment field is correctly set
	require.Equal(t, commitID, r.Comment)

	var filesInArchive []string
	for _, f := range r.File {
		// skip directories
		if f.FileInfo().IsDir() {
			continue
		}

		name := strings.TrimPrefix(f.Name, ctx.Reponame+"/")
		filesInArchive = append(filesInArchive, name)

		// make sure all files are the same as in the repo itself
		frd, err := f.Open()
		require.NoError(t, err)
		defer frd.Close()
		actualContent, err := io.ReadAll(frd)
		require.NoError(t, err)
		actualFileMode := f.Mode()
		compareToGitRecord(t, git.ZIP, filesInGit[name], actualContent, actualFileMode)
	}
	// check that all files that are in git are also present in the archive
	compareListOfStrings(t, mapKeys(filesInGit), filesInArchive)
}

func compareToGitRecord(t *testing.T, archiveType git.ArchiveType, gitRecord record, actualContent []byte, actualFileMode fs.FileMode) {
	expectedContent := gitRecord.content
	var expectedFileMode fs.FileMode
	// The expected file mode depends on the archive type and the type of file in git
	// (regular, executable, symlink, annex pointer, annex symlink)
	switch archiveType {
	case git.TARGZ:
		if gitRecord.gitMode == git.EntryModeExec ||
			(gitRecord.gitMode == git.EntryModeSymlink && gitRecord.isAnnexed && (gitRecord.annexedMode&0o100) != 0) {
			// If the file is a regular executable git file (plain-git or annex pointer file)
			// or a symlink to an executable annexed file expect file mode 0775, just like
			// what `git archive` would do for executable files.
			expectedFileMode = fs.FileMode(0o775)
		} else if gitRecord.gitMode == git.EntryModeBlob ||
			(gitRecord.gitMode == git.EntryModeSymlink && gitRecord.isAnnexed && (gitRecord.annexedMode&0o100) == 0) {
			// If the file is a regular non-executable git file (plain-git or annex pointer
			// file) or a symlink to a non-executable annexed file expect file mode 0664, like
			// what `git archive` would do.
			expectedFileMode = fs.FileMode(0o664)
		} else if gitRecord.gitMode == git.EntryModeSymlink {
			// If the file is a plain-git symlink expect a normal symlink.
			expectedFileMode = fs.FileMode(0o777) | fs.ModeSymlink
			// gitRecord.content contains the link target, but in tar.gz there is no content
			// for symlinks, so set the expectedContent to an empty byte slice.
			expectedContent = []byte{}
		}
	case git.ZIP:
		if gitRecord.gitMode == git.EntryModeExec ||
			(gitRecord.gitMode == git.EntryModeSymlink && gitRecord.isAnnexed && (gitRecord.annexedMode&0o100) != 0) {
			// If the file is a regular executable git file (plain-git or annex pointer file)
			// or a symlink to an executable annexed file expect file mode 0755.
			expectedFileMode = fs.FileMode(0o755)
		} else if gitRecord.gitMode == git.EntryModeBlob ||
			(gitRecord.gitMode == git.EntryModeSymlink && gitRecord.isAnnexed && (gitRecord.annexedMode&0o100) == 0) {
			// If the file is a regular non-executable git file (plain-git or annex pointer
			// file) or a symlink to a non-executable annexed file it should be archived with
			// creatorFAT and have rw permissions, like what `git archive` would do.
			// This means go should read it in with 0666 permissions.
			expectedFileMode = fs.FileMode(0o666)
		} else if gitRecord.gitMode == git.EntryModeSymlink {
			// If the file is a plain-git symlink expect a normal symlink.
			expectedFileMode = fs.FileMode(0o777) | fs.ModeSymlink
		}
	}

	// check that the file modes (type and permissions) are equal
	require.Equal(t, expectedFileMode.String(), actualFileMode.String())

	// check that the contents are equal
	require.Equal(t, expectedContent, actualContent)
}

func compareListOfStrings(t *testing.T, l1, l2 []string) {
	sort.Strings(l1)
	sort.Strings(l2)
	require.Equal(t, l1, l2)
}

func mapKeys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, len(m))

	i := 0
	for k := range m {
		keys[i] = k
		i++
	}

	return keys
}
