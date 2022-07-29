// Copyright 2022 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// I should test both:
// - symlink annexing
// - smudge annexing
// - http annexing
// - ssh annexing
//
// and then cross all that with testing different combinations of permissions
// ..yeah? Is that a reasonable thing to do?

// it would also be good, probably, to test how push-to-create interacts with git-annex

package integrations

import (
	"testing"
	"github.com/stretchr/testify/require"

	"errors"
	"os"
	"io/fs"
	"math/rand"
	"path"
	"path/filepath"
	"regexp"
	"fmt"
	"strings"
	"net/url"

	"code.gitea.io/gitea/modules/git"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/util"
	/*
	   "code.gitea.io/gitea/models/perm"
	*/

	//"time" // DEBUG
)

func TestGitAnnex(t *testing.T) {
	/*
		// TODO: look into how LFS did this
		if !setting.Annex.Enabled {
			t.Skip()
		}
	*/
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		defer doCleanAnnexLockdown() // workaround https://git-annex.branchable.com/internals/lockdown/

		API := NewAPITestContext(t, "user2", "annex-repo1")
		require.NotNil(t, API)

		t.Run("SSH", func(t *testing.T) {
			defer PrintCurrentTest(t)()
			//t.Run("CreateRepo", doAPICreateRepository(API, false))
			doAPICreateRepository(API, false)(t)

			// Setup the user's ssh key
			withKeyFile(t, "test-key", func(keyFile string) {
				//fmt.Printf("ssh key is at %#v\n", keyFile) // DEBUG
				os.Setenv("GIT_ANNEX_USE_GIT_SSH", "1") // withKeyFile works by setting GIT_SSH_COMMAND, but git-annex only respects that if this is set
				doAPICreateUserKey(API, "test-key", keyFile)(t)

				repoURL := createSSHUrl(API.GitPath(), u)

				// Setup clone folder
				repoPath, err := os.MkdirTemp("", API.Reponame)
				require.NoError(t, err)
				defer util.RemoveAll(repoPath)
				doGitClone(repoPath, repoURL)(t)

				//fmt.Printf("So yeah here's the thing: %#v\n", repoPath) // DEBUG

				doInitAnnexRepo(t, repoPath)

				// Upload
				_, _, err = git.NewCommand(git.DefaultContext, "annex", "sync", "--content").RunStdString(&git.RunOpts{Dir: repoPath})
				require.NoError(t, err)


				// Verify the upload

				// - method 0: check that 'git annex sync' successfully contacted the remote git-annex
				remoteAnnexUUID, _, err := git.NewCommand(git.DefaultContext, "config", "remote.origin.annex-uuid").RunStdString(&git.RunOpts{Dir: repoPath})
				require.NoError(t, err)
				remoteAnnexUUID = strings.TrimSpace(remoteAnnexUUID)
				require.Regexp(t,
					regexp.MustCompile("^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$"),
					remoteAnnexUUID,
					"git annex sync should have been able to download the remote's annex uuid")

				// Verify the upload: Check that the file was uploaded

				// - method 1: 'git annex whereis'
				annexWhereis, _, err := git.NewCommand(git.DefaultContext, "annex", "whereis", "large.bin").RunStdString(&git.RunOpts{Dir: repoPath})
				require.NoError(t, err)
				require.True(t,
				    strings.Contains(annexWhereis, " -- origin\n"),
				    "git annex whereis should report the file is uploaded to origin")

				// - method 2: look directly into the remote repo to find the file
				annexObjectPath, err := AnnexObjectPath(path.Join(setting.RepoRootPath, API.Username, API.Reponame+".git"), "large.bin")
				require.NoError(t, err)
				_, stat_err := os.Stat(annexObjectPath)
				require.NoError(t, stat_err, "Annexed file should exist in remote .git/annex/objects folder")
				// TODO: directly diff the source and target files

				//fmt.Printf("Sleeping now. good luck.\n") // give time to allow manually inspecting the test server; the password for all users is 'password'!
				//time.Sleep(2 * time.Second) // DEBUG

				// Delete the repo, make sure it's fully gone
				doAPIDeleteRepository(API)(t)

				_, stat_err = os.Stat(annexObjectPath)
				require.True(t, os.IsNotExist(stat_err), "Annexed file should not exist in remote .git/annex/objects folder")

				_, stat_err = os.Stat(path.Join(setting.RepoRootPath, API.Username, API.Reponame+".git"))
				require.True(t, os.IsNotExist(stat_err), "Remote annex repo should be removed from disk")

			})

		})

	})
}

func doGenerateRandomFile(size int, path string) (err error) {
	// Generate random file
	bufSize := 4 * 1024
	if bufSize > size {
		bufSize = size
	}

	buffer := make([]byte, bufSize)

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	written := 0
	for written < size {
		n := size - written
		if n > bufSize {
			n = bufSize
		}
		_, err := rand.Read(buffer[:n])
		if err != nil {
			return err
		}
		n, err = f.Write(buffer[:n])
		if err != nil {
			return err
		}
		written += n
	}
	if err != nil {
		return err
	}

	return nil
}

func doCleanAnnexLockdown() {
	// do chmod -R +w $REPOS in order to
	// handle https://git-annex.branchable.com/internals/lockdown/
	// > (The only bad consequence of this is that rm -rf .git doesn't work unless you first run chmod -R +w .git)
	// If this isn't done, the test can only be run once, because it reuses its gitea-repositories/ path

	filepath.WalkDir(setting.RepoRootPath, func(path string, d fs.DirEntry, err error) error {
		if err == nil {
			// 0200 == u+w, in octal unix permission notation
			info, err := d.Info()
			if err != nil {
				return err
			}

			err = os.Chmod(path, info.Mode()|0200)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func AnnexObjectPath(repoPath string, file string) (string, error) {
	// given a repo and a file in it
	// TODO: handle other branches, e.g. non-HEAD branches etc
	annexKey, _, err := git.NewCommand(git.DefaultContext, "show", "HEAD:"+file).RunStdString(&git.RunOpts{Dir: repoPath})
	if err != nil { return "", err }

	annexKey = strings.TrimSpace(annexKey)
	if ! strings.HasPrefix(annexKey, "/annex/objects/") {
		return "", errors.New(fmt.Sprintf("%s/%s does not appear to be annexed .", repoPath, file))
	}
	annexKey = strings.TrimPrefix(annexKey, "/annex/objects/")

	// we need to know the two-level folder prefix: https://git-annex.branchable.com/internals/hashing/
	keyHashPrefix, _, err := git.NewCommand(git.DefaultContext, "annex", "examinekey", "--format=${hashdirlower}", annexKey).RunStdString(&git.RunOpts{Dir: repoPath})
	if err != nil { return "", err }

	// TODO: handle non-bare repos
	// if ! bare { repoPath += "/.git", and use hashdirmixed instead of hashdirlower }

	return path.Join(repoPath, "annex", "objects", keyHashPrefix, annexKey, annexKey), nil
}

func doInitAnnexRepo(t *testing.T, repoPath string) {
	// initialize a repo with a some annexed and unannexed files

	// set up what files should be annexed
	// in this case, all *.bin  files will be annexed
	// without this, git-annex's default config annexes every file larger than some number of megabytes
	f, err := os.Create(path.Join(repoPath, ".gitattributes"))
	require.NoError(t, err)
	f.WriteString("*.bin  filter=annex annex.largefiles=anything")
	f.Close()

	require.NoError(t, git.AddChanges(repoPath, false, "."))
	require.NoError(t, git.CommitChanges(repoPath, git.CommitChangesOptions{Message: "Configure git-annex settings"}))

	require.NoError(t, git.NewCommand(git.DefaultContext, "annex", "init", "gitea-annex-test").Run(&git.RunOpts{Dir: repoPath}))

	doGenerateRandomFile(1024*1024/4, path.Join(repoPath, "large.bin"))
	require.NoError(t, git.AddChanges(repoPath, false, "."))
	require.NoError(t, git.CommitChanges(repoPath, git.CommitChangesOptions{Message: "Annex a file"}))
}
