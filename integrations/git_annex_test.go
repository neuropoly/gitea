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
	"github.com/stretchr/testify/require"
	"testing"

	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"code.gitea.io/gitea/models/perm"
	repo_model "code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/modules/git"
	"code.gitea.io/gitea/modules/setting"
	api "code.gitea.io/gitea/modules/structs"
	"code.gitea.io/gitea/modules/util"

	"time" // DEBUG
)

func TestGitAnnex(t *testing.T) {
	/*
		// TODO: look into how LFS did this
		if !setting.Annex.Enabled {
			t.Skip()
		}
	*/

	trueBool := true // this is silly but there's places it's needed
	falseBool := !trueBool

	// Some guidelines:
	// a APITestContext is an awkward union of session credential + username + target repo
	// which is assumed to be owned by that username; if you want to target a different
	// repo, you need to edit its .Reponame or just ignore it and write "username/reponame.git"

	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		defer doCleanAnnexLockdown() // workaround https://git-annex.branchable.com/internals/lockdown/

		// Different sessions, so we can test
		// We unset Reponame up here at the top, then later add it according to each test
		ownerSession := NewAPITestContext(t, "user2", "")
		readCollaboratorSession := NewAPITestContext(t, "user4", "")
		writeCollaboratorSession := NewAPITestContext(t, "user5", "")
		otherSession := NewAPITestContext(t, "user8", "") // a user with no specific access
		// Note: there's also full anonymous access, which is only available for public HTTP repos; it should behave the same as 'other'
		// but we test it separately below anyway

		t.Run("Public", func(t *testing.T) {
			defer PrintCurrentTest(t)()

			// create a public repo
			s := ownerSession // copy to prevent cross-contamination
			s.Reponame = "annex-public"
			doAPICreateRepository(s, false)(t)
			doAPIEditRepository(s, &api.EditRepoOption{Private: &falseBool})(t) // make the repo public
			// double-check it's public (this should be taken care of by models/fixtures/repository.yml, but better to check)
			repo, err := repo_model.GetRepositoryByOwnerAndName(s.Username, s.Reponame)
			require.NoError(t, err)
			require.True(t, !repo.IsPrivate)

			sshURL := createSSHUrl(s.GitPath(), u)
			//httpURL := createSSHUrl(s.GitPath(), u) // XXX this puts username and password into the URL
			// anonHTTPUrl := ???

			// set up collaborators
			doAPIAddCollaborator(s, readCollaboratorSession.Username, perm.AccessModeRead)(t)
			doAPIAddCollaborator(s, writeCollaboratorSession.Username, perm.AccessModeWrite)(t)

			// fill in fixture data
			doAPIAnnexInitRepository(t, s, u) // XXX this function always uses ssh, so we don't have a way to test git-annex-push-to-create-over-http;

			t.Run("Owner", func(t *testing.T) {
				defer PrintCurrentTest(t)()
				t.Run("SSH", func(t *testing.T) {
					defer PrintCurrentTest(t)()

					repoURL := sshURL

					withAnnexCtxKeyFile(t, ownerSession, func() {
						repoPath, err := os.MkdirTemp("", s.Reponame)
						require.NoError(t, err)
						//defer util.RemoveAll(repoPath)

						doAnnexClone(t, repoPath, repoURL)

						t.Run("Contribute", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doGenerateRandomFile(1024*1024/4, path.Join(repoPath, "contribution.bin")))
							require.NoError(t, git.AddChanges(repoPath, false, "."))
							require.NoError(t, git.CommitChanges(repoPath, git.CommitChangesOptions{Message: "Annex a file"}))
							_, _, err = git.NewCommand(git.DefaultContext, "annex", "copy", "--to", "origin").RunStdString(&git.RunOpts{Dir: repoPath})
							require.NoError(t, err)

							_, _, err = git.NewCommand(git.DefaultContext, "annex", "sync", "--no-content").RunStdString(&git.RunOpts{Dir: repoPath})
							require.NoError(t, err)

							// verify the file was uploaded
							annexObjectPath, err := AnnexObjectPath(path.Join(setting.RepoRootPath, s.Username, s.Reponame+".git"), "contribution.bin")
							require.NoError(t, err)
							match, err := filecmp(path.Join(repoPath, "contribution.bin"), annexObjectPath, 0)
							require.NoError(t, err, "Annexed file should be readable in both "+repoPath+"/large.bin and "+annexObjectPath)
							require.True(t, match, "Annexed files should be the same")

						})
					})
				})
			})

			t.Run("ReadCollaborator", func(t *testing.T) {
				defer PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer PrintCurrentTest(t)()
					repoURL := sshURL

					withAnnexCtxKeyFile(t, readCollaboratorSession, func() {

						repoPath, err := os.MkdirTemp("", s.Reponame)
						require.NoError(t, err)
						defer util.RemoveAll(repoPath)

						doAnnexClone(t, repoPath, repoURL)

						// now what?

						// now we try to upload again and see what happens

						t.Run("Contribute", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doGenerateRandomFile(1024*1024/4, path.Join(repoPath, "contribution.bin")))
							require.NoError(t, git.AddChanges(repoPath, false, "."))
							require.NoError(t, git.CommitChanges(repoPath, git.CommitChangesOptions{Message: "Annex a file"}))
							_, _, err = git.NewCommand(git.DefaultContext, "annex", "copy", "--to", "origin").RunStdString(&git.RunOpts{Dir: repoPath})
							require.Error(t, err)
							//require.True(t, strings.Contains(err.Error(), "Gitea: Unauthorized"), "Uploading should fail due to permissions")
						})
					})
				})
			})

			t.Run("WriteCollaborator", func(t *testing.T) {
				defer PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer PrintCurrentTest(t)()
					repoURL := sshURL

					withAnnexCtxKeyFile(t, writeCollaboratorSession, func() {

						repoPath, err := os.MkdirTemp("", s.Reponame)
						require.NoError(t, err)
						defer util.RemoveAll(repoPath)

						doAnnexClone(t, repoPath, repoURL)

						// now what?

						// now we try to upload again and see what happens

						t.Run("Contribute", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doGenerateRandomFile(1024*1024/4, path.Join(repoPath, "contribution.bin")))
							require.NoError(t, git.AddChanges(repoPath, false, "."))
							require.NoError(t, git.CommitChanges(repoPath, git.CommitChangesOptions{Message: "Annex a file"}))
							_, _, err = git.NewCommand(git.DefaultContext, "annex", "copy", "--to", "origin").RunStdString(&git.RunOpts{Dir: repoPath})
							require.NoError(t, err)

							_, _, err = git.NewCommand(git.DefaultContext, "annex", "sync", "--no-content").RunStdString(&git.RunOpts{Dir: repoPath})
							require.NoError(t, err)

							// verify the file was uploaded
							annexObjectPath, err := AnnexObjectPath(path.Join(setting.RepoRootPath, s.Username, s.Reponame+".git"), "contribution.bin")
							require.NoError(t, err)
							match, err := filecmp(path.Join(repoPath, "contribution.bin"), annexObjectPath, 0)
							require.NoError(t, err, "Annexed file should be readable in both "+repoPath+"/large.bin and "+annexObjectPath)
							require.True(t, match, "Annexed files should be the same")

						})
					})
				})
			})

			t.Run("Other", func(t *testing.T) {
				defer PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer PrintCurrentTest(t)()
					repoURL := sshURL

					withAnnexCtxKeyFile(t, otherSession, func() {

						repoPath, err := os.MkdirTemp("", s.Reponame)
						require.NoError(t, err)
						defer util.RemoveAll(repoPath)

						doAnnexClone(t, repoPath, repoURL)

						// now what?

						// now we try to upload again and see what happens

						t.Run("Contribute", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doGenerateRandomFile(1024*1024/4, path.Join(repoPath, "contribution.bin")))
							require.NoError(t, git.AddChanges(repoPath, false, "."))
							require.NoError(t, git.CommitChanges(repoPath, git.CommitChangesOptions{Message: "Annex a file"}))
							_, _, err = git.NewCommand(git.DefaultContext, "annex", "copy", "--to", "origin").RunStdString(&git.RunOpts{Dir: repoPath})
							require.Error(t, err, "Uploading should fail due to permissions")
							// XXX this causes a *different* error message than the other cases
							// look into why and see if it can be made consistent
							//require.True(t, strings.Contains(err.Error(), "Gitea: Unauthorized"), "Uploading should fail due to permissions")
						})
					})
				})
			})

			t.Run("Delete", func(t *testing.T) {
				defer PrintCurrentTest(t)()

				// Delete the repo, make sure it's fully gone
				doAPIDeleteRepository(s)(t)
				_, stat_err := os.Stat(path.Join(setting.RepoRootPath, s.GitPath()))
				require.True(t, os.IsNotExist(stat_err), "Remote annex repo should be removed from disk")
			})

			//fmt.Printf("Sleeping now. good luck.\n") // give time to allow manually inspecting the test server; the password for all users is 'password'!
			time.Sleep(0 * time.Second) // DEBUG
		})

		t.Run("Private", func(t *testing.T) {
			defer PrintCurrentTest(t)()

			// create a public repo
			s := ownerSession // copy to prevent cross-contamination
			s.Reponame = "annex-private"
			doAPICreateRepository(s, false)(t)
			repo, err := repo_model.GetRepositoryByOwnerAndName(s.Username, s.Reponame)
			require.NoError(t, err)
			require.True(t, repo.IsPrivate)

			sshURL := createSSHUrl(s.GitPath(), u)
			//httpURL := createSSHUrl(s.GitPath(), u) // XXX this puts username and password into the URL
			// anonHTTPUrl := ???

			// set up collaborators
			doAPIAddCollaborator(s, readCollaboratorSession.Username, perm.AccessModeRead)(t)
			doAPIAddCollaborator(s, writeCollaboratorSession.Username, perm.AccessModeWrite)(t)

			// fill in fixture data
			doAPIAnnexInitRepository(t, s, u) // XXX this function always uses ssh, so we don't have a way to test git-annex-push-to-create-over-http;

			withAnnexCtxKeyFile(t, ownerSession, func() {

				repoPath, err := os.MkdirTemp("", s.Reponame)
				require.NoError(t, err)
				//defer util.RemoveAll(repoPath)

				doAnnexClone(t, repoPath, sshURL)

				t.Run("Owner", func(t *testing.T) {
					defer PrintCurrentTest(t)()
					t.Run("SSH", func(t *testing.T) {
						defer PrintCurrentTest(t)()

						withAnnexCtxKeyFile(t, ownerSession, func() {

							t.Run("Contribute", func(t *testing.T) {
								defer PrintCurrentTest(t)()

								require.NoError(t, doGenerateRandomFile(1024*1024/4, path.Join(repoPath, "contribution.bin")))
								require.NoError(t, git.AddChanges(repoPath, false, "."))
								require.NoError(t, git.CommitChanges(repoPath, git.CommitChangesOptions{Message: "Annex a file"}))
								_, _, err = git.NewCommand(git.DefaultContext, "annex", "copy", "--to", "origin").RunStdString(&git.RunOpts{Dir: repoPath})
								require.NoError(t, err)

								_, _, err = git.NewCommand(git.DefaultContext, "annex", "sync", "--no-content").RunStdString(&git.RunOpts{Dir: repoPath})
								require.NoError(t, err)

								// verify the file was uploaded
								annexObjectPath, err := AnnexObjectPath(path.Join(setting.RepoRootPath, s.Username, s.Reponame+".git"), "contribution.bin")
								require.NoError(t, err)
								match, err := filecmp(path.Join(repoPath, "contribution.bin"), annexObjectPath, 0)
								require.NoError(t, err, "Annexed file should be readable in both "+repoPath+"/large.bin and "+annexObjectPath)
								require.True(t, match, "Annexed files should be the same")

							})
						})
					})
				})

				t.Run("ReadCollaborator", func(t *testing.T) {
					defer PrintCurrentTest(t)()

					t.Run("SSH", func(t *testing.T) {
						defer PrintCurrentTest(t)()

						withAnnexCtxKeyFile(t, readCollaboratorSession, func() {

							// now we try to upload again and see what happens

							t.Run("Contribute", func(t *testing.T) {
								defer PrintCurrentTest(t)()

								require.NoError(t, doGenerateRandomFile(1024*1024/4, path.Join(repoPath, "contribution.bin")))
								require.NoError(t, git.AddChanges(repoPath, false, "."))
								require.NoError(t, git.CommitChanges(repoPath, git.CommitChangesOptions{Message: "Annex a file"}))
								_, _, err = git.NewCommand(git.DefaultContext, "annex", "copy", "--to", "origin").RunStdString(&git.RunOpts{Dir: repoPath})
								require.Error(t, err, "Uploading should fail due to permissions")
								// XXX this causes a *different* error message than the other cases
								// look into why and see if it can be made consistent
								//require.True(t, strings.Contains(err.Error(), "Gitea: Unauthorized"), "Uploading should fail due to permissions")
							})
						})
					})
				})

				t.Run("WriteCollaborator", func(t *testing.T) {
					defer PrintCurrentTest(t)()

					t.Run("SSH", func(t *testing.T) {
						defer PrintCurrentTest(t)()

						withAnnexCtxKeyFile(t, writeCollaboratorSession, func() {

							t.Run("Contribute", func(t *testing.T) {
								defer PrintCurrentTest(t)()

								require.NoError(t, doGenerateRandomFile(1024*1024/4, path.Join(repoPath, "contribution.bin")))
								require.NoError(t, git.AddChanges(repoPath, false, "."))
								require.NoError(t, git.CommitChanges(repoPath, git.CommitChangesOptions{Message: "Annex a file"}))
								_, _, err = git.NewCommand(git.DefaultContext, "annex", "copy", "--to", "origin").RunStdString(&git.RunOpts{Dir: repoPath})
								require.NoError(t, err)

								_, _, err = git.NewCommand(git.DefaultContext, "annex", "sync", "--no-content").RunStdString(&git.RunOpts{Dir: repoPath})
								require.NoError(t, err)

								// verify the file was uploaded
								annexObjectPath, err := AnnexObjectPath(path.Join(setting.RepoRootPath, s.Username, s.Reponame+".git"), "contribution.bin")
								require.NoError(t, err)
								match, err := filecmp(path.Join(repoPath, "contribution.bin"), annexObjectPath, 0)
								require.NoError(t, err, "Annexed file should be readable in both "+repoPath+"/large.bin and "+annexObjectPath)
								require.Truef(t, match, "Annexed files %s and %s should be the same", path.Join(repoPath, "contribution.bin"), annexObjectPath)

							})
						})
					})
				})

				t.Run("Other", func(t *testing.T) {
					defer PrintCurrentTest(t)()

					t.Run("SSH", func(t *testing.T) {
						defer PrintCurrentTest(t)()

						withAnnexCtxKeyFile(t, otherSession, func() {

							t.Run("Contribute", func(t *testing.T) {
								defer PrintCurrentTest(t)()

								require.NoError(t, doGenerateRandomFile(1024*1024/4, path.Join(repoPath, "contribution.bin")))
								require.NoError(t, git.AddChanges(repoPath, false, "."))
								require.NoError(t, git.CommitChanges(repoPath, git.CommitChangesOptions{Message: "Annex a file"}))
								_, _, err = git.NewCommand(git.DefaultContext, "annex", "copy", "--to", "origin").RunStdString(&git.RunOpts{Dir: repoPath})
								require.Error(t, err, "Uploading should fail due to permissions")
								require.True(t, strings.Contains(err.Error(), "Gitea: Unauthorized"), "Uploading should fail due to permissions")

							})
						})
					})
				})

				t.Run("Delete", func(t *testing.T) {
					defer PrintCurrentTest(t)()

					// Delete the repo, make sure it's fully gone
					//doAPIDeleteRepository(s)(t)
					//_, stat_err := os.Stat(path.Join(setting.RepoRootPath, s.GitPath()))
					//require.True(t, os.IsNotExist(stat_err), "Remote annex repo should be removed from disk")
				})

				//fmt.Printf("Sleeping now. good luck.\n") // give time to allow manually inspecting the test server; the password for all users is 'password'!
				time.Sleep(0 * time.Second) // DEBUG
			})
		})
	})
}

// https://stackoverflow.com/a/30038571
func filecmp(file1, file2 string, chunkSize int) (bool, error) {
	// Check file size ...
	if chunkSize == 0 {
		chunkSize = 2 << 12
	}

	f1, err := os.Open(file1)
	if err != nil {
		return false, err
	}
	defer f1.Close()

	f2, err := os.Open(file2)
	if err != nil {
		return false, err
	}
	defer f2.Close()

	for {
		b1 := make([]byte, chunkSize)
		_, err1 := f1.Read(b1)
		if err1 != nil && err1 != io.EOF {
			return false, err1
		}

		b2 := make([]byte, chunkSize)
		_, err2 := f2.Read(b2)
		if err2 != nil && err2 != io.EOF {
			return false, err2
		}

		if err1 == io.EOF && err2 == io.EOF {
			return true, nil
		} else if err1 != nil || err2 != nil {
			return false, nil
		}

		if !bytes.Equal(b1, b2) {
			return false, nil
		}
	}
}

func doGenerateRandomFile(size int, path string) (err error) {
	// Generate random file

	// XXX TODO: maybe this should not be random, but instead a predictable pattern, so that the test is deterministic
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

	// find the path inside *.git/annex/objects of a given file
	// i.e. figure out its two-level hash prefix: https://git-annex.branchable.com/internals/hashing/
	// ASSUMES the target file is checked into HEAD

	var bare bool // whether the repo is bare or not; this changes what the hashing algorithm is, due to backwards compatibility

	bareStr, _, err := git.NewCommand(git.DefaultContext, "config", "core.bare").RunStdString(&git.RunOpts{Dir: repoPath})
	if err != nil {
		return "", err
	}

	if bareStr == "true\n" {
		bare = true
	} else if bareStr == "false\n" {
		bare = false
	} else {
		return "", errors.New(fmt.Sprintf("Could not determine if %s is a bare repo or not; git config core.bare = <%s>", repoPath, bareStr))
	}

	// given a repo and a file in it
	// TODO: handle other branches, e.g. non-HEAD branches etc
	annexKey, _, err := git.NewCommand(git.DefaultContext, "show", "HEAD:"+file).RunStdString(&git.RunOpts{Dir: repoPath})
	if err != nil {
		return "", err
	}

	annexKey = strings.TrimSpace(annexKey)
	if !strings.HasPrefix(annexKey, "/annex/objects/") {
		return "", errors.New(fmt.Sprintf("%s/%s does not appear to be annexed .", repoPath, file))
	}
	annexKey = strings.TrimPrefix(annexKey, "/annex/objects/")

	var keyformat string
	if bare {
		keyformat = "hashdirlower"
	} else {
		keyformat = "hashdirmixed"
	}
	keyHashPrefix, _, err := git.NewCommand(git.DefaultContext, "annex", "examinekey", "--format=${"+keyformat+"}", annexKey).RunStdString(&git.RunOpts{Dir: repoPath})
	if err != nil {
		return "", err
	}

	if !bare {
		repoPath = path.Join(repoPath, ".git")
	}
	return path.Join(repoPath, "annex", "objects", keyHashPrefix, annexKey, annexKey), nil
}

func doAnnexClone(t *testing.T, repoPath string, repoURL *url.URL) {
	doGitClone(repoPath, repoURL)(t)

	_, _, git_err := git.NewCommand(git.DefaultContext, "annex", "get", ".").RunStdString(&git.RunOpts{Dir: repoPath})
	require.NoError(t, git_err)

	// Verify the download

	// - method 0: check that 'git annex get' successfully contacted the remote git-annex
	remoteAnnexUUID, _, git_err := git.NewCommand(git.DefaultContext, "config", "remote.origin.annex-uuid").RunStdString(&git.RunOpts{Dir: repoPath})
	require.NoError(t, git_err)
	remoteAnnexUUID = strings.TrimSpace(remoteAnnexUUID)
	require.Regexp(t,
		regexp.MustCompile("^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$"),
		remoteAnnexUUID,
		"git annex sync should have been able to download the remote's annex uuid")

	// TODO: scan for all annexed files?

	// - method 2: look into .git/annex/objects to find the annexed file
	annexObjectPath, err := AnnexObjectPath(repoPath, "large.bin")
	require.NoError(t, err)
	_, stat_err := os.Stat(annexObjectPath)
	require.NoError(t, stat_err, "Annexed file should exist in remote .git/annex/objects folder")

}

func doAPIAnnexInitRepository(t *testing.T, ctx APITestContext, u *url.URL) {

	API := ctx // TODO: change the names

	// ohhhh right. I need to install an ssh key here. dammit.
	withAnnexCtxKeyFile(t, ctx, func() {
		// Setup clone folder
		repoPath, err := os.MkdirTemp("", API.Reponame)
		require.NoError(t, err)
		defer util.RemoveAll(repoPath)

		repoURL := createSSHUrl(ctx.GitPath(), u)
		doGitClone(repoPath, repoURL)(t)

		//fmt.Printf("So yeah here's the thing: %#v\n", repoPath) // DEBUG

		doAnnexInitRepository(t, repoPath)

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
		remoteRepoPath := path.Join(setting.RepoRootPath, API.Username, API.Reponame+".git")
		annexObjectPath, err := AnnexObjectPath(remoteRepoPath, "large.bin")
		require.NoError(t, err)
		//_, stat_err := os.Stat(annexObjectPath)
		//require.NoError(t, stat_err, "Annexed file should exist in remote .git/annex/objects folder")
		match, err := filecmp(path.Join(repoPath, "large.bin"), annexObjectPath, 0)
		require.NoError(t, err, "Annexed file should be readable in both "+repoPath+" and "+remoteRepoPath)
		require.True(t, match, "Annexed files should be the same")
	})
}

func doAnnexInitRepository(t *testing.T, repoPath string) {
	// initialize a repo with a some annexed and unannexed files
	// TODO: this could be replaced with a fixture repo; see
	//       integrations/gitea-repositories-meta/ and models/fixtures/repository.yml
	//       However we reuse this many times.

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

	require.NoError(t, doGenerateRandomFile(1024*1024/4, path.Join(repoPath, "large.bin")))
	require.NoError(t, git.AddChanges(repoPath, false, "."))
	require.NoError(t, git.CommitChanges(repoPath, git.CommitChangesOptions{Message: "Annex a file"}))
}

func withAnnexCtxKeyFile(t *testing.T, ctx APITestContext, callback func()) {
	os.Setenv("GIT_ANNEX_USE_GIT_SSH", "1") // withKeyFile works by setting GIT_SSH_COMMAND, but git-annex only respects that if this is set

	_gitAnnexUseGitSSH, gitAnnexUseGitSSHExists := os.LookupEnv("GIT_ANNEX_USE_GIT_SSH")
	defer func() {
		if gitAnnexUseGitSSHExists {
			os.Setenv("GIT_ANNEX_USE_GIT_SSH", _gitAnnexUseGitSSH)
		}
	}()

	withCtxKeyFile(t, ctx, callback)
}
