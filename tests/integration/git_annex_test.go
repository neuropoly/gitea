// Copyright 2022 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package integration

import (
	"code.gitea.io/gitea/tests"
	"github.com/stretchr/testify/require"
	"testing"

	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	"code.gitea.io/gitea/models/perm"
	repo_model "code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/modules/git"
	"code.gitea.io/gitea/modules/setting"
	api "code.gitea.io/gitea/modules/structs"
	"code.gitea.io/gitea/modules/util"
)

// Some guidelines:
//
// * a APITestContext is an awkward union of session credential + username + target repo
//   which is assumed to be owned by that username; if you want to target a different
//   repo, you need to edit its .Reponame or just ignore it and write "username/reponame.git"

/*
 Test that permissions are enforced on git-annex-shell commands.

 Along the way, test that uploading, downloading, and deleting all work.
*/
func TestGitAnnexPermissions(t *testing.T) {
	/*
		// TODO: look into how LFS did this
		if !setting.Annex.Enabled {
			t.Skip()
		}
	*/

	// Each case below is split so that 'clone' is done as
	// the repo owner, but 'copy' as the user under test.
	//
	// Otherwise, in cases where permissions block the
	// initial 'clone', the test would simply end there
	// and never verify if permissions apply properly to
	// 'annex copy' -- potentially leaving a security gap.

	onGiteaRun(t, func(t *testing.T, u *url.URL) {

		t.Run("Public", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()

			// create a public repo
			ownerCtx := NewAPITestContext(t, "user2", "annex-public")
			doAPICreateRepository(ownerCtx, false)(t)
			private := false // this API takes pointers, so we need a variable
			doAPIEditRepository(ownerCtx, &api.EditRepoOption{Private: &private})(t)

			// double-check it's public
			repo, err := repo_model.GetRepositoryByOwnerAndName(ownerCtx.Username, ownerCtx.Reponame)
			require.NoError(t, err)
			require.False(t, repo.IsPrivate)

			// Remote addresses of the repo
			repoURL := createSSHUrl(ownerCtx.GitPath(), u)                        // remote git URL
			remoteRepoPath := path.Join(setting.RepoRootPath, ownerCtx.GitPath()) // path on disk -- which can be examined directly because we're testing from localhost

			// Fill in fixture data
			withAnnexCtxKeyFile(t, ownerCtx, func() {
				err = doInitRemoteAnnexRepository(t, repoURL)
				require.NoError(t, err, "git-annex repository should have been initialized")
			})

			// Different sessions, so we can test different permissions.
			// We leave Reponame blank because we don't actually then later add it according to each case if needed
			//
			// NB: these usernames need to match appropriate entries in models/fixtures/user.yml
			writerCtx := NewAPITestContext(t, "user5", "")
			readerCtx := NewAPITestContext(t, "user4", "")
			outsiderCtx := NewAPITestContext(t, "user8", "") // a user with no specific access

			// set up collaborators
			doAPIAddCollaborator(ownerCtx, readerCtx.Username, perm.AccessModeRead)(t)
			doAPIAddCollaborator(ownerCtx, writerCtx.Username, perm.AccessModeWrite)(t)

			// tests
			t.Run("Owner", func(t *testing.T) {
				defer tests.PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer tests.PrintCurrentTest(t)()

					repoPath := path.Join(t.TempDir(), ownerCtx.Reponame)
					defer util.RemoveAll(repoPath) // cleans out git-annex lockdown permissions

					withAnnexCtxKeyFile(t, ownerCtx, func() {
						doGitClone(repoPath, repoURL)(t)
					})

					withAnnexCtxKeyFile(t, ownerCtx, func() {
						t.Run("Init", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.NoError(t, doAnnexInitTest(remoteRepoPath, repoPath))
						})

						t.Run("Download", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.NoError(t, doAnnexDownloadTest(remoteRepoPath, repoPath))
						})

						t.Run("Upload", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.NoError(t, doAnnexUploadTest(remoteRepoPath, repoPath))
						})
					})
				})
			})

			t.Run("Writer", func(t *testing.T) {
				defer tests.PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer tests.PrintCurrentTest(t)()

					repoPath := path.Join(t.TempDir(), ownerCtx.Reponame)
					defer util.RemoveAll(repoPath) // cleans out git-annex lockdown permissions

					withAnnexCtxKeyFile(t, ownerCtx, func() {
						doGitClone(repoPath, repoURL)(t)
					})

					withAnnexCtxKeyFile(t, writerCtx, func() {
						t.Run("Init", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.NoError(t, doAnnexInitTest(remoteRepoPath, repoPath))
						})

						t.Run("Download", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.NoError(t, doAnnexDownloadTest(remoteRepoPath, repoPath))
						})

						t.Run("Upload", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.NoError(t, doAnnexUploadTest(remoteRepoPath, repoPath))
						})
					})
				})
			})

			t.Run("Reader", func(t *testing.T) {
				defer tests.PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer tests.PrintCurrentTest(t)()

					repoPath := path.Join(t.TempDir(), ownerCtx.Reponame)
					defer util.RemoveAll(repoPath) // cleans out git-annex lockdown permissions

					withAnnexCtxKeyFile(t, ownerCtx, func() {
						doGitClone(repoPath, repoURL)(t)
					})

					withAnnexCtxKeyFile(t, readerCtx, func() {
						t.Run("Init", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.NoError(t, doAnnexInitTest(remoteRepoPath, repoPath))
						})

						t.Run("Download", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.NoError(t, doAnnexDownloadTest(remoteRepoPath, repoPath))
						})

						t.Run("Upload", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.Error(t, doAnnexUploadTest(remoteRepoPath, repoPath), "Uploading should fail due to permissions")
						})
					})
				})
			})

			t.Run("Outsider", func(t *testing.T) {
				defer tests.PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer tests.PrintCurrentTest(t)()

					repoPath := path.Join(t.TempDir(), ownerCtx.Reponame)
					defer util.RemoveAll(repoPath) // cleans out git-annex lockdown permissions

					withAnnexCtxKeyFile(t, ownerCtx, func() {
						doGitClone(repoPath, repoURL)(t)
					})

					withAnnexCtxKeyFile(t, outsiderCtx, func() {
						t.Run("Init", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.NoError(t, doAnnexInitTest(remoteRepoPath, repoPath))
						})

						t.Run("Download", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.NoError(t, doAnnexDownloadTest(remoteRepoPath, repoPath))
						})

						t.Run("Upload", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.Error(t, doAnnexUploadTest(remoteRepoPath, repoPath), "Uploading should fail due to permissions")
						})
					})
				})
			})

			t.Run("Delete", func(t *testing.T) {
				defer tests.PrintCurrentTest(t)()

				// Delete the repo, make sure it's fully gone
				doAPIDeleteRepository(ownerCtx)(t)
				_, stat_err := os.Stat(remoteRepoPath)
				require.True(t, os.IsNotExist(stat_err), "Remote annex repo should be removed from disk")
			})
		})

		t.Run("Private", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()

			// create a private repo
			ownerCtx := NewAPITestContext(t, "user2", "annex-private")
			doAPICreateRepository(ownerCtx, false)(t)

			// double-check it's private
			repo, err := repo_model.GetRepositoryByOwnerAndName(ownerCtx.Username, ownerCtx.Reponame)
			require.NoError(t, err)
			require.True(t, repo.IsPrivate)

			// Remote addresses of the repo
			repoURL := createSSHUrl(ownerCtx.GitPath(), u)                        // remote git URL
			remoteRepoPath := path.Join(setting.RepoRootPath, ownerCtx.GitPath()) // path on disk -- which can be examined directly because we're testing from localhost

			// Fill in fixture data
			withAnnexCtxKeyFile(t, ownerCtx, func() {
				err = doInitRemoteAnnexRepository(t, repoURL)
				require.NoError(t, err, "git-annex repository should have been initialized")
			})

			// Different sessions, so we can test different permissions.
			// We leave Reponame blank because we don't actually then later add it according to each case if needed
			//
			// NB: these usernames need to match appropriate entries in models/fixtures/user.yml
			writerCtx := NewAPITestContext(t, "user5", "")
			readerCtx := NewAPITestContext(t, "user4", "")
			outsiderCtx := NewAPITestContext(t, "user8", "") // a user with no specific access
			// Note: there's also full anonymous access, which is only available for public HTTP repos;
			// it should behave the same as 'outsider' but we (will) test it separately below anyway

			// set up collaborators
			doAPIAddCollaborator(ownerCtx, readerCtx.Username, perm.AccessModeRead)(t)
			doAPIAddCollaborator(ownerCtx, writerCtx.Username, perm.AccessModeWrite)(t)

			// tests
			t.Run("Owner", func(t *testing.T) {
				defer tests.PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer tests.PrintCurrentTest(t)()

					repoPath := path.Join(t.TempDir(), ownerCtx.Reponame)
					defer util.RemoveAll(repoPath) // cleans out git-annex lockdown permissions

					withAnnexCtxKeyFile(t, ownerCtx, func() {
						doGitClone(repoPath, repoURL)(t)
					})

					withAnnexCtxKeyFile(t, ownerCtx, func() {
						t.Run("Init", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.NoError(t, doAnnexInitTest(remoteRepoPath, repoPath))
						})

						t.Run("Download", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.NoError(t, doAnnexDownloadTest(remoteRepoPath, repoPath))
						})

						t.Run("Upload", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.NoError(t, doAnnexUploadTest(remoteRepoPath, repoPath))
						})
					})
				})
			})

			t.Run("Writer", func(t *testing.T) {
				defer tests.PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer tests.PrintCurrentTest(t)()

					repoPath := path.Join(t.TempDir(), ownerCtx.Reponame)
					defer util.RemoveAll(repoPath) // cleans out git-annex lockdown permissions

					withAnnexCtxKeyFile(t, ownerCtx, func() {
						doGitClone(repoPath, repoURL)(t)
					})

					withAnnexCtxKeyFile(t, writerCtx, func() {
						t.Run("Init", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.NoError(t, doAnnexInitTest(remoteRepoPath, repoPath))
						})

						t.Run("Download", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.NoError(t, doAnnexDownloadTest(remoteRepoPath, repoPath))
						})

						t.Run("Upload", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.NoError(t, doAnnexUploadTest(remoteRepoPath, repoPath))
						})
					})
				})
			})

			t.Run("Reader", func(t *testing.T) {
				defer tests.PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer tests.PrintCurrentTest(t)()

					repoPath := path.Join(t.TempDir(), ownerCtx.Reponame)
					defer util.RemoveAll(repoPath) // cleans out git-annex lockdown permissions

					withAnnexCtxKeyFile(t, ownerCtx, func() {
						doGitClone(repoPath, repoURL)(t)
					})

					withAnnexCtxKeyFile(t, readerCtx, func() {
						t.Run("Init", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.NoError(t, doAnnexInitTest(remoteRepoPath, repoPath))
						})

						t.Run("Download", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.NoError(t, doAnnexDownloadTest(remoteRepoPath, repoPath))
						})

						t.Run("Upload", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.Error(t, doAnnexUploadTest(remoteRepoPath, repoPath), "Uploading should fail due to permissions")
						})
					})
				})
			})

			t.Run("Outsider", func(t *testing.T) {
				defer tests.PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer tests.PrintCurrentTest(t)()

					repoPath := path.Join(t.TempDir(), ownerCtx.Reponame)
					defer util.RemoveAll(repoPath) // cleans out git-annex lockdown permissions

					withAnnexCtxKeyFile(t, ownerCtx, func() {
						doGitClone(repoPath, repoURL)(t)
					})

					withAnnexCtxKeyFile(t, outsiderCtx, func() {
						t.Run("Init", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.Error(t, doAnnexInitTest(remoteRepoPath, repoPath), "annex init should fail due to permissions")
						})

						t.Run("Download", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.Error(t, doAnnexDownloadTest(remoteRepoPath, repoPath), "annex copy --from should fail due to permissions")
						})

						t.Run("Upload", func(t *testing.T) {
							defer tests.PrintCurrentTest(t)()

							require.Error(t, doAnnexUploadTest(remoteRepoPath, repoPath), "annex copy --to should fail due to permissions")
						})
					})
				})
			})

			t.Run("Delete", func(t *testing.T) {
				defer tests.PrintCurrentTest(t)()

				// Delete the repo, make sure it's fully gone
				doAPIDeleteRepository(ownerCtx)(t)
				_, stat_err := os.Stat(remoteRepoPath)
				require.True(t, os.IsNotExist(stat_err), "Remote annex repo should be removed from disk")
			})
		})
	})
}

/* test that 'git annex init' works

precondition: repoPath contains a pre-cloned git repo with an annex: a valid git-annex branch,
              and a file 'large.bin' in its origin's annex. See doInitAnnexRepository().

*/
func doAnnexInitTest(remoteRepoPath string, repoPath string) (err error) {
	_, _, err = git.NewCommand(git.DefaultContext, "annex", "init").RunStdString(&git.RunOpts{Dir: repoPath})
	if err != nil {
		return fmt.Errorf("Couldn't `git annex init`: %w", err)
	}

	// - method 0: 'git config remote.origin.annex-uuid'.
	//   Demonstrates that 'git annex init' successfully contacted
	//   the remote git-annex and was able to learn its ID number.
	readAnnexUUID, _, err := git.NewCommand(git.DefaultContext, "config", "remote.origin.annex-uuid").RunStdString(&git.RunOpts{Dir: repoPath})
	if err != nil {
		return fmt.Errorf("Couldn't read remote `git config remote.origin.annex-uuid`: %w", err)
	}
	readAnnexUUID = strings.TrimSpace(readAnnexUUID)

	match := regexp.MustCompile("^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$").MatchString(readAnnexUUID)
	if !match {
		return errors.New(fmt.Sprintf("'git config remote.origin.annex-uuid' should have been able to download the remote's uuid; but instead read '%s'.", readAnnexUUID))
	}

	remoteAnnexUUID, _, err := git.NewCommand(git.DefaultContext, "config", "annex.uuid").RunStdString(&git.RunOpts{Dir: remoteRepoPath})
	if err != nil {
		return fmt.Errorf("Couldn't read local `git config annex.uuid`: %w", err)
	}

	remoteAnnexUUID = strings.TrimSpace(remoteAnnexUUID)
	match = regexp.MustCompile("^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$").MatchString(remoteAnnexUUID)
	if !match {
		return errors.New(fmt.Sprintf("'git annex init' should have been able to download the remote's uuid; but instead read '%s'.", remoteAnnexUUID))
	}

	if readAnnexUUID != remoteAnnexUUID {
		return errors.New(fmt.Sprintf("'git annex init' should have read the expected annex UUID '%s', but instead got '%s'", remoteAnnexUUID, readAnnexUUID))
	}

	// - method 1: 'git annex whereis'.
	//   Demonstrates that git-annex understands the annexed file can be found in the remote annex.
	annexWhereis, _, err := git.NewCommand(git.DefaultContext, "annex", "whereis", "large.bin").RunStdString(&git.RunOpts{Dir: repoPath})
	if err != nil {
		return fmt.Errorf("Couldn't `git annex whereis large.bin`: %w", err)
	}
	// Note: this regex is unanchored because 'whereis' outputs multiple lines containing
	//       headers and 1+ remotes and we just want to find one of them.
	match = regexp.MustCompile(regexp.QuoteMeta(remoteAnnexUUID) + " -- .* \\[origin\\]\n").MatchString(annexWhereis)
	if !match {
		return errors.New("'git annex whereis' should report large.bin is known to be in [origin]")
	}

	return nil
}

func doAnnexDownloadTest(remoteRepoPath string, repoPath string) (err error) {
	// NB: this test does something slightly different if run separately from "doAnnexInitTest()":
	//     "git annex copy" will notice and run "git annex init", silently.
	//     This shouldn't change any results, but be aware in case it does.

	_, _, err = git.NewCommand(git.DefaultContext, "annex", "copy", "--from", "origin").RunStdString(&git.RunOpts{Dir: repoPath})
	if err != nil {
		return err
	}

	// verify the file was downloaded
	localObjectPath, err := annexObjectPath(repoPath, "large.bin")
	if err != nil {
		return err
	}
	//localObjectPath := path.Join(repoPath, "large.bin") // or, just compare against the checked-out file

	remoteObjectPath, err := annexObjectPath(remoteRepoPath, "large.bin")
	if err != nil {
		return err
	}

	match, err := util.FileCmp(localObjectPath, remoteObjectPath, 0)
	if err != nil {
		return err
	}
	if !match {
		return errors.New("Annexed files should be the same")
	}

	return nil
}

func doAnnexUploadTest(remoteRepoPath string, repoPath string) (err error) {
	// NB: this test does something slightly different if run separately from "Init":
	//     it first runs "git annex init" silently in the background.
	//     This shouldn't change any results, but be aware in case it does.

	err = generateRandomFile(1024*1024/4, path.Join(repoPath, "contribution.bin"))
	if err != nil {
		return err
	}

	err = git.AddChanges(repoPath, false, ".")
	if err != nil {
		return err
	}

	err = git.CommitChanges(repoPath, git.CommitChangesOptions{Message: "Annex another file"})
	if err != nil {
		return err
	}

	_, _, err = git.NewCommand(git.DefaultContext, "annex", "copy", "--to", "origin").RunStdString(&git.RunOpts{Dir: repoPath})
	if err != nil {
		return err
	}

	_, _, err = git.NewCommand(git.DefaultContext, "annex", "sync", "--no-content").RunStdString(&git.RunOpts{Dir: repoPath})
	if err != nil {
		return err
	}

	// verify the file was uploaded
	localObjectPath, err := annexObjectPath(repoPath, "contribution.bin")
	if err != nil {
		return err
	}
	//localObjectPath := path.Join(repoPath, "contribution.bin") // or, just compare against the checked-out file

	remoteObjectPath, err := annexObjectPath(remoteRepoPath, "contribution.bin")
	if err != nil {
		return err
	}

	match, err := util.FileCmp(localObjectPath, remoteObjectPath, 0)
	if err != nil {
		return err
	}
	if !match {
		return errors.New("Annexed files should be the same")
	}

	return nil
}

// ---- Helpers ----

func generateRandomFile(size int, path string) (err error) {
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

// ---- Annex-specific helpers ----

/* Initialize a repo with some baseline annexed and non-annexed files.

TODO: this could be replaced with a fixture repo;
see integrations/gitea-repositories-meta/ and models/fixtures/repository.yml.

However we reuse this template for -different- repos.
*/
func doInitAnnexRepository(repoPath string) error {
	// set up what files should be annexed
	// in this case, all *.bin  files will be annexed
	// without this, git-annex's default config annexes every file larger than some number of megabytes
	f, err := os.Create(path.Join(repoPath, ".gitattributes"))
	if err != nil {
		return err
	}

	_, err = f.WriteString("*                   annex.largefiles=nothing")
	if err != nil {
		return err
	}
	_, err = f.WriteString("*.bin  filter=annex annex.largefiles=anything")
	if err != nil {
		return err
	}
	f.Close()

	err = git.AddChanges(repoPath, false, ".")
	if err != nil {
		return err
	}
	err = git.CommitChanges(repoPath, git.CommitChangesOptions{Message: "Configure git-annex settings"})
	if err != nil {
		return err
	}

	// 'git annex init'
	// 'gitea-annex-test' is there to avoid the nuisance comment getting stored.
	err = git.NewCommand(git.DefaultContext, "annex", "init", "gitea-annex-test").Run(&git.RunOpts{Dir: repoPath})
	if err != nil {
		return err
	}

	// add a file to the annex
	err = generateRandomFile(1024*1024/4, path.Join(repoPath, "large.bin"))
	if err != nil {
		return err
	}
	err = git.AddChanges(repoPath, false, ".")
	if err != nil {
		return err
	}
	err = git.CommitChanges(repoPath, git.CommitChangesOptions{Message: "Annex a file"})
	if err != nil {
		return err
	}

	return nil
}

/* Initialize a repo with some baseline annexed and non-annexed files.

TODO: this could be replaced with a fixture repo;
see integrations/gitea-repositories-meta/ and models/fixtures/repository.yml.

However we reuse this template for -different- repos.

TODO: This has to take a testing.T, but only because it reuses a routine
      written in the other integration tests which expects it.
      It would be cleaner if it didn't have to.
*/
func doInitRemoteAnnexRepository(t *testing.T, repoURL *url.URL) error {
	repoPath := path.Join(t.TempDir(), path.Base(repoURL.Path))
	// This clone is immediately thrown away, which
	// helps force the tests to be end-to-end.
	defer util.RemoveAll(repoPath)

	doGitClone(repoPath, repoURL)(t)

	err := doInitAnnexRepository(repoPath)
	if err != nil {
		return err
	}

	_, _, err = git.NewCommand(git.DefaultContext, "annex", "sync", "--content").RunStdString(&git.RunOpts{Dir: repoPath})
	if err != nil {
		return err
	}

	return nil
}

/* given a git repo and a path to an annexed file in it (assumed to be committed to its HEAD),
   find the path in .git/annex/objects/ that contains its actual contents. */
func annexObjectPath(repoPath string, file string) (string, error) {

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

/* like withKeyFile(), but automatically sets it the account given in ctx for use by git-annex */
func withAnnexCtxKeyFile(t *testing.T, ctx APITestContext, callback func()) {
	_gitAnnexUseGitSSH, gitAnnexUseGitSSHExists := os.LookupEnv("GIT_ANNEX_USE_GIT_SSH")
	defer func() {
		// reset
		if gitAnnexUseGitSSHExists {
			os.Setenv("GIT_ANNEX_USE_GIT_SSH", _gitAnnexUseGitSSH)
		}
	}()

	os.Setenv("GIT_ANNEX_USE_GIT_SSH", "1") // withKeyFile works by setting GIT_SSH_COMMAND, but git-annex only respects that if this is set

	withCtxKeyFile(t, ctx, callback)
}
