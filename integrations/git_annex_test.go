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
		defer annexUnlockdown() // workaround https://git-annex.branchable.com/internals/lockdown/

		t.Run("Public", func(t *testing.T) {
			defer PrintCurrentTest(t)()

			// create a public repo
			ctx := NewAPITestContext(t, "user2", "annex-public")
			doAPICreateRepository(ctx, false)(t)
			doAPIEditRepository(ctx, &api.EditRepoOption{Private: &falseBool})(t)

			// double-check it's public
			repo, err := repo_model.GetRepositoryByOwnerAndName(ctx.Username, ctx.Reponame)
			require.NoError(t, err)
			require.True(t, !repo.IsPrivate)

			// fill in fixture data
			// TODO: replace this with a pre-made repo in integrations/gitea-repositories-meta/ ?
			withAnnexCtxKeyFile(t, ctx, func() {
				// note: this clone is immediately thrown away;
				// the tests below reclone it, to test end-to-end.
				repoPath, err := os.MkdirTemp("", ctx.Reponame)
				require.NoError(t, err)
				defer util.RemoveAll(repoPath)

				repoURL := createSSHUrl(ctx.GitPath(), u)
				doGitClone(repoPath, repoURL)(t)

				doInitAnnexRepository(t, repoPath)

				_, _, err = git.NewCommand(git.DefaultContext, "annex", "sync", "--content").RunStdString(&git.RunOpts{Dir: repoPath})
				require.NoError(t, err)
			})

			// Different sessions, so we can test different permissions.
			// We leave Reponame blank because we don't actually then later add it according to each case if needed
			//
			// NB: these usernames need to match appropriate entries in models/fixtures/user.yml
			ownerCtx := NewAPITestContext(t, ctx.Username, "")
			writerCtx := NewAPITestContext(t, "user5", "")
			readerCtx := NewAPITestContext(t, "user4", "")
			outsiderCtx := NewAPITestContext(t, "user8", "") // a user with no specific access
			// Note: there's also full anonymous access, which is only available for public HTTP repos;
			// it should behave the same as 'outsider' but we (will) test it separately below anyway

			//httpURL := createSSHUrl(ctx.GitPath(), u) // XXX this puts username and password into the URL
			// anonHTTPUrl := ???

			// set up collaborators
			doAPIAddCollaborator(ctx, readerCtx.Username, perm.AccessModeRead)(t)
			doAPIAddCollaborator(ctx, writerCtx.Username, perm.AccessModeWrite)(t)

			// tests
			t.Run("Owner", func(t *testing.T) {
				defer PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer PrintCurrentTest(t)()

					repoURL := createSSHUrl(ctx.GitPath(), u)

					repoPath, err := os.MkdirTemp("", ctx.Reponame)
					require.NoError(t, err)
					defer util.RemoveAll(repoPath)

					remoteRepoPath := path.Join(setting.RepoRootPath, ctx.GitPath())

					// This test is split up into separate withKeyFile()s
					// so it can isolate 'git annex copy' from 'git clone':
					//
					// 'clone' is done as the repo owner, to guarantee it
					// works, but 'copy' is done as the user under test.
					//
					// Otherwise, in cases where permissions block the
					// initial 'clone', the test would simply end there
					// and never verify if permissions apply properly to
					// 'annex copy' -- potentially leaving a security gap.
					withAnnexCtxKeyFile(t, ctx, func() {
						doGitClone(repoPath, repoURL)(t)
					})

					withAnnexCtxKeyFile(t, ownerCtx, func() {
						t.Run("Init", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doAnnexInitTest(remoteRepoPath, repoPath))
						})

						t.Run("Download", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doAnnexDownloadTest(remoteRepoPath, repoPath))
						})

						t.Run("Upload", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doAnnexUploadTest(remoteRepoPath, repoPath))
						})
					})
				})
			})

			t.Run("Writer", func(t *testing.T) {
				defer PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer PrintCurrentTest(t)()

					repoURL := createSSHUrl(ctx.GitPath(), u)

					repoPath, err := os.MkdirTemp("", ctx.Reponame)
					require.NoError(t, err)
					defer util.RemoveAll(repoPath)

					remoteRepoPath := path.Join(setting.RepoRootPath, ctx.GitPath())

					// This test is split up into separate withKeyFile()s
					// so it can isolate 'git annex copy' from 'git clone':
					//
					// 'clone' is done as the repo owner, to guarantee it
					// works, but 'copy' is done as the user under test.
					//
					// Otherwise, in cases where permissions block the
					// initial 'clone', the test would simply end there
					// and never verify if permissions apply properly to
					// 'annex copy' -- potentially leaving a security gap.
					withAnnexCtxKeyFile(t, ctx, func() {
						doGitClone(repoPath, repoURL)(t)
					})

					withAnnexCtxKeyFile(t, writerCtx, func() {
						t.Run("Init", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doAnnexInitTest(remoteRepoPath, repoPath))
						})

						t.Run("Download", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doAnnexDownloadTest(remoteRepoPath, repoPath))
						})

						t.Run("Upload", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doAnnexUploadTest(remoteRepoPath, repoPath))
						})
					})
				})
			})

			t.Run("Reader", func(t *testing.T) {
				defer PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer PrintCurrentTest(t)()

					repoURL := createSSHUrl(ctx.GitPath(), u)

					repoPath, err := os.MkdirTemp("", ctx.Reponame)
					require.NoError(t, err)
					defer util.RemoveAll(repoPath)

					remoteRepoPath := path.Join(setting.RepoRootPath, ctx.GitPath())

					// This test is split up into separate withKeyFile()s
					// so it can isolate 'git annex copy' from 'git clone':
					//
					// 'clone' is done as the repo owner, to guarantee it
					// works, but 'copy' is done as the user under test.
					//
					// Otherwise, in cases where permissions block the
					// initial 'clone', the test would simply end there
					// and never verify if permissions apply properly to
					// 'annex copy' -- potentially leaving a security gap.
					withAnnexCtxKeyFile(t, ctx, func() {
						doGitClone(repoPath, repoURL)(t)
					})

					withAnnexCtxKeyFile(t, readerCtx, func() {
						t.Run("Init", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doAnnexInitTest(remoteRepoPath, repoPath))
						})

						t.Run("Download", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doAnnexDownloadTest(remoteRepoPath, repoPath))
						})

						t.Run("Upload", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.Error(t, doAnnexUploadTest(remoteRepoPath, repoPath), "Uploading should fail due to permissions")
						})
					})
				})
			})

			t.Run("Outsider", func(t *testing.T) {
				defer PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer PrintCurrentTest(t)()

					repoURL := createSSHUrl(ctx.GitPath(), u)

					repoPath, err := os.MkdirTemp("", ctx.Reponame)
					require.NoError(t, err)
					defer util.RemoveAll(repoPath)

					remoteRepoPath := path.Join(setting.RepoRootPath, ctx.GitPath())

					// This test is split up into separate withKeyFile()s
					// so it can isolate 'git annex copy' from 'git clone':
					//
					// 'clone' is done as the repo owner, to guarantee it
					// works, but 'copy' is done as the user under test.
					//
					// Otherwise, in cases where permissions block the
					// initial 'clone', the test would simply end there
					// and never verify if permissions apply properly to
					// 'annex copy' -- potentially leaving a security gap.
					withAnnexCtxKeyFile(t, ctx, func() {
						doGitClone(repoPath, repoURL)(t)
					})

					withAnnexCtxKeyFile(t, outsiderCtx, func() {
						t.Run("Init", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doAnnexInitTest(remoteRepoPath, repoPath))
						})

						t.Run("Download", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doAnnexDownloadTest(remoteRepoPath, repoPath))
						})

						t.Run("Upload", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.Error(t, doAnnexUploadTest(remoteRepoPath, repoPath), "Uploading should fail due to permissions")
						})
					})
				})
			})

			t.Run("Delete", func(t *testing.T) {
				defer PrintCurrentTest(t)()

				// Delete the repo, make sure it's fully gone
				doAPIDeleteRepository(ctx)(t)
				_, stat_err := os.Stat(path.Join(setting.RepoRootPath, ctx.GitPath()))
				require.True(t, os.IsNotExist(stat_err), "Remote annex repo should be removed from disk")
			})

			//fmt.Printf("Sleeping now. good luck.\n") // give time to allow manually inspecting the test server; the password for all users is 'password'!
			time.Sleep(0 * time.Second) // DEBUG
		})

		t.Run("Private", func(t *testing.T) {
			defer PrintCurrentTest(t)()

			// create a private repo
			ctx := NewAPITestContext(t, "user2", "annex-private")
			doAPICreateRepository(ctx, false)(t)

			// double-check it's private
			repo, err := repo_model.GetRepositoryByOwnerAndName(ctx.Username, ctx.Reponame)
			require.NoError(t, err)
			require.True(t, repo.IsPrivate)

			// fill in fixture data
			// TODO: replace this with a pre-made repo in integrations/gitea-repositories-meta/ ?
			withAnnexCtxKeyFile(t, ctx, func() {
				// note: this clone is immediately thrown away;
				// the tests below reclone it, to test end-to-end.
				repoPath, err := os.MkdirTemp("", ctx.Reponame)
				require.NoError(t, err)
				defer util.RemoveAll(repoPath)

				repoURL := createSSHUrl(ctx.GitPath(), u)
				doGitClone(repoPath, repoURL)(t)

				doInitAnnexRepository(t, repoPath)

				_, _, err = git.NewCommand(git.DefaultContext, "annex", "sync", "--content").RunStdString(&git.RunOpts{Dir: repoPath})
				require.NoError(t, err)
			})

			// Different sessions, so we can test different permissions.
			// We leave Reponame blank because we don't actually then later add it according to each case if needed
			//
			// NB: these usernames need to match appropriate entries in models/fixtures/user.yml
			ownerCtx := NewAPITestContext(t, ctx.Username, "")
			writerCtx := NewAPITestContext(t, "user5", "")
			readerCtx := NewAPITestContext(t, "user4", "")
			outsiderCtx := NewAPITestContext(t, "user8", "") // a user with no specific access
			// Note: there's also full anonymous access, which is only available for public HTTP repos;
			// it should behave the same as 'outsider' but we (will) test it separately below anyway

			//httpURL := createSSHUrl(ctx.GitPath(), u) // XXX this puts username and password into the URL
			// anonHTTPUrl := ???

			// set up collaborators
			doAPIAddCollaborator(ctx, readerCtx.Username, perm.AccessModeRead)(t)
			doAPIAddCollaborator(ctx, writerCtx.Username, perm.AccessModeWrite)(t)

			// tests
			t.Run("Owner", func(t *testing.T) {
				defer PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer PrintCurrentTest(t)()

					repoURL := createSSHUrl(ctx.GitPath(), u)

					repoPath, err := os.MkdirTemp("", ctx.Reponame)
					require.NoError(t, err)
					defer util.RemoveAll(repoPath)

					remoteRepoPath := path.Join(setting.RepoRootPath, ctx.GitPath())

					// This test is split up into separate withKeyFile()s
					// so it can isolate 'git annex copy' from 'git clone':
					//
					// 'clone' is done as the repo owner, to guarantee it
					// works, but 'copy' is done as the user under test.
					//
					// Otherwise, in cases where permissions block the
					// initial 'clone', the test would simply end there
					// and never verify if permissions apply properly to
					// 'annex copy' -- potentially leaving a security gap.
					withAnnexCtxKeyFile(t, ctx, func() {
						doGitClone(repoPath, repoURL)(t)
					})

					withAnnexCtxKeyFile(t, ownerCtx, func() {
						t.Run("Init", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doAnnexInitTest(remoteRepoPath, repoPath))
						})

						t.Run("Download", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doAnnexDownloadTest(remoteRepoPath, repoPath))
						})

						t.Run("Upload", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doAnnexUploadTest(remoteRepoPath, repoPath))
						})
					})
				})
			})

			t.Run("Writer", func(t *testing.T) {
				defer PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer PrintCurrentTest(t)()

					repoURL := createSSHUrl(ctx.GitPath(), u)

					repoPath, err := os.MkdirTemp("", ctx.Reponame)
					require.NoError(t, err)
					defer util.RemoveAll(repoPath)

					remoteRepoPath := path.Join(setting.RepoRootPath, ctx.GitPath())

					// This test is split up into separate withKeyFile()s
					// so it can isolate 'git annex copy' from 'git clone':
					//
					// 'clone' is done as the repo owner, to guarantee it
					// works, but 'copy' is done as the user under test.
					//
					// Otherwise, in cases where permissions block the
					// initial 'clone', the test would simply end there
					// and never verify if permissions apply properly to
					// 'annex copy' -- potentially leaving a security gap.
					withAnnexCtxKeyFile(t, ctx, func() {
						doGitClone(repoPath, repoURL)(t)
					})

					withAnnexCtxKeyFile(t, writerCtx, func() {
						t.Run("Init", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doAnnexInitTest(remoteRepoPath, repoPath))
						})

						t.Run("Download", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doAnnexDownloadTest(remoteRepoPath, repoPath))
						})

						t.Run("Upload", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doAnnexUploadTest(remoteRepoPath, repoPath))
						})
					})
				})
			})

			t.Run("Reader", func(t *testing.T) {
				defer PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer PrintCurrentTest(t)()

					repoURL := createSSHUrl(ctx.GitPath(), u)

					repoPath, err := os.MkdirTemp("", ctx.Reponame)
					require.NoError(t, err)
					defer util.RemoveAll(repoPath)

					remoteRepoPath := path.Join(setting.RepoRootPath, ctx.GitPath())

					// This test is split up into separate withKeyFile()s
					// so it can isolate 'git annex copy' from 'git clone':
					//
					// 'clone' is done as the repo owner, to guarantee it
					// works, but 'copy' is done as the user under test.
					//
					// Otherwise, in cases where permissions block the
					// initial 'clone', the test would simply end there
					// and never verify if permissions apply properly to
					// 'annex copy' -- potentially leaving a security gap.
					withAnnexCtxKeyFile(t, ctx, func() {
						doGitClone(repoPath, repoURL)(t)
					})

					withAnnexCtxKeyFile(t, readerCtx, func() {
						t.Run("Init", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doAnnexInitTest(remoteRepoPath, repoPath))
						})

						t.Run("Download", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.NoError(t, doAnnexDownloadTest(remoteRepoPath, repoPath))
						})

						t.Run("Upload", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.Error(t, doAnnexUploadTest(remoteRepoPath, repoPath), "Uploading should fail due to permissions")
						})
					})
				})
			})

			t.Run("Outsider", func(t *testing.T) {
				defer PrintCurrentTest(t)()

				t.Run("SSH", func(t *testing.T) {
					defer PrintCurrentTest(t)()

					repoURL := createSSHUrl(ctx.GitPath(), u)

					repoPath, err := os.MkdirTemp("", ctx.Reponame)
					require.NoError(t, err)
					defer util.RemoveAll(repoPath)

					remoteRepoPath := path.Join(setting.RepoRootPath, ctx.GitPath())

					// This test is split up into separate withKeyFile()s
					// so it can isolate 'git annex copy' from 'git clone':
					//
					// 'clone' is done as the repo owner, to guarantee it
					// works, but 'copy' is done as the user under test.
					//
					// Otherwise, in cases where permissions block the
					// initial 'clone', the test would simply end there
					// and never verify if permissions apply properly to
					// 'annex copy' -- potentially leaving a security gap.
					withAnnexCtxKeyFile(t, ctx, func() {
						doGitClone(repoPath, repoURL)(t)
					})

					withAnnexCtxKeyFile(t, outsiderCtx, func() {
						t.Run("Init", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.Error(t, doAnnexInitTest(remoteRepoPath, repoPath), "annex init should fail due to permissions")
						})

						t.Run("Download", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.Error(t, doAnnexDownloadTest(remoteRepoPath, repoPath), "annex copy --from should fail due to permissions")
						})

						t.Run("Upload", func(t *testing.T) {
							defer PrintCurrentTest(t)()

							require.Error(t, doAnnexUploadTest(remoteRepoPath, repoPath), "annex copy --to should fail due to permissions")
						})
					})
				})
			})

			t.Run("Delete", func(t *testing.T) {
				defer PrintCurrentTest(t)()

				// Delete the repo, make sure it's fully gone
				doAPIDeleteRepository(ctx)(t)
				_, stat_err := os.Stat(path.Join(setting.RepoRootPath, ctx.GitPath()))
				require.True(t, os.IsNotExist(stat_err), "Remote annex repo should be removed from disk")
			})

			//fmt.Printf("Sleeping now. good luck.\n") // give time to allow manually inspecting the test server; the password for all users is 'password'!
			time.Sleep(0 * time.Second) // DEBUG
		})
	})
}

/* test that 'git annex init' works

precondition: repoPath contains a pre-cloned git repo with a git-annex branch

*/
func doAnnexInitTest(remoteRepoPath string, repoPath string) (err error) {
	_, _, err = git.NewCommand(git.DefaultContext, "annex", "init").RunStdString(&git.RunOpts{Dir: repoPath})
	if err != nil {
		return err
	}

	// - method 0: 'git config remote.origin.annex-uuid'.
	//   Demonstrates that 'git annex init' successfully contacted
	//   the remote git-annex and was able to learn its ID number.
	readAnnexUUID, _, err := git.NewCommand(git.DefaultContext, "config", "remote.origin.annex-uuid").RunStdString(&git.RunOpts{Dir: repoPath})
	if err != nil {
		return err
	}
	readAnnexUUID = strings.TrimSpace(readAnnexUUID)

	match := regexp.MustCompile("^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$").MatchString(readAnnexUUID)
	if !match {
		return errors.New(fmt.Sprintf("'git config remote.origin.annex-uuid' should have been able to download the remote's uuid; but instead read '%s'.", readAnnexUUID))
	}

	remoteAnnexUUID, _, err := git.NewCommand(git.DefaultContext, "config", "annex.uuid").RunStdString(&git.RunOpts{Dir: remoteRepoPath})
	if err != nil {
		return err
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
		return err
	}
	match = regexp.MustCompile(regexp.QuoteMeta(remoteAnnexUUID) + " -- .* \\[origin\\]\n").MatchString(annexWhereis)
	if !match {
		return errors.New("'git annex whereis' should report large.bin is known to be in [origin]")
	}

	return nil
}

func doAnnexDownloadTest(remoteRepoPath string, repoPath string) (err error) {
	// NB: this test does something slightly different if run separately from "doAnnexInitTest()":
	//     it first runs "git annex init" silently in the background.
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

	match, err := filecmp(localObjectPath, remoteObjectPath, 0)
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

	match, err := filecmp(localObjectPath, remoteObjectPath, 0)
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

// ---- Annex-specific helpers ----

/* Initialize a repo with some baseline annexed and non-annexed files.

TODO: this could be replaced with a fixture repo;
see integrations/gitea-repositories-meta/ and models/fixtures/repository.yml.

However we reuse this template for -different- repos.
*/
func doInitAnnexRepository(t *testing.T, repoPath string) {
	// set up what files should be annexed
	// in this case, all *.bin  files will be annexed
	// without this, git-annex's default config annexes every file larger than some number of megabytes
	f, err := os.Create(path.Join(repoPath, ".gitattributes"))
	require.NoError(t, err)
	f.WriteString("*.bin  filter=annex annex.largefiles=anything")
	f.Close()
	require.NoError(t, git.AddChanges(repoPath, false, "."))
	require.NoError(t, git.CommitChanges(repoPath, git.CommitChangesOptions{Message: "Configure git-annex settings"}))

	// 'git annex init'
	// 'gitea-annex-test' is there to avoid the nuisance comment getting stored.
	require.NoError(t, git.NewCommand(git.DefaultContext, "annex", "init", "gitea-annex-test").Run(&git.RunOpts{Dir: repoPath}))

	// add a file to the annex
	require.NoError(t, generateRandomFile(1024*1024/4, path.Join(repoPath, "large.bin")))
	require.NoError(t, git.AddChanges(repoPath, false, "."))
	require.NoError(t, git.CommitChanges(repoPath, git.CommitChangesOptions{Message: "Annex a file"}))
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

/*
Do chmod -R +w $REPOS in order to handle https://git-annex.branchable.com/internals/lockdown/:

> (The only bad consequence of this is that rm -rf .git doesn't work unless you first run chmod -R +w .git)

Without, these tests can only be run once, because they reuse `gitea-repositories/`
folder and will balk at finding pre-existing partial repos.
*/
func annexUnlockdown() {
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

/* like withKeyFile(), but automatically sets it the account given in ctx for use by git-annex */
func withAnnexCtxKeyFile(t *testing.T, ctx APITestContext, callback func()) {
	os.Setenv("GIT_ANNEX_USE_GIT_SSH", "1") // withKeyFile works by setting GIT_SSH_COMMAND, but git-annex only respects that if this is set

	_gitAnnexUseGitSSH, gitAnnexUseGitSSHExists := os.LookupEnv("GIT_ANNEX_USE_GIT_SSH")
	defer func() {
		// reset
		if gitAnnexUseGitSSHExists {
			os.Setenv("GIT_ANNEX_USE_GIT_SSH", _gitAnnexUseGitSSH)
		}
	}()

	withCtxKeyFile(t, ctx, callback)
}
