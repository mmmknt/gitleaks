package scan

import (
	"context"

	"golang.org/x/sync/errgroup"

	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	log "github.com/sirupsen/logrus"
)

// RepoScanner is a repo scanner
type RepoScanner struct {
	opts     options.Options
	cfg      config.Config
	repo     *git.Repository
	throttle *Throttle
	repoName string
}

// NewRepoScanner returns a new repo scanner (go figure). This function also
// sets up the leak listener for multi-threaded awesomeness.
func NewRepoScanner(opts options.Options, cfg config.Config, repo *git.Repository) *RepoScanner {
	rs := &RepoScanner{
		opts:     opts,
		cfg:      cfg,
		repo:     repo,
		throttle: NewThrottle(opts),
		repoName: getRepoName(opts),
	}

	return rs
}

// Scan kicks of a repo scan
func (rs *RepoScanner) Scan() (Report, error) {
	log.Info("start RepoScanner Scan")
	log.Infof("Opts. Verbose: %v, Quiet: %v, RepoURL: %v, Path: %v, ConfigPath: %v, RepoConfigPath: %v, " +
		"ClonePath: %v, Version: %v, Username: %v, Threads: %v, Unstaged: %v, Branch: %v, " +
		"Redact: %v, Debug: %v, NoGit: %v, CodeOnLeak: %v, AppendRepoConfig: %v, AdditionalConfig: %v, " +
		"Report: %v, ReportFormat: %v, FilesAtCommit: %v, Commit: %v, Commits: %v, CommitsFile: %v, " +
		"CommitFrom: %v, CommitTo: %v, CommitSince: %v, CommitUntil: %v, Depth: %v",
		rs.opts.Verbose, rs.opts.Quiet, rs.opts.RepoURL, rs.opts.Path, rs.opts.ConfigPath, rs.opts.RepoConfigPath,
		rs.opts.ClonePath, rs.opts.Version, rs.opts.Username, rs.opts.Threads, rs.opts.Unstaged, rs.opts.Branch,
		rs.opts.Redact, rs.opts.Debug, rs.opts.NoGit, rs.opts.CodeOnLeak, rs.opts.AppendRepoConfig, rs.opts.AdditionalConfig,
		rs.opts.Report, rs.opts.ReportFormat, rs.opts.FilesAtCommit, rs.opts.Commit, rs.opts.Commits, rs.opts.CommitsFile,
		rs.opts.CommitFrom, rs.opts.CommitTo, rs.opts.CommitSince, rs.opts.CommitUntil, rs.opts.Depth)
	var (
		scannerReport Report
		commits       chan *object.Commit
	)
	logOpts, err := logOptions(rs.repo, rs.opts)
	if err != nil {
		return scannerReport, err
	}
	cIter, err := rs.repo.Log(logOpts)
	if err != nil {
		return scannerReport, err
	}

	g, _ := errgroup.WithContext(context.Background())
	commits = make(chan *object.Commit)
	leaks := make(chan Leak)

	commitNum := 0
	g.Go(func() error {
		defer close(commits)
		err = cIter.ForEach(func(c *object.Commit) error {
			log.Infof("start cIter target: %s", c.Hash.String())
			if c == nil || depthReached(commitNum, rs.opts) {
				return storer.ErrStop
			}

			if rs.cfg.Allowlist.CommitAllowed(c.Hash.String()) {
				return nil
			}
			commitNum++
			commits <- c
			log.Infof("send CommitScanner target: %s", c.Hash.String())
			if c.Hash.String() == rs.opts.CommitTo {
				return storer.ErrStop
			}

			return err
		})
		cIter.Close()
		return nil
	})

	for commit := range commits {
		c := commit
		log.Infof("receive CommitScanner target: %s", c.Hash.String())
		rs.throttle.Limit()
		g.Go(func() error {
			log.Infof("NewCommitScanner target: %s", c.Hash.String())
			commitScanner := NewCommitScanner(rs.opts, rs.cfg, rs.repo, c)
			commitScanner.SetRepoName(rs.repoName)
			report, err := commitScanner.Scan()
			rs.throttle.Release()
			if err != nil {
				log.Error(err)
			}
			for _, leak := range report.Leaks {
				leaks <- leak
			}
			return nil
		})
	}

	go func() {
		if err := g.Wait(); err != nil {
			log.Error(err)
		}
		close(leaks)
	}()

	for leak := range leaks {
		scannerReport.Leaks = append(scannerReport.Leaks, leak)
	}

	scannerReport.Commits = commitNum
	return scannerReport, g.Wait()
}

// SetRepoName sets the repo name
func (rs *RepoScanner) SetRepoName(repoName string) {
	rs.repoName = repoName
}
