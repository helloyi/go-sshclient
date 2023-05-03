// Package sshclient implements an SSH client.
package sshclient

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"sync"
	"time"

	"github.com/kr/fs"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type remoteScriptType byte
type remoteShellType byte

const (
	cmdLine remoteScriptType = iota
	rawScript
	scriptFile

	interactiveShell remoteShellType = iota
	nonInteractiveShell
)

// A Client implements an SSH client that supports running commands and scripts remotely.
type Client struct {
	sshClient    *ssh.Client
	sftpSessions sync.Map
}

// DialWithPasswd starts a client connection to the given SSH server with passwd authmethod.
func DialWithPasswd(addr, user, passwd string) (*Client, error) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(passwd),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	return Dial("tcp", addr, config)
}

// DialWithKey starts a client connection to the given SSH server with key authmethod.
func DialWithKey(addr, user, keyfile string) (*Client, error) {
	key, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	return Dial("tcp", addr, config)
}

// DialWithKeyWithPassphrase same as DialWithKey but with a passphrase to decrypt the private key
func DialWithKeyWithPassphrase(addr, user, keyfile string, passphrase string) (*Client, error) {
	key, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	return Dial("tcp", addr, config)
}

// Dial starts a client connection to the given SSH server.
// This wraps ssh.Dial.
func Dial(network, addr string, config *ssh.ClientConfig) (*Client, error) {
	sshClient, err := ssh.Dial(network, addr, config)
	if err != nil {
		return nil, err
	}

	return &Client{sshClient: sshClient}, nil
}

// Close closes the underlying client network connection.
func (c *Client) Close() error {
	merr := newMultiError()
	c.sftpSessions.Range(func(key, value interface{}) bool {
		err := value.(*RemoteFileSystem).Close()
		merr.Append(err)
		return true
	})
	merr.Append(c.sshClient.Close())
	return merr.ErrorOrNil()
}

// UnderlyingClient get the underlying client.
func (c *Client) UnderlyingClient() *ssh.Client {
	return c.sshClient
}

// Dial initiates a Client to the addr from the remote host.
func (c *Client) Dial(network, addr string, config *ssh.ClientConfig) (*Client, error) {
	conn, err := c.sshClient.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return nil, err
	}

	client := ssh.NewClient(sshConn, chans, reqs)

	return &Client{sshClient: client}, nil
}

// DialWithPasswd initiates a Client to the addr from the remote host with passwd authmethod.
func (c *Client) DialWithPasswd(addr, user, passwd string) (*Client, error) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(passwd),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	return c.Dial("tcp", addr, config)
}

// DialWithKey initiates a Client to the addr from the remote host with key authmethod.
func (c *Client) DialWithKey(addr, user, keyfile string) (*Client, error) {
	key, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	return c.Dial("tcp", addr, config)
}

// DialWithKeyWithPassphrase same as DialWithKey but with a passphrase to decrypt the private key
func (c *Client) DialWithKeyWithPassphrase(addr, user, keyfile, passphrase string) (*Client, error) {
	key, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	return c.Dial("tcp", addr, config)
}

// Cmd creates a RemoteScript that can run the command on the client. The cmd string is split on newlines and each line is executed separately.
func (c *Client) Cmd(cmd string) *RemoteScript {
	return &RemoteScript{
		_type:  cmdLine,
		client: c.sshClient,
		script: bytes.NewBufferString(cmd + "\n"),
	}
}

// Script creates a RemoteScript that can run the script on the client.
func (c *Client) Script(script string) *RemoteScript {
	return &RemoteScript{
		_type:  rawScript,
		client: c.sshClient,
		script: bytes.NewBufferString(script + "\n"),
	}
}

// ScriptFile creates a RemoteScript that can read a local script file and run it remotely on the client.
func (c *Client) ScriptFile(fname string) *RemoteScript {
	return &RemoteScript{
		_type:      scriptFile,
		client:     c.sshClient,
		scriptFile: fname,
	}
}

// A RemoteScript represents script that can be run remotely.
type RemoteScript struct {
	client     *ssh.Client
	_type      remoteScriptType
	script     *bytes.Buffer
	scriptFile string
	err        error

	stdout io.Writer
	stderr io.Writer
}

// Run runs the script on the client.
//
// The returned error is nil if the command runs, has no problems
// copying stdin, stdout, and stderr, and exits with a zero exit
// status.
func (rs *RemoteScript) Run() error {
	if rs.err != nil {
		fmt.Println(rs.err) // TODO
		return rs.err
	}

	if rs._type == cmdLine {
		return rs.runCmds()
	} else if rs._type == rawScript {
		return rs.runScript()
	} else if rs._type == scriptFile {
		return rs.runScriptFile()
	} else {
		return errors.New("Not supported RemoteScript type")
	}
}

// Output runs the script on the client and returns its standard output.
func (rs *RemoteScript) Output() ([]byte, error) {
	if rs.stdout != nil {
		return nil, errors.New("Stdout already set")
	}
	var out bytes.Buffer
	rs.stdout = &out
	err := rs.Run()
	return out.Bytes(), err
}

// SmartOutput runs the script on the client. On success, its standard ouput is returned. On error, its standard error is returned.
func (rs *RemoteScript) SmartOutput() ([]byte, error) {
	if rs.stdout != nil {
		return nil, errors.New("Stdout already set")
	}
	if rs.stderr != nil {
		return nil, errors.New("Stderr already set")
	}

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)
	rs.stdout = &stdout
	rs.stderr = &stderr
	err := rs.Run()
	if err != nil {
		return stderr.Bytes(), err
	}
	return stdout.Bytes(), err
}

// Cmd appends a command to the RemoteScript.
func (rs *RemoteScript) Cmd(cmd string) *RemoteScript {
	_, err := rs.script.WriteString(cmd + "\n")
	if err != nil {
		rs.err = err
	}
	return rs
}

// SetStdio specifies where its standard output and error data will be written.
func (rs *RemoteScript) SetStdio(stdout, stderr io.Writer) *RemoteScript {
	rs.stdout = stdout
	rs.stderr = stderr
	return rs
}

func (rs *RemoteScript) runCmd(cmd string) error {
	session, err := rs.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	session.Stdout = rs.stdout
	session.Stderr = rs.stderr

	if err := session.Run(cmd); err != nil {
		return err
	}
	return nil
}

func (rs *RemoteScript) runCmds() error {
	for {
		statment, err := rs.script.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if err := rs.runCmd(statment); err != nil {
			return err
		}
	}

	return nil
}

func (rs *RemoteScript) runScript() error {
	session, err := rs.client.NewSession()
	if err != nil {
		return err
	}

	session.Stdin = rs.script
	session.Stdout = rs.stdout
	session.Stderr = rs.stderr

	if err := session.Shell(); err != nil {
		return err
	}
	if err := session.Wait(); err != nil {
		return err
	}

	return nil
}

func (rs *RemoteScript) runScriptFile() error {
	var buffer bytes.Buffer
	file, err := os.Open(rs.scriptFile)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(&buffer, file)
	if err != nil {
		return err
	}

	rs.script = &buffer
	return rs.runScript()
}

// A RemoteShell represents a login shell on the client.
type RemoteShell struct {
	client         *ssh.Client
	requestPty     bool
	terminalConfig *TerminalConfig

	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

// A TerminalConfig represents the configuration for an interactive shell session.
type TerminalConfig struct {
	Term   string
	Height int
	Weight int
	Modes  ssh.TerminalModes
}

// Terminal create a interactive shell on client.
func (c *Client) Terminal(config *TerminalConfig) *RemoteShell {
	return &RemoteShell{
		client:         c.sshClient,
		terminalConfig: config,
		requestPty:     true,
	}
}

// Shell create a noninteractive shell on client.
func (c *Client) Shell() *RemoteShell {
	return &RemoteShell{
		client:     c.sshClient,
		requestPty: false,
	}
}

// SetStdio specifies where the its standard output and error data will be written.
func (rs *RemoteShell) SetStdio(stdin io.Reader, stdout, stderr io.Writer) *RemoteShell {
	rs.stdin = stdin
	rs.stdout = stdout
	rs.stderr = stderr
	return rs
}

// Start starts a remote shell on client.
func (rs *RemoteShell) Start() error {
	session, err := rs.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	if rs.stdin == nil {
		session.Stdin = os.Stdin
	} else {
		session.Stdin = rs.stdin
	}
	if rs.stdout == nil {
		session.Stdout = os.Stdout
	} else {
		session.Stdout = rs.stdout
	}
	if rs.stderr == nil {
		session.Stderr = os.Stderr
	} else {
		session.Stderr = rs.stderr
	}

	if rs.requestPty {
		tc := rs.terminalConfig
		if tc == nil {
			tc = &TerminalConfig{
				Term:   "xterm",
				Height: 40,
				Weight: 80,
			}
		}
		if err := session.RequestPty(tc.Term, tc.Height, tc.Weight, tc.Modes); err != nil {
			return err
		}
	}

	if err := session.Shell(); err != nil {
		return err
	}

	if err := session.Wait(); err != nil {
		return err
	}

	return nil
}

// RemoteFileSystem represents a remoote file system.
type RemoteFileSystem struct {
	sftp *sftp.Client
	err  error

	config remoteFileSystemConfig
	opts   []sftp.ClientOption

	cli *Client
}

// RemoteFile represents a remote file.
type RemoteFile struct {
	*sftp.File
}

// Sftp creates a new SFTP session, using zero or more option functions.
func (c *Client) Sftp(opts ...SftpOption) *RemoteFileSystem {
	config := remoteFileSystemConfig{-1, -1, -1, -1, -1}
	for _, opt := range opts {
		opt(&config)
	}

	rawRfs, ok := c.sftpSessions.Load(config)
	if ok {
		return rawRfs.(*RemoteFileSystem)
	}

	sftpClient, err := sftp.NewClient(c.sshClient, config.sftpClientOptions()...)
	rfs := &RemoteFileSystem{
		config: config,
		sftp:   sftpClient,
		cli:    c,
		err:    err,
	}

	if rfs.err == nil {
		c.sftpSessions.Store(rfs.config, rfs)
	}

	return rfs
}

// Close closes the SFTP session.
func (rfs *RemoteFileSystem) Close() error {
	if rfs.err != nil {
		return rfs.err
	}

	rfs.cli.sftpSessions.Delete(rfs.config)

	return rfs.sftp.Close()
}

func (rfs *RemoteFileSystem) Chmod(path string, mode os.FileMode) error {
	if rfs.err != nil {
		return rfs.err
	}

	return rfs.sftp.Chmod(path, mode)
}

func (rfs *RemoteFileSystem) Chown(path string, uid, gid int) error {
	if rfs.err != nil {
		return rfs.err
	}

	return rfs.sftp.Chown(path, uid, gid)
}

func (rfs *RemoteFileSystem) Chtimes(path string, atime time.Time, mtime time.Time) error {
	if rfs.err != nil {
		return rfs.err
	}

	return rfs.sftp.Chtimes(path, atime, mtime)
}

func (rfs *RemoteFileSystem) Create(path string) (*RemoteFile, error) {
	if rfs.err != nil {
		return nil, rfs.err
	}

	file, err := rfs.sftp.Create(path)
	if err != nil {
		return nil, err
	}

	return &RemoteFile{file}, nil
}

func (rfs *RemoteFileSystem) Getwd() (string, error) {
	if rfs.err != nil {
		return "", rfs.err
	}

	return rfs.sftp.Getwd()
}

func (rfs *RemoteFileSystem) Glob(pattern string) (matches []string, err error) {
	if rfs.err != nil {
		return nil, rfs.err
	}

	return rfs.sftp.Glob(pattern)
}

func (rfs *RemoteFileSystem) Link(oldname, newname string) error {
	if rfs.err != nil {
		return rfs.err
	}

	return rfs.sftp.Link(oldname, newname)
}

func (rfs *RemoteFileSystem) Lstat(path string) (os.FileInfo, error) {
	if rfs.err != nil {
		return nil, rfs.err
	}

	return rfs.sftp.Lstat(path)
}

func (rfs *RemoteFileSystem) Mkdir(path string) error {
	if rfs.err != nil {
		return rfs.err
	}

	return rfs.sftp.Mkdir(path)
}

func (rfs *RemoteFileSystem) MkdirAll(path string) error {
	if rfs.err != nil {
		return rfs.err
	}

	return rfs.sftp.MkdirAll(path)
}

func (rfs *RemoteFileSystem) Open(path string) (*RemoteFile, error) {
	if rfs.err != nil {
		return nil, rfs.err
	}

	file, err := rfs.sftp.Open(path)
	if err != nil {
		return nil, err
	}

	return &RemoteFile{file}, nil
}

func (rfs *RemoteFileSystem) OpenFile(path string, f int) (*RemoteFile, error) {
	if rfs.err != nil {
		return nil, rfs.err
	}

	file, err := rfs.sftp.OpenFile(path, f)
	if err != nil {
		return nil, err
	}

	return &RemoteFile{file}, nil
}

func (rfs *RemoteFileSystem) PosixRename(oldname, newname string) error {
	if rfs.err != nil {
		return rfs.err
	}

	return rfs.sftp.PosixRename(oldname, newname)
}

func (rfs *RemoteFileSystem) ReadDir(path string) ([]os.FileInfo, error) {
	if rfs.err != nil {
		return nil, rfs.err
	}

	return rfs.sftp.ReadDir(path)
}

func (rfs *RemoteFileSystem) ReadLink(path string) (string, error) {
	if rfs.err != nil {
		return "", rfs.err
	}

	return rfs.sftp.ReadLink(path)
}

func (rfs *RemoteFileSystem) RealPath(path string) (string, error) {
	if rfs.err != nil {
		return "", rfs.err
	}

	return rfs.sftp.RealPath(path)
}

func (rfs *RemoteFileSystem) Remove(path string) error {
	if rfs.err != nil {
		return rfs.err
	}

	return rfs.sftp.Remove(path)
}

func (rfs *RemoteFileSystem) RemoveDirectory(path string) error {
	if rfs.err != nil {
		return rfs.err
	}

	return rfs.sftp.RemoveDirectory(path)
}

func (rfs *RemoteFileSystem) Rename(oldname, newname string) error {
	if rfs.err != nil {
		return rfs.err
	}

	return rfs.sftp.Rename(oldname, newname)
}

func (rfs *RemoteFileSystem) Stat(path string) (os.FileInfo, error) {
	if rfs.err != nil {
		return nil, rfs.err
	}

	return rfs.sftp.Stat(path)
}

type StatVFS struct {
	*sftp.StatVFS
}

func (rfs *RemoteFileSystem) StatVFS(path string) (*StatVFS, error) {
	if rfs.err != nil {
		return nil, rfs.err
	}

	stat, err := rfs.sftp.StatVFS(path)
	if err != nil {
		return nil, err
	}

	return &StatVFS{stat}, nil
}

func (rfs *RemoteFileSystem) Symlink(oldname, newname string) error {
	if rfs.err != nil {
		return rfs.err
	}

	return rfs.sftp.Symlink(oldname, newname)
}

func (rfs *RemoteFileSystem) Truncate(path string, size int64) error {
	if rfs.err != nil {
		return rfs.err
	}

	return rfs.sftp.Truncate(path, size)
}

func (rfs *RemoteFileSystem) Wait() error {
	if rfs.err != nil {
		return rfs.err
	}

	return rfs.sftp.Wait()
}

func (rfs *RemoteFileSystem) Walk(root string) (*fs.Walker, error) {
	if rfs.err != nil {
		return nil, rfs.err
	}

	return rfs.sftp.Walk(root), nil
}

func (rfs *RemoteFileSystem) Upload(hostPath, remotePath string) (retErr error) {
	if rfs.err != nil {
		return rfs.err
	}

	multierr := newMultiError()
	defer func() {
		retErr = multierr.ErrorOrNil()
	}()

	hostFile, err := os.Open(hostPath)
	if err != nil {
		return multierr.Append(err)
	}
	defer multierr.AppendErrFunc(hostFile.Close)

	remoteFile, err := rfs.sftp.OpenFile(remotePath, os.O_CREATE|os.O_WRONLY)
	if err != nil {
		return multierr.Append(err)
	}
	defer multierr.AppendErrFunc(remoteFile.Close)

	_, err = remoteFile.ReadFrom(hostFile)
	return multierr.Append(err)
}

func (rfs *RemoteFileSystem) Download(remotePath, hostPath string) (retErr error) {
	if rfs.err != nil {
		return rfs.err
	}

	multierr := newMultiError()
	defer func() {
		retErr = multierr.ErrorOrNil()
	}()

	remoteFile, err := rfs.sftp.Open(remotePath)
	if err != nil {
		return multierr.Append(err)
	}
	defer multierr.AppendErrFunc(remoteFile.Close)

	hostFile, err := os.OpenFile(hostPath, os.O_CREATE|os.O_WRONLY, os.ModeAppend|os.ModePerm)
	if err != nil {
		return multierr.Append(err)
	}
	defer multierr.AppendErrFunc(hostFile.Close)

	_, err = remoteFile.WriteTo(hostFile)
	return multierr.Append(err)
}

func (rfs *RemoteFileSystem) ReadFile(name string) ([]byte, error) {
	if rfs.err != nil {
		return nil, rfs.err
	}

	f, err := rfs.sftp.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var size int
	if info, err := f.Stat(); err == nil {
		size64 := info.Size()
		if int64(int(size64)) == size64 {
			size = int(size64)
		}
	}
	size++ // one byte for final read at EOF

	// If a file claims a small size, read at least 512 bytes.
	// In particular, files in Linux's /proc claim size 0 but
	// then do not work right if read in small pieces,
	// so an initial read of 1 byte would not work correctly.
	if size < 512 {
		size = 512
	}

	data := make([]byte, 0, size)
	for {
		if len(data) >= cap(data) {
			d := append(data[:cap(data)], 0)
			data = d[:len(data)]
		}
		n, err := f.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return data, err
		}
	}
}

func (rfs *RemoteFileSystem) WriteFile(name string, data []byte, perm os.FileMode) error {
	if rfs.err != nil {
		return rfs.err
	}

	f, err := rfs.sftp.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
	}
	return err
}
