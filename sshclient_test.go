package sshclient

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDailWithPasswd(t *testing.T) {
	user := "test"
	passwd := "test"
	listener := newLocalListener(t)
	addr := listener.Addr().String()

	srv := newTestServer(t, listener, user, passwd)
	defer srv.Shutdown(context.Background())

	cli, err := DialWithPasswd(addr, user, passwd)
	defer cli.Close()
	assert.NoError(t, err)
}

func newTestTerminalHandler(t *testing.T) ssh.Handler {
	return func(s ssh.Session) {
		ptyReq, winCh, isPty := s.Pty()
		if isPty {
			cmd := exec.Command("bash")
			cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
			close := func() {
				_, err := cmd.Process.Wait()
				s.Write([]byte{0})
				assert.NoError(t, err)
			}
			ptmx, err := pty.Start(cmd)
			assert.NoError(t, err)
			defer func() { _ = ptmx.Close() }() // Best effort.

			go func() {
				for win := range winCh {
					syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), uintptr(syscall.TIOCSWINSZ),
						uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(win.Height), uint16(win.Width), 0, 0})))
				}
			}()

			var once sync.Once
			go func() {
				_, err = io.Copy(ptmx, s)
				assert.NoError(t, err)
				once.Do(close)
			}()
			_, err = io.Copy(s, ptmx)
			assert.NoError(t, err)
			once.Do(close)
		} else {
			io.WriteString(s, "No PTY requested.\n")
			s.Exit(1)
		}
	}
}

func newTestCmdHandler(t *testing.T) ssh.Handler {
	return func(s ssh.Session) {
		rawCmd := s.RawCommand()
		cmd := exec.Command("bash", "-c", rawCmd)
		stdout, err := cmd.StdoutPipe()
		assert.NoError(t, err)
		stderr, err := cmd.StderrPipe()
		assert.NoError(t, err)

		err = cmd.Start()
		assert.NoError(t, err)

		data, err := ioutil.ReadAll(stdout)
		s.Write(data)
		data, err = ioutil.ReadAll(stderr)
		s.Stderr().Write(data)

		cmd.Wait()
	}
}

func newTestShellHandler(t *testing.T) ssh.Handler {
	return func(s ssh.Session) {
		script, err := ioutil.ReadAll(s)
		assert.NoError(t, err)
		cmd := exec.Command("bash", "-c", string(script))
		stdout, err := cmd.StdoutPipe()
		assert.NoError(t, err)
		stderr, err := cmd.StderrPipe()
		assert.NoError(t, err)

		err = cmd.Start()
		assert.NoError(t, err)

		data, err := ioutil.ReadAll(stdout)
		s.Write(data)
		data, err = ioutil.ReadAll(stderr)
		s.Stderr().Write(data)

		err = cmd.Wait()
		assert.NoError(t, err)
	}
}

func TestCmdRun(t *testing.T) {
	srv, cli := newSimpleTestServerAndClient(t)
	srv.Handler = newTestCmdHandler(t)

	defer srv.Shutdown(context.Background())
	defer cli.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := cli.Cmd("echo -n stdout").Cmd("echo -n stderr >&2").SetStdio(&stdout, &stderr).Run()
	assert.NoError(t, err)

	assert.Equal(t, "stdout", stdout.String())
	assert.Equal(t, "stderr", stderr.String())
}

func TestScriptRun(t *testing.T) {
	srv, cli := newSimpleTestServerAndClient(t)
	srv.Handler = newTestShellHandler(t)

	defer srv.Shutdown(context.Background())
	defer cli.Close()

	script := `
    echo -n stdout
    echo -n stderr >&2
  `
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := cli.Script(script).SetStdio(&stdout, &stderr).Run()
	assert.NoError(t, err)
	assert.Equal(t, "stdout", stdout.String())
	assert.Equal(t, "stderr", stderr.String())
}

func TestScriptFileRun(t *testing.T) {
	srv, cli := newSimpleTestServerAndClient(t)
	srv.Handler = newTestShellHandler(t)
	defer srv.Shutdown(context.Background())
	defer cli.Close()

	f, err := ioutil.TempFile("", "sshclient-test-script")
	assert.NoError(t, err)
	f.Write([]byte(`
echo -n stdout
echo -n stderr >&2
`))
	err = f.Close()
	assert.NoError(t, err)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cli.ScriptFile(f.Name()).SetStdio(&stdout, &stderr).Run()
	assert.NoError(t, err)
	assert.Equal(t, "stdout", stdout.String())
	assert.Equal(t, "stderr", stderr.String())
}

func TestClientCmdOutput(t *testing.T) {
	srv, cli := newSimpleTestServerAndClient(t)
	srv.Handler = newTestCmdHandler(t)
	defer srv.Shutdown(context.Background())
	defer cli.Close()

	out, err := cli.Cmd("echo -n a").Output()
	assert.NoError(t, err)
	assert.Equal(t, "a", string(out))
}

func TestClientCmdSmartOutput(t *testing.T) {
	srv, cli := newSimpleTestServerAndClient(t)
	srv.Handler = newTestCmdHandler(t)
	defer srv.Shutdown(context.Background())
	defer cli.Close()

	out, err := cli.Cmd("echo -n a && exit 125").SmartOutput()
	assert.NoError(t, err)
	assert.Equal(t, "a", string(out))
}

func TestClientShell(t *testing.T) {
	srv, cli := newSimpleTestServerAndClient(t)
	srv.Handler = newTestShellHandler(t)
	defer srv.Shutdown(context.Background())
	defer cli.Close()

	script := bytes.NewBufferString("echo -n stdout\n echo -n stderr >&2")
	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)
	err := cli.Shell().SetStdio(script, &stdout, &stderr).Start()
	assert.NoError(t, err)
	assert.Equal(t, "stdout", stdout.String())
	assert.Equal(t, "stderr", stderr.String())
}

func TestClientTerminal(t *testing.T) {
	srv, cli := newSimpleTestServerAndClient(t)
	srv.Handler = newTestTerminalHandler(t)
	defer srv.Shutdown(context.Background())
	defer cli.Close()

	var stdin bytes.Buffer
	stdoutr, stdoutw := io.Pipe()
	go func() {
		err := cli.Terminal(nil).SetStdio(&stdin, stdoutw, nil).Start()
		t.Log("client exit:", err)
	}()

	// NOTE: a zero time error exists
	today := time.Now().Format("20060102")
	stdin.Write([]byte("date +%Y%m%d\nexit\n"))
	stdout := bufio.NewReader(stdoutr)
	data, err := stdout.ReadBytes(0) // end with 0
	assert.NoError(t, err)
	assert.Contains(t, string(data), today)
}

func newTestClient(t *testing.T, addr, user, passwd string) *Client {
	cli, err := DialWithPasswd(addr, user, passwd)
	assert.Nilf(t, err, "new defaultClient error: %s\n", err)
	return cli
}

func newTestSftpHandler(t *testing.T) ssh.SubsystemHandler {
	return func(sess ssh.Session) {
		opts := []sftp.ServerOption{
			sftp.WithDebug(os.Stdout),
		}
		server, err := sftp.NewServer(sess, opts...)
		assert.Nilf(t, err, "sftp server init error: %s\n", err)
		if err := server.Serve(); err == io.EOF {
			server.Close()
		} else {
			assert.Nilf(t, err, "sftp server completed with error: %s\n", err)
		}
	}
}

func newTestServer(t *testing.T, listener net.Listener, user, password string) *ssh.Server {
	sshServer := &ssh.Server{
		PasswordHandler: func(ctx ssh.Context, passwd string) bool {
			return ctx.User() == user && passwd == password
		},
		SubsystemHandlers: map[string]ssh.SubsystemHandler{},
	}

	go func() {
		err := sshServer.Serve(listener)
		require.ErrorIs(t, err, ssh.ErrServerClosed)
		t.Log("sshServer exit:", err)
	}()

	return sshServer
}

func newLocalListener(t *testing.T) net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		l, err = net.Listen("tcp6", "[::1]:0")
		assert.Nil(t, err)
	}
	return l
}

func newSimpleTestServerAndClient(t *testing.T) (*ssh.Server, *Client) {
	user := "test"
	password := "test"

	listener := newLocalListener(t)
	addr := listener.Addr().String()

	srv := newTestServer(t, listener, user, password)
	cli := newTestClient(t, addr, user, password)

	return srv, cli
}

func newTestSftpServerAndClient(t *testing.T) (*ssh.Server, *Client) {
	user := "test"
	password := "test"

	listener := newLocalListener(t)
	addr := listener.Addr().String()

	srv := newTestServer(t, listener, user, password)
	srv.SubsystemHandlers["sftp"] = newTestSftpHandler(t)
	cli := newTestClient(t, addr, user, password)

	return srv, cli
}

func TestClientSftpGetwd(t *testing.T) {
	srv, cli := newTestSftpServerAndClient(t)
	defer srv.Shutdown(context.TODO())
	defer cli.Close()

	oswd, err := os.Getwd()
	assert.NoError(t, err)
	wd, err := cli.Sftp().Getwd()
	assert.NoError(t, err)
	assert.Equal(t, oswd, wd)
}

func TestClientSftpChmod(t *testing.T) {
	srv, cli := newTestSftpServerAndClient(t)
	defer srv.Shutdown(context.Background())
	defer cli.Close()

	f, err := ioutil.TempFile("", "sftptest-chmod")
	assert.NoError(t, err)
	f.Close()
	defer os.Remove(f.Name())

	err = cli.Sftp().Chmod(f.Name(), 0531)
	assert.NoError(t, err)

	stat, err := os.Stat(f.Name())
	assert.NoError(t, err)
	mode := stat.Mode() & os.ModePerm
	assert.EqualValues(t, 0531, mode)

	sf, err := cli.Sftp().Open(f.Name())
	assert.NoError(t, err)
	assert.NoError(t, sf.Chmod(0500))
	sf.Close()

	stat, err = os.Stat(f.Name())
	assert.NoError(t, err)
	mode = stat.Mode() & os.ModePerm
	assert.EqualValues(t, 0500, mode)
}

func TestClientSftpLstat(t *testing.T) {
	srv, cli := newTestSftpServerAndClient(t)
	defer srv.Shutdown(context.Background())
	defer cli.Close()

	f, err := ioutil.TempFile("", "sftptest-lstat")
	assert.NoError(t, err)
	f.Close()
	defer os.Remove(f.Name())

	expected, err := os.Lstat(f.Name())
	assert.NoError(t, err)

	actual, err := cli.Sftp().Lstat(f.Name())
	assert.NoError(t, err)

	assert.EqualValues(t, expected.Name(), actual.Name())
	assert.EqualValues(t, expected.Size(), actual.Size())
}

func TestClientSftpFileRead(t *testing.T) {
	srv, cli := newTestSftpServerAndClient(t)
	defer srv.Shutdown(context.Background())
	defer cli.Close()

	f, err := ioutil.TempFile("", "read-test")
	assert.NoError(t, err)
	fname := f.Name()
	defer os.RemoveAll(fname)
	f.Write([]byte("hello"))
	f.Close()

	f2, err := cli.Sftp().Open(fname)
	assert.NoError(t, err)
	defer f2.Close()

	stuff := make([]byte, 32)
	n, err := f2.Read(stuff)
	assert.ErrorIs(t, err, io.EOF)
	assert.Equal(t, 5, n)
	assert.Equal(t, "hello", string(stuff[0:5]))
}

func TestClientSftpUpload(t *testing.T) {
	srv, cli := newTestSftpServerAndClient(t)
	defer srv.Shutdown(context.Background())
	defer cli.Close()

	dir, err := ioutil.TempDir("", "sshclient-test-upload")
	assert.NoError(t, err)
	defer os.RemoveAll(dir)

	localFile, err := ioutil.TempFile(dir, "local")
	assert.NoError(t, err)
	localFile.Write([]byte("hello"))
	localFile.Close()

	remotePath := path.Join(dir, "remote")
	err = cli.Sftp().Upload(localFile.Name(), remotePath)
	assert.NoError(t, err)

	data, err := cli.Sftp().ReadFile(remotePath)
	assert.NoError(t, err)
	assert.Equal(t, "hello", string(data))
}

func TestClientSftpDowload(t *testing.T) {
	srv, cli := newTestSftpServerAndClient(t)
	defer srv.Shutdown(context.Background())
	defer cli.Close()

	dir, err := ioutil.TempDir("", "sshclient-test-upload")
	assert.NoError(t, err)
	defer os.RemoveAll(dir)

	remoteFile, err := ioutil.TempFile(dir, "remote")
	assert.NoError(t, err)
	remoteFile.Write([]byte("hello"))
	remoteFile.Close()

	hostPath := path.Join(dir, "local")
	err = cli.Sftp().Download(remoteFile.Name(), hostPath)
	assert.NoError(t, err)

	data, err := os.ReadFile(hostPath)
	assert.NoError(t, err)
	assert.Equal(t, "hello", string(data))
}
