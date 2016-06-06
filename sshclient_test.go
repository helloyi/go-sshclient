package sshclient

import (
	"bytes"
	"flag"
	"os"
	"testing"
)

var (
	addr   string
	user   string
	passwd string
	prikey string
)

func TestDailWithPasswd(t *testing.T) {
	client, err := DialWithPasswd(addr, user, passwd)
	if err != nil {
		t.Fatal("DialWithPasswd err: ", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal("client.Close err: ", err)
	}
}

func TestDailWithKey(t *testing.T) {
	client, err := DialWithKey(addr, user, prikey)
	if err != nil {
		t.Fatal("DialWithPasswd err: ", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal("client.Close err: ", err)
	}
}

func TestCmdRun(t *testing.T) {
	client, err := DialWithPasswd(addr, user, passwd)
	if err != nil {
		t.Fatal("DialWithPasswd err: ", err)
	}
	defer client.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err = client.Cmd("echo stdout").Cmd(">&2 echo stderr").SetStdio(&stdout, &stderr).Run()
	if err != nil {
		t.Fatal("Run command err: ", err)
	}

	if stdout.String() != "stdout\n" {
		t.Fatal("Command output mismatching on stdout")
	}
	if stderr.String() != "stderr\n" {
		t.Fatal("Command output mismatching on stderr")
	}
}

func TestScriptRun(t *testing.T) {
	client, err := DialWithPasswd(addr, user, passwd)
	if err != nil {
		t.Fatal("DialWithPasswd err: ", err)
	}
	defer client.Close()

	script := `
    echo stdout
    >&2 echo stderr
  `
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err = client.Script(script).SetStdio(&stdout, &stderr).Run()
	if err != nil {
		t.Fatal("Run command err: ", err)
	}
	if stdout.String() != "stdout\n" {
		t.Fatal("Command output mismatching on stdout")
	}
	if stderr.String() != "stderr\n" {
		t.Fatal("Command output mismatching on stderr")

	}
}

func TestScriptFileRun(t *testing.T) {
	client, err := DialWithPasswd(addr, user, passwd)
	if err != nil {
		t.Fatal("DialWithPasswd err: ", err)
	}
	defer client.Close()
}

func TestRemoteScriptOutput(t *testing.T) {
	client, err := DialWithPasswd(addr, user, passwd)
	if err != nil {
		t.Fatal("DialWithPasswd err: ", err)
	}
	defer client.Close()

	out, err := client.Cmd("echo a").Output()
	if err != nil {
		t.Fatal("Run command err: ", err)
	}
	if string(out) != "a\n" {
		t.Fatal("Command output mismatching on stdout")
	}
}

func TestRemoteScriptSmartOutput(t *testing.T) {
	client, err := DialWithPasswd(addr, user, passwd)
	if err != nil {
		t.Fatal("DialWithPasswd err: ", err)
	}
	defer client.Close()

	out, err := client.Cmd("echo a").SmartOutput()
	if err != nil {
		t.Fatal("Run command err: ", err)
	}
	if string(out) != "a\n" {
		t.Fatal("Command output mismatching on stdout")
	}

	script := `
    >&2 echo error
    exit 123
  `
	out, err = client.Script(script).SmartOutput()
	if err == nil {
		t.Fatal("Run script err")
	}
	if string(out) != "error\n" {
		t.Fatal("Command output mismatching on stderr")
	}
}

func TestShell(t *testing.T) {
	client, err := DialWithPasswd(addr, user, passwd)
	if err != nil {
		t.Fatal("DialWithPasswd err: ", err)
	}
	defer client.Close()

	script := bytes.NewBufferString("echo stdout\n  >&2 echo stderr")
	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)
	err = client.Shell().SetStdio(script, &stdout, &stderr).Start()
	if err != nil {
		t.Fatal("Start shell faield: ", err)
	}

	if stdout.String() != "stdout" == false {
		t.Fatal("Command output mismatching on stdout")
	}
	if stderr.String() != "stderr" == false {
		t.Fatal("Command output mismatching on stderr")
	}
}

func TestMain(m *testing.M) {
	flag.StringVar(&addr, "addr", "localhost:22", "The host of ssh")
	flag.StringVar(&user, "user", "username", "The user of login")
	flag.StringVar(&passwd, "passwd", "yourpasswd", "The passwd of user")
	flag.StringVar(&prikey, "privatekey", "/path/to/your/key", "The privatekey of user")

	flag.Parse()
	os.Exit(m.Run())
}
