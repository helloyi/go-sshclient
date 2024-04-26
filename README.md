# simple sshclient with golang

[![GoDoc](https://godoc.org/github.com/helloyi/go-sshclient?status.svg)](https://godoc.org/github.com/helloyi/go-sshclient)

This package implemented a ssh client. It can run remote command, execute
remote script, request terminal and request non-interactive shell simply.

## install package

```shell
# The -u flag instructs get to update modules providing dependencies
# of packages named on the command line to use newer minor or patch
# releases when available.
go get -u github.com/helloyi/go-sshclient
```

## create a ssh client

+ Dial with passwd

```go
client, err := DialWithPasswd("host:port", "username", "passwd")
if err != nil {
  handleErr(err)
}
defer client.Close()
```

+ Dial with private key

```go
client, err := DialWithKey("host:port", "username", "prikeyFile")
if err != nil {
  handleErr(err)
}
defer client.Close()
```

+ Dial with private key and a passphrase to decrypt the key

```go
client, err := DialWithKeyWithPassphrase("host:port", "username", "prikeyFile", "my-passphrase"))
if err != nil {
  handleErr(err)
}
defer client.Close()
```

+ Dial

```go
config := &ssh.ClientConfig{
	User: user,
	Auth: []ssh.AuthMethod{
		ssh.Password("yourpasswd"),
	},
}
client, err := Dial("network", "host:port", config)
if err != nil {
  handleErr(err)
}
defer client.Close()
```

+ Dial from remote host

[To PR](https://github.com/helloyi/go-sshclient/pull/13)

```go
client0, err := Dial("tcp", "host:port", config{})
if err != nil {
  handleErr(err)
}
defer client0.Close()

client, err := client0.Dail("tcp", "host:port", config{})
if err != nil {
  handleErr(err)
}
defer client.Close()
```

+ Dial by SOCKS5 proxy

```go
client, err := DialWithPasswd(addr, user, passwd, WithDialFuncOption(func(network string, address string) (net.Conn, error) {
    // get proxy address from env or config
    proxyAddress := os.Getenv("socks5_proxy")
    dial, err := proxy.SOCKS5(network, proxyAddress, nil, nil)
    if err != nil {
        t.Fatal(err)
    }
    c, err := dial.Dial(network, address)
    return c, err
}))
if err != nil {
    handleErr(err)
}
defer client.Close()
```

## execute commmand

+ Don't care about output, calling Run

```go
// run one command
if err := client.Cmd("cmd").Run(); err {
  handleErr(err)
}

// run muti command one time
// if there is a command run err, and the next commands will not run
if err := client.Cmd("cmd1").Cmd("cmd2").Cmd("cmd3").Run(); err != nil {
  handleErr(err)
}
```

+ Get output, calling Output

```go
out, err := client.Cmd("cmd").Output()
if err != nil {
  handleErr(err)
}
fmt.Println(string(out))
```

+ Return stderr message, when execution error, calling SmartOutput

```go
out, err := client.Cmd("cmd").SmartOutput()
if err != nil {
  // the 'out' is stderr output
  handleErr(err, out)
}
// the 'out' is stdout output
fmt.Println(string(out))
```

+ Write stdout and stderr to your buffer, calling SetStdio

```go
var (
  stdout bytes.Buffer
  stderr bytes.Buffer
)

if err := client.Cmd("cmd").SetStdio(&stdout, &stderr).Run(); err {
  handleErr(err)
}

// get it
fmt.Println(string(stdout))
fmt.Println(string(stderr))
```

## execute script

+ Run script

```go
script = `
  statment1
  statment2
`

// It's as same as Cmd
client.Script(script).Run()
client.Script(script).Output()
client.Script(script).SmartOutput()
```

+ Run a shell script file

```go
client.ScriptFile("/path/to/the/script").Run()
client.ScriptFile("/path/to/the/script").Output()
client.ScriptFile("/path/to/the/script").SmartOutput()
```

## get shell

+ Get a non-interactive shell

```go
if err := client.Shell().Start(); err != nil {
  handleErr(err)
}
```

+ Get a interactive shell

```go
// default terminal
if err := client.Terminal(nil).Start(); err != nil {
  handleErr(err)
}

// with a terminal config
config := &sshclient.TerminalConfig {
  Term: "xterm",
  Height: 40,
  Weight: 80,
  Modes: ssh.TerminalModes {
	  ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
	  ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
  }
}
if err := client.Terminal(config).Start(); err != nil {
  handleErr(err)
}
```

+ And sometimes, you could set your stdio buffer

```go
var (
  stdin  bytes.Buffer
  stdout bytes.Buffer
  stderr bytes.Buffer
)

// Now, it's like client.Script("script").Run()
stdin.NewBufferString("script")
if err := client.Shell().SetStdio(&stdin, &stdout, &stderr).Start(); err != nil {
  handleErr(err)
}

fmt.Println(stdout.String())
fmt.Println(stderr.String())
```



## remote file operations

Use  `sftp := client.Sftp()` to obtain a `RemoteFileSystem`. Use `sftp.Closer()` to close it after use, `sftp` can be passively closed using the `client.Close()` if it is used during the client lifetime. 

Because it is designed to have a one-to-one configuration-to-instance relationship, you can obtain the same `RemoteFileSystem` everywhere with the same configuration. Here is an example of the code:

```go
// The following are the same Sftp specified by opts
opts := []client.SftpOption{client.SftpMaxPacket(16384)}
wd, err := client.Sftp(opts...).Getwd()
// ...
err := client.Sftp(opts...).Mkdir("path")
// ...
client.Sftp(opts...).Close()
```



### upload file

+ Get a RemoteFileSystem

```go
sftp := client.Sftp()
```

+ Then upload local file to remote

```go
// upload
if err := sftp.Upload("host/file/path"，"remote/file/path"); err != nil {
  handleErr(err)
}
```

+ Close RemoteFileSystem

```go
if err := sftp.Close(); err != nil {
  handleErr(err)
}
```

