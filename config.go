package sshclient

import (
	"github.com/pkg/sftp"
)

type remoteFileSystemConfig struct {
	maxConcurrentRequestsPerFile int
	maxPacket                    int
	useConcurrentReads           int8
	useConcurrentWrites          int8
	useFstat                     int8
}

type SftpOption func(*remoteFileSystemConfig)

func SftpMaxConcurrentRequestsPerFile(n int) SftpOption {
	return func(config *remoteFileSystemConfig) {
		config.maxConcurrentRequestsPerFile = n
	}
}

func SftpMaxPacket(size int) SftpOption {
	return func(config *remoteFileSystemConfig) {
		config.maxPacket = size
	}
}

func SftpUseConcurrentReads(value bool) SftpOption {
	return func(config *remoteFileSystemConfig) {
		if value {
			config.useConcurrentReads = 1
		} else {
			config.useConcurrentReads = 0
		}
	}
}

func SftpUseConcurrentWrites(value bool) SftpOption {
	return func(config *remoteFileSystemConfig) {
		if value {
			config.useConcurrentWrites = 1
		} else {
			config.useConcurrentWrites = 0
		}
	}
}

func SftpUseFstat(value bool) SftpOption {
	return func(config *remoteFileSystemConfig) {
		if value {
			config.useFstat = 1
		} else {
			config.useFstat = 0
		}
	}
}

func (rfsc *remoteFileSystemConfig) sftpClientOptions() []sftp.ClientOption {
	opts := make([]sftp.ClientOption, 0, 5)

	if v := rfsc.maxConcurrentRequestsPerFile; v != -1 {
		opts = append(opts, sftp.MaxConcurrentRequestsPerFile(v))
	}
	if v := rfsc.maxPacket; v != -1 {
		opts = append(opts, sftp.MaxPacket(v))
	}
	if v := rfsc.useConcurrentReads; v != -1 {
		opts = append(opts, sftp.UseConcurrentReads(v == 1))
	}
	if v := rfsc.useConcurrentWrites; v != -1 {
		opts = append(opts, sftp.UseConcurrentWrites(v == 1))
	}
	if v := rfsc.useFstat; v != -1 {
		opts = append(opts, sftp.UseFstat(v == 1))
	}

	return opts
}
