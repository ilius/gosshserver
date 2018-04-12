// Copyright 2018 Saeed Rasooli
// Copyright 2014 The Gogs Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package gosshserver

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"

	"log"

	"github.com/Unknwon/com"
	"github.com/google/shlex"
	"golang.org/x/crypto/ssh"
)

var DefaultCiphers = []string{
	"chacha20-poly1305@openssh.com",
	"aes128-ctr", "aes192-ctr", "aes256-ctr",
	"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
	"aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc",
}

func cleanCommand(cmd string) string {
	i := strings.Index(cmd, "git")
	if i == -1 {
		return cmd
	}
	return cmd[i:]
}

func handleServerConn(keyID string, chans <-chan ssh.NewChannel) {
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		ch, reqs, err := newChan.Accept()
		if err != nil {
			log.Println("Error accepting channel:", err)
			continue
		}

		go func(in <-chan *ssh.Request) {
			defer ch.Close()
			for req := range in {
				payload := cleanCommand(string(req.Payload))
				switch req.Type {
				case "env":
					args := strings.Split(strings.Replace(payload, "\x00", "", -1), "\v")
					if len(args) < 2 {
						log.Printf("Warning: SSH: Invalid env arguments: %#v\n", args)
						continue
					}
					if args[0] == "" {
						args = args[1:]
					}
					if len(args) != 2 {
						log.Printf("Warning: SSH: Invalid env arguments: %#v\n", args)
						continue
					}
					args[0] = strings.TrimLeft(args[0], "\x04")
					_, _, err := com.ExecCmdBytes("env", args[0]+"="+args[1])
					if err != nil {
						log.Println("env:", err)
						return
					}
				case "exec":
					cmdStringFull := strings.TrimLeft(payload, "'()")
					fmt.Printf("SSH: Payload: cmdStringFull = %#v\n", cmdStringFull)
					cmdParts, err := shlex.Split(cmdStringFull)
					if err != nil {
						log.Println("SSH: Error in parsing command:", cmdStringFull)
						return
					}

					cmd := exec.Command(cmdParts[0], cmdParts[1:]...)

					stdout, err := cmd.StdoutPipe()
					if err != nil {
						log.Println("SSH: StdoutPipe:", err)
						return
					}
					stderr, err := cmd.StderrPipe()
					if err != nil {
						log.Println("SSH: StderrPipe:", err)
						return
					}
					input, err := cmd.StdinPipe()
					if err != nil {
						log.Println("SSH: StdinPipe:", err)
						return
					}

					// FIXME: check timeout
					if err = cmd.Start(); err != nil {
						log.Println("SSH: Start:", err)
						return
					}

					req.Reply(true, nil)
					go io.Copy(input, ch)
					io.Copy(ch, stdout)
					io.Copy(ch.Stderr(), stderr)

					if err = cmd.Wait(); err != nil {
						log.Println("SSH: Wait:", err)
						return
					}

					ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
					return
				default:
				}
			}
		}(reqs)
	}
}

func listen(config *ssh.ServerConfig, host string, port string) {
	listener, err := net.Listen("tcp", host+":"+port)
	if err != nil {
		log.Fatal(4, "Fail to start SSH server: %v", err)
	}
	for {
		// Once a ServerConfig has been configured, connections can be accepted.
		conn, err := listener.Accept()
		if err != nil {
			log.Println("SSH: Error accepting incoming connection:", err)
			continue
		}

		// Before use, a handshake must be performed on the incoming net.Conn.
		// It must be handled in a separate goroutine,
		// otherwise one user could easily block entire loop.
		// For example, user could be asked to trust server key fingerprint and hangs.
		go func() {
			fmt.Println("SSH: Handshaking for", conn.RemoteAddr())
			sConn, chans, reqs, err := ssh.NewServerConn(conn, config)
			if err != nil {
				if err == io.EOF {
					log.Println("Waring: SSH: Handshaking was terminated:", err)
				} else {
					log.Println("SSH: Error on handshaking:", err)
				}
				return
			}

			fmt.Printf("SSH: Connection from %s (%s)\n", sConn.RemoteAddr(), sConn.ClientVersion())
			// The incoming Request channel must be serviced.
			go ssh.DiscardRequests(reqs)
			go handleServerConn(sConn.Permissions.Extensions["key-id"], chans)
		}()
	}
}

// used for logging only
func getStrippedPublicKey(key ssh.PublicKey) string {
	keyBytes := key.Marshal()
	keyB64 := base64.StdEncoding.EncodeToString(keyBytes)
	return "..." + keyB64[len(keyB64)-10:]
}

// Listen starts a SSH server listens on given port.
func Listen(host string, port string, ciphers []string, privateKey string, authorizedPublicKeys map[string]bool) {
	if ciphers == nil {
		ciphers = DefaultCiphers
	}

	config := &ssh.ServerConfig{
		Config: ssh.Config{
			Ciphers: ciphers,
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !authorizedPublicKeys[string(key.Marshal())] {
				log.Println("SSH: invalid public key:", getStrippedPublicKey(key))
				return nil, os.ErrPermission
			}
			fmt.Println("SSH: authentication succeed")
			return &ssh.Permissions{}, nil
		},
	}

	private, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		panic("SSH: Fail to parse private key")
	}
	config.AddHostKey(private)

	go listen(config, host, port)
}
