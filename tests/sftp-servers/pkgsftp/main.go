// A minimal SSH server whose sftp subsystem is github.com/pkg/sftp, the Go SFTP implementation behind many Go-based SFTP
// products. SshSharp's SFTP interop tests run against it in CI, next to OpenSSH and atmoz/sftp, to catch differences between
// servers. Password authentication for one user; a fresh host key at each start; files under -root.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"flag"
	"log"
	"net"
	"os"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:2202", "address to listen on")
	root := flag.String("root", ".", "directory the SFTP session starts in (its login directory)")
	flag.Parse()
	user, password := os.Getenv("SFTP_USER"), os.Getenv("SFTP_PASSWORD")
	if user == "" || password == "" {
		log.Fatal("SFTP_USER and SFTP_PASSWORD must be set")
	}

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		log.Fatal(err)
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, given []byte) (*ssh.Permissions, error) {
			if meta.User() == user && subtle.ConstantTimeCompare(given, []byte(password)) == 1 {
				return nil, nil
			}
			return nil, errors.New("access denied")
		},
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("pkg/sftp test server on %s, root %s", *listen, *root)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go serve(conn, config, *root)
	}
}

func serve(conn net.Conn, config *ssh.ServerConfig, root string) {
	defer conn.Close()
	_, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("handshake: %v", err)
		return
	}
	go ssh.DiscardRequests(requests)
	for incoming := range channels {
		if incoming.ChannelType() != "session" {
			_ = incoming.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		channel, channelRequests, err := incoming.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer channel.Close()
			for request := range channelRequests {
				isSftp := request.Type == "subsystem" && len(request.Payload) > 4 && string(request.Payload[4:]) == "sftp"
				_ = request.Reply(isSftp, nil)
				if !isSftp {
					continue
				}
				server, err := sftp.NewServer(channel, sftp.WithServerWorkingDirectory(root))
				if err != nil {
					log.Printf("sftp: %v", err)
					return
				}
				if err := server.Serve(); err != nil && !errors.Is(err, net.ErrClosed) {
					log.Printf("sftp session ended: %v", err)
				}
				_ = server.Close()
				return
			}
		}()
	}
}
