package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/gliderlabs/ssh"
	"github.com/ilius/gosshserver"
)

func loadAuthorizedPublicKeys() map[string]bool {
	authorizedKeysBytes, err := ioutil.ReadFile(filepath.Join(os.Getenv("HOME"), ".ssh", "authorized_keys"))
	if err != nil {
		panic(err)
	}
	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			panic(err)
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}
	return authorizedKeysMap
}

func main() {
	authorizedPublicKeys := loadAuthorizedPublicKeys()
	privateKeyBytes, err := ioutil.ReadFile(filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa"))
	if err != nil {
		panic(err)
	}
	gosshserver.Listen("127.0.0.1", "2222", nil, string(privateKeyBytes), authorizedPublicKeys)
	reader := bufio.NewReader(os.Stdin)
	for {
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text != "" {
			fmt.Println("Echo:", text)
		}
	}
}
