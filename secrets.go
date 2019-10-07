package main

import (
	"golang.org/x/crypto/bcrypt"
	"os"
	"bufio"
	"strings"
)

func storeSecret(username, password string) {
	os.Mkdir("data", 0600)
	f, _ := os.OpenFile("data/secrets", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	defer f.Close()
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), 10)
	f.WriteString(username + ":" + string(hash) + "\n")
}

func passwordIsOk(username, password string) bool {
	hash := getSecret(username)
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func getSecret(username string) string {
	f, _ := os.OpenFile("data/secrets", os.O_RDONLY|os.O_CREATE, 0600)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		return strings.SplitAfterN(scanner.Text(), ":", 2)[1]
	}
	return ""
}
