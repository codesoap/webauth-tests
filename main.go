package main

import (
	"bufio"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"strings"
)

var jwt_secret = []byte("my secret secret")

func main() {
	http.HandleFunc("/", serveIndex)
	http.HandleFunc("/register", serveRegistration)
	http.HandleFunc("/login", serveLogin)
	http.HandleFunc("/profile", serveProfile) // Can only be accessed after login.
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "html/index.html")
}

func serveRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.PostFormValue("username")
		password := r.PostFormValue("password")
		storeSecret(username, password)
		http.Redirect(w, r, "/", 303)
	} else {
		http.ServeFile(w, r, "html/registration.html")
	}
}

func serveLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.PostFormValue("username")
		password := r.PostFormValue("password")
		if passwordIsOk(username, password) {
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"aud": username,
			})
			tokenString, _ := token.SignedString(jwt_secret)
			jwt_cookie := &http.Cookie{
				Name:     "token",
				Value:    tokenString,
				MaxAge:   120,   // The token will only be used for 120s.
				Secure:   false, // Make this true in production!
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			}
			http.SetCookie(w, jwt_cookie)
			http.Redirect(w, r, "/", 303)
		} else {
			fmt.Fprintf(w, "Login failed\n")
		}
	} else {
		http.ServeFile(w, r, "html/login.html")
	}
}

func serveProfile(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		fmt.Fprintf(w, "Not authorized\n")
		return
	}
	tokenString := cookie.Value
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return jwt_secret, nil
	})
	if err != nil {
		fmt.Fprintf(w, "Not authorized\n")
		return
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Fprintf(w, "This is the profile of %s.\n", claims["aud"])
		fmt.Fprintf(w, "It can only be seen by the logged in user.\n")
	} else {
		fmt.Fprintf(w, "Not authorized\n")
	}
	return
}

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
		text := scanner.Text()
		if strings.SplitAfterN(text, ":", 2)[0] == username + ":" {
			return strings.SplitAfterN(text, ":", 2)[1]
		}
	}
	return ""
}
