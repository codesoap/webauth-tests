package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
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
	fmt.Fprintf(w, "Index\n")
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
			fmt.Fprintf(w, "Login succeeded; token will be set as a cookie\n")
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
