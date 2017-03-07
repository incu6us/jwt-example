package main

import (
	"io/ioutil"
	"log"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"time"
	"net/http"
	"crypto/rsa"
	"github.com/gorilla/mux"
	"strings"
	"fmt"
	"strconv"
	"encoding/json"
)

const (
	PRIVATE_KEY = "./sample_key.priv"
	PUBLIC_KEY  = "./sample_key.pub"

	TOKEN_VALIDITY_TIME = time.Duration(30) * time.Second
	TOKEN_JWT_ID        = "2nd8-83je-asd0-75ds"
	TOKEN_ISSUER        = "http://example.com/"
	TOKEN_SUBJECT       = "user@example.com"

	USERNAME = "test"
	PASSWORD = "test"
)

type TokenResponse struct {
	Token string `json:"token"`
}

func readPublicRSA() (*rsa.PublicKey, error) {
	bytes, _ := ioutil.ReadFile(PUBLIC_KEY)
	rsaPublic, err := crypto.ParseRSAPublicKeyFromPEM(bytes)
	if err != nil {
		return nil, err
	}

	return rsaPublic, nil
}

func tokenValidate(token []byte) (bool, string) {
	rsaPublic, _ := readPublicRSA()

	jwt, err := jws.ParseJWT(token)
	if err != nil {
		log.Printf("parsing error: %v\n", err)
		return false, err.Error()
	}

	// Validate token
	if err = jwt.Validate(rsaPublic, crypto.SigningMethodRS256); err != nil {
		log.Printf("validation error: %v\n", err)
		return false, err.Error()
	}

	return true, ""
}

func tokenGen() string {
	bytes, _ := ioutil.ReadFile(PRIVATE_KEY)

	claims := jws.Claims{}
	claims.SetExpiration(time.Now().Add(TOKEN_VALIDITY_TIME))
	claims.SetJWTID(TOKEN_JWT_ID)
	claims.SetIssuer(TOKEN_ISSUER)
	claims.SetSubject(TOKEN_SUBJECT)

	rsaPrivate, _ := crypto.ParseRSAPrivateKeyFromPEM(bytes)
	jwt := jws.NewJWT(claims, crypto.SigningMethodRS256)

	b, _ := jwt.Serialize(rsaPrivate)

	return string(b)
}

func checkAuthHeader(r *http.Request) ([]byte, bool) {
	var tokenHeader string

	if tokenHeader = r.Header.Get("Authorization");
		len(tokenHeader) > 7 && strings.EqualFold(tokenHeader[0:7], "BEARER ") {

		//log.Printf("token: %s\n", []byte(tokenHeader[7:]))
		return []byte(tokenHeader[7:]), true
	}
	return nil, false
}

func checkTokenTTL(token []byte) int {
	jwtInst, _ := jws.ParseJWT(token)

	tokenTime, _ := jwtInst.Claims().Expiration()
	expTime := time.Since(tokenTime)

	return int(-expTime.Seconds())
}

func checkTokenJTI(token []byte) (string, bool) {
	jwtInst, _ := jws.ParseJWT(token)

	return jwtInst.Claims().JWTID()
}

func checkTokenIssuer(token []byte) (string, bool) {
	jwtInst, _ := jws.ParseJWT(token)

	return jwtInst.Claims().Issuer()
}

func checkTokenSubject(token []byte) (string, bool) {
	jwtInst, _ := jws.ParseJWT(token)

	return jwtInst.Claims().Subject()
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	rUsername := r.Header.Get("username")
	rPassword := r.Header.Get("password")

	if rUsername == USERNAME && rPassword == PASSWORD {
		GenToken(w, r)
	}
}

func GenToken(w http.ResponseWriter, r *http.Request) {
	var tokenResponse TokenResponse
	tokenResponse.Token = tokenGen()

	data, _ := json.Marshal(tokenResponse)
	w.Write(data)
}

func ParseTokenHandler(w http.ResponseWriter, r *http.Request) {
	var token []byte
	var jti string
	var iss string
	var sub string
	var ok bool
	var message string

	if token, ok = checkAuthHeader(r); !ok {
		fmt.Fprintln(w, "\nNo token was not found in headers. Go to /login page")
		return
	}

	if ok, message = tokenValidate(token); !ok {
		fmt.Fprintln(w, "\n"+message+". Go to /login form")
		return
	}

	if jti, ok = checkTokenJTI(token); !ok {
		fmt.Fprintln(w, "JWT ID is wrong")
		return
	}

	if iss, ok = checkTokenIssuer(token); !ok {
		fmt.Fprintln(w, "JWT issuer is wrong")
		return
	}

	if sub, ok = checkTokenSubject(token); !ok {
		fmt.Fprintln(w, "JWT subject is wrong")
		return
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "very secured data :)")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "",
		"JWT_ID: "+jti+"\n",
		"JWT_ISSUER: "+iss+"\n",
		"JWT_SUBJECT: "+sub+"\n",
		"Access granted for "+strconv.Itoa(checkTokenTTL(token))+" seconds.\n",
	)

}

func main() {
	srvMux := mux.NewRouter().StrictSlash(true)
	srvMux.HandleFunc("/", ParseTokenHandler)
	srvMux.HandleFunc("/login", LoginHandler)
	//srvMux.HandleFunc("/token", GenToken)

	log.Println("Server running...")

	http.ListenAndServe(":3000", srvMux)
}
