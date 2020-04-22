package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/fcgi"
	"strings"
	"sync"

	sessions "./sessions"
	"github.com/gidoBOSSftw5731/log"
	"github.com/jinzhu/configor"
	"golang.org/x/crypto/bcrypt"

	//pq is imported because below is a psql db that is made
	_ "github.com/lib/pq"
)

type newFCGI struct{}

//hashable is a struct of all the information necessary to check a password hash
type hashable struct {
	key, salt, origHash *string
	pepper              string
}

//hashes is a struct to hold an array of hashes, a few other details are passed for later processing.
type hashes struct {
	arr [52]hashable
	ok  bool
	wg  *sync.WaitGroup
}

var (
	Config struct {
		DB struct {
			User     string `default:"betterbb"`
			Password string `required:"true" env:"DBPassword" default:"PlsDontSue"`
			Port     string `default:"5432"`
			IP       string `default:"127.0.0.1"`
		}
	}
	db       *sql.DB
	stmtMap  = make(map[string]*sql.Stmt)
	queryMap = map[string]string{
		"checkForUniqueUsername": `SELECT FROM users WHERE
		username = $1
		OR
		email = $2`,
		"addUserToDB":        `INSERT INTO users VALUES($1, $2, $3, $4, $5)`,
		"deleteSessionKey":   `DELETE FROM sessions WHERE token = $1`,
		"checkSession":       `SELECT FROM sessions WHERE token = $1`,
		"insertNewSession":   `INSERT INTO sessions (token, expiration, username) VALUES($1, $2, $3)`,
		"checkSessionExpiry": `SELECT expiration, username FROM sessions where token = $1`,
		"getHashAndSalt":     `SELECT passwordhash, passwordsalt FROM users WHERE username=$1`,
	}
)

const (
	alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	//This is the number of rounds that occur every time you compute the key
	bcryptCost = 12
)

func main() {
	log.SetCallDepth(4)
	configor.Load(&Config, "config.yml")

	var err error
	db, err = MkDB()
	if err != nil {
		log.Fatalln(err)
	}

	if db.Ping() != nil {
		log.Fatalln(err)
	}

	defineSQLStatements()

	log.Traceln("Listening")
	//  Start the fcgi listener, we use fcgi so we can have a loadbalancer and a cache upstream
	listener, err := net.Listen("tcp", "127.0.0.1:9001")
	if err != nil {
		log.Fatalln(err)
	}
	var h newFCGI
	fcgi.Serve(listener, h)
}

func defineSQLStatements() {

	for i, j := range queryMap {
		var err error
		stmtMap[i], err = db.Prepare(j)
		if err != nil {
			log.Fatalln(err)
		}
	}
}

//MkDB is a function that takes a config struct and returns a pointer to a database.
func MkDB() (*sql.DB, error) {
	//var err error
	return sql.Open("postgres", fmt.Sprintf("user=%v password=%v dbname=betterbb host=%v port=%v",
		Config.DB.User, Config.DB.Password, Config.DB.IP, Config.DB.Port))
	/*
		CREATE DATABASE betterbb;
		create user betterbb with encrypted password 'PlsDontSue';
		CREATE TABLE users (
			username text,
			email text,
			passwordhash text,
			passwordsalt text,
			role int
		);
		CREATE TABLE sessions (
			username text,
			token text,
			expiration text
		);
		GRANT ALL ON ALL TABLES IN SCHEMA public TO betterbb;
	*/
}

func signUpHandler(resp http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	username := req.FormValue("username")
	password := req.FormValue("password")
	email := req.FormValue("email")
	if username == "" || password == "" || email == "" {
		ErrorHandler(resp, req, 400, "Field left empty")
		return
	}

	/*secure, err := regexp.MatchString(`^([A-Z].*[A-Z])([~/!@#$&*])([0-9].*[0-9])([a-z][a-z][a-z]).{8,}$`, password)
	if err != nil {
		ErrorHandler(resp, req, 500, "Internal Error, please try again")
		return
	}

	if !secure {
		ErrorHandler(resp, req, 400, "Password must have: 2 Uppercase, 1 Special Character, 2 numbers, 3 lowercase letters, and be atleast 8 characters long")
		return
	}*/

	err := stmtMap["checkForUniqueUsername"].QueryRow(username, email).Scan()
	switch err {
	case sql.ErrNoRows, nil:
	default:
		ErrorHandler(resp, req, 400, "Username taken or email already in use")
		return
	}

	// user is unique now

	// create salt
	saltByte, _ := GenerateRandomBytes(40)
	salt := base64.URLEncoding.EncodeToString(saltByte)[:40]

	// stored as [pepper][password][salt]
	hash, err := bcrypt.GenerateFromPassword([]byte(string(string(alphabet[randInt()])+password+salt)), bcryptCost)
	if err != nil {
		ErrorHandler(resp, req, 500, "Internal Error, please try again")
		return
	}

	_, err = stmtMap["addUserToDB"].Exec(username, email, hash, salt, 1)
	if err != nil {
		ErrorHandler(resp, req, 500, "Error creating account")
		return
	}

	// success

	fmt.Sprintln(resp, "Success")

}

func randInt() int64 {
	nBig, err := rand.Int(rand.Reader, big.NewInt(52))
	if err != nil {
		panic(err)
	}
	n := nBig.Int64()
	return n
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

//LoginHandler handles the login on the login page
func LoginHandler(resp http.ResponseWriter, req *http.Request) {
	log.Traceln("logging someone in!")

	req.ParseForm()

	user := req.FormValue("username")
	password := req.FormValue("password")
	_, ok := checkKey(resp, req, &password, &user, true)
	if !ok {
		http.Redirect(resp, req, "/login"+"?issue=BadUserPass", http.StatusTemporaryRedirect)
		return
	}

}

func (h newFCGI) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	urlSplit := strings.Split(req.URL.Path, "/")

	if len(urlSplit) < 2 {
		ErrorHandler(resp, req, 400,
			"Nothing to see here")
		return
	}

	log.Tracef("URLSplit: %v", urlSplit)

	switch urlSplit[1] {
	case "":
		http.ServeFile(resp, req, "../public/index.html")
	case "signup":
		http.ServeFile(resp, req, "../public/signup.html")
	case "css":
		http.ServeFile(resp, req, "../public/global.css")
	case "signuphandler":
		signUpHandler(resp, req)
		http.Redirect(resp, req, "/", http.StatusTemporaryRedirect)
	case "logout", "signout":
		sessions.DeleteKeySite(resp, req, stmtMap)
		http.Redirect(resp, req, "/", http.StatusTemporaryRedirect)
	case "signin", "login":
		http.ServeFile(resp, req, "../public/signin.html")
	case "loginhandler":
		LoginHandler(resp, req)
		http.Redirect(resp, req, "/", http.StatusTemporaryRedirect)
	case "verifysession":
		var user string
		ok, err := sessions.Verify(resp, req, stmtMap, &user)
		if err != nil && err != fmt.Errorf("INVALID") {
			log.Errorln(err)
			ErrorHandler(resp, req, 401, "quien es?")
			return
		}
		fmt.Fprintln(resp, ok)
	default:
		ErrorHandler(resp, req, 404, "Malformed URL")
	}

}

//ErrorHandler is a function to handle HTTP errors
func ErrorHandler(resp http.ResponseWriter, req *http.Request, status int, alert string) {
	resp.WriteHeader(status)
	log.Errorf("HTTP error: %v, witty message: %v", status, alert)
	fmt.Fprintf(resp, "You have found an error! This error is of type %v. Built in alert: \n'%v',\n Would you like a <a href='https://http.cat/%v'>cat</a> or a <a href='https://httpstatusdogs.com/%v'>dog?</a>",
		status, alert, status, status)
}

func chkHash(inout chan *hashes) {
	var output hashes
	input := <-inout

	var ok bool

	var wg0 sync.WaitGroup
	var wg1 sync.WaitGroup
	var wg2 sync.WaitGroup
	var wg3 sync.WaitGroup

	wg0.Add(len(alphabet) / 4)
	wg1.Add(len(alphabet) / 4)
	wg2.Add(len(alphabet) / 4)
	wg3.Add(len(alphabet) / 4)

	go func() {
		for i := 0; i < len(alphabet)/4; i++ {
			obj := input.arr[i]

			if ok {
				wg0.Done()
				continue
			}

			err := bcrypt.CompareHashAndPassword([]byte(*obj.origHash), []byte(string(obj.pepper+*obj.key+*obj.salt)))
			//log.Traceln(string(obj.pepper), string(*obj.origHash))

			if err == nil {
				ok = true
			}
			output.arr[i] = obj

			wg0.Done()
		}
	}()
	go func() {
		for i := len(alphabet) / 4; i < 2*len(alphabet)/4; i++ {
			obj := input.arr[i]

			if ok {
				wg1.Done()
				continue
			}

			err := bcrypt.CompareHashAndPassword([]byte(*obj.origHash), []byte(string(obj.pepper+*obj.key+*obj.salt)))
			//log.Traceln(string(obj.pepper), string(*obj.origHash))

			if err == nil {
				ok = true
			}
			output.arr[i] = obj

			wg1.Done()
		}
	}()
	go func() {
		for i := 2 * len(alphabet) / 4; i < 3*len(alphabet)/4; i++ {
			obj := input.arr[i]

			if ok {
				wg2.Done()
				continue
			}

			err := bcrypt.CompareHashAndPassword([]byte(*obj.origHash), []byte(string(obj.pepper+*obj.key+*obj.salt)))
			//log.Traceln(string(obj.pepper), string(*obj.origHash))

			if err == nil {
				ok = true
			}
			output.arr[i] = obj

			wg2.Done()
		}
	}()
	go func() {
		for i := 3 * len(alphabet) / 4; i < len(alphabet); i++ {
			obj := input.arr[i]

			if ok {
				wg3.Done()
				continue
			}

			err := bcrypt.CompareHashAndPassword([]byte(*obj.origHash), []byte(string(obj.pepper+*obj.key+*obj.salt)))
			//log.Traceln(string(obj.pepper), string(*obj.origHash))

			if err == nil {
				ok = true
			}
			output.arr[i] = obj

			wg3.Done()
		}
	}()

	wg0.Wait()
	wg1.Wait()
	wg2.Wait()
	wg3.Wait()

	output.ok = ok

	log.Debugln("Done checking password!")

	input.wg.Done()

	inout <- &output
}

func checkHash(key, user *string) (bool, error) {
	var ok bool

	//fmt.Println(user)
	var origHash, salt string
	var in hashes
	err := stmtMap["getHashAndSalt"].QueryRow(user).Scan(&origHash, &salt)
	if err != nil {
		log.Errorln(err)
		return ok, err
	}

	c := make(chan *hashes)

	var wg sync.WaitGroup

	go chkHash(c)

	in.wg = &wg
	wg.Add(1)

	for i, x := range alphabet {
		in.arr[i] = hashable{key, &salt, &origHash, string(x)}
	}
	c <- &in

	wg.Wait()

	output := *<-c
	if output.ok {
		ok = true
	}

	log.Debugln("Password Success: ", ok)

	return ok, err
}

// checkKey simply looks in the keys map for evidence of a key.
func checkKey(resp http.ResponseWriter, req *http.Request, inputKey, user *string, newSess bool) (bool, bool) { // session good, key good
	ok, err := sessions.Verify(resp, req, stmtMap, user) // good session
	if ok {
		return true, true
	}
	if err != nil {
		log.Errorln(err)
	}

	keyOK, err := checkHash(inputKey, user)
	if err != nil {
		return false, false
	}

	if !keyOK { // key not good
		return false, false
	}

	if newSess {
		err = sessions.New(resp, req, stmtMap) // make new session if none found and valid key
		if err != nil {
			log.Errorln(err)

			switch err.Error() {
			case "SESSION_EXISTS", "":
			default:
				return false, false
			}
		}
	}

	return false, true // session bad key good
}
