package sessions

import (
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gidoBOSSftw5731/log"
)

// Cookie is a struct detailing all parts of an http cookie
type Cookie struct {
	Name       string
	Value      string
	Path       string
	Domain     string
	Expires    time.Time
	RawExpires string

	// MaxAge=0 means no 'Max-Age' attribute specified.
	// MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'
	// MaxAge>0 means Max-Age attribute present and given in seconds
	MaxAge   int
	Secure   bool
	HTTPOnly bool
	Raw      string
	Unparsed []string // Raw text of unparsed attribute-value pairs
}

const (
	allowedChars = "!#$%&'()*+,-./123456789:<=>?@ABCDEFGHJKLMNOPRSTUVWXYZ[]^_abcdefghijkmnopqrstuvwxyz{|}~" // 86 chars
)

//DeleteKeySite is a function to remove the cookie from the user and the key from the db
func DeleteKeySite(resp http.ResponseWriter, req *http.Request, stmtMap map[string]*sql.Stmt) {
	cookie, err := req.Cookie("session")
	if err != nil {
		return
	} else if cookie.Value == "" {
		return
	}
	deleteKey(resp, stmtMap, cookie.Value)
}

func deleteKey(resp http.ResponseWriter, stmtMap map[string]*sql.Stmt, token string) error {
	_, err := stmtMap["deleteSessionKey"].Exec(token)
	cookie := http.Cookie{Name: "session", Value: "", Expires: time.Now()}
	http.SetCookie(resp, &cookie)
	return err
}

//New is a function to create a new session cookie and write it to the client.
//Im relying on an external system to not overwrite the cookie, though a check
//will be present, returning err SESSION_EXISTS
func New(resp http.ResponseWriter, req *http.Request, stmtMap map[string]*sql.Stmt) error {
	log.Traceln("Beginning to make a new session for the client")
	lastcookie, _ := req.Cookie("session")
	if lastcookie != nil {
		return fmt.Errorf("SESSION_EXISTS")
	}
	expiration := time.Now().Add(720 * time.Hour).Unix()
	allowedCharsSplit := strings.Split(allowedChars, "")
	var session string
	var x int
	rand.Seed(time.Now().UnixNano())
	for i := 0; i <= 128; i++ {
		x = rand.Intn(len(allowedChars)-0-1) + 0 // Not helpful name, but this generates a randon number from 0 to 84 to locate what we need for the session
		session += allowedCharsSplit[x]          // Using x to navigate the split for one character
	}

	cookie := http.Cookie{Name: "session", Value: session, Expires: time.Unix(expiration, 0), Path: "/"}

	err := stmtMap["checkSession"].QueryRow(session).Scan()
	switch {
	case err == sql.ErrNoRows:
		log.Debug("New session, adding..")
		_, err := stmtMap["insertNewSession"].Exec(session, expiration, req.FormValue("username"))
		if err != nil {
			log.Error(err)
			return err
		}
		log.Debug("Added token info to table")
	case err != nil:
		log.Error(err)
		return err
	default:
		return fmt.Errorf("SQL_ROW_EXISTS")
	}

	http.SetCookie(resp, &cookie)

	return nil
}

//Verify cookies to make sure they aren't expired or invalid.
func Verify(resp http.ResponseWriter, req *http.Request, stmtMap map[string]*sql.Stmt, user *string) (bool, error) {
	log.Traceln("Beginning to check the key")
	OK := true
	cookie, _ := req.Cookie("session")

	if cookie == nil {
		return false, fmt.Errorf("INVALID")
	}

	var expr string
	err := stmtMap["checkSessionExpiry"].QueryRow(cookie.Value).Scan(&expr, user)
	switch {
	case err != nil:
		log.Errorln("session not in db..")
		return false, fmt.Errorf("INVALID")
	default:
		log.Traceln("Found a session")
	}
	/*
		if ip != getClientIP(req) {
			OK = false
			err = fmt.Errorf("MISMATCHED_IP")
			return OK, err

		} */

	fmtExpr, _ := strconv.ParseInt(expr, 10, 64)

	if fmtExpr <= time.Now().Unix() {
		err := deleteKey(resp, stmtMap, fmt.Sprintln(cookie))
		if err != nil {
			log.Errorln(err)
		}
		return false, fmt.Errorf("EXPIRED")
	}

	return OK, err
}
