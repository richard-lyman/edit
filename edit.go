/*
Copyright (c) 2014, Richard B. Lyman
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/
package main

import (
	"bytes"
	//"crypto/tls"
	"archive/tar"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/garyburd/redigo/redis"
	"github.com/gorilla/context"
	"github.com/gorilla/securecookie"
	"golang.org/x/crypto/bcrypt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"
)

var generateConfig = flag.Bool("gen", false, "Generates a valid config file, assuming a default local install of Redis.")

type configStruct struct {
	HostAndPort      string `json:"host_and_port"`
	Webroot          string `json:"webroot"`
	RootTitle        string `json:"root_title"`
	RedisHostAndPort string `json:"redis_host_and_port"`
	ProcessCommand   string `json:"process_command"`
}

var config = configStruct{}

func getConfig() {
	f, err := ioutil.ReadFile("config.json")
	if err != nil {
		log.Fatalln("Unable to read config file:", err)
	}
	if json.Unmarshal(f, &config) != nil {
		log.Fatalln("Unable to unmarshal config file:", err)
	}
	log.Printf("Using config: %#v\n", config)
}

type userContext int

const userKey userContext = 0

func main() {
	flag.Parse()
	if *generateConfig {
		if _, err := os.Stat("config.json"); os.IsNotExist(err) {
			log.Println("Generating config...")
			ioutil.WriteFile("config.json", []byte(`{
        "host_and_port":":1234",
        "webroot":"webroot",
        "root_title":"An Editable Site",
        "redis_host_and_port":"localhost:6379",
        "process_command":"./process.sh"
}
`), 0600)
		} else {
			log.Println("Config file 'config.json' already exists - we will not overwrite it.")
		}
		os.Exit(0)
	}
	getConfig()
	tmpDuration, _ := time.ParseDuration("8h")
	pageLockTTL = tmpDuration.Seconds()
	err := os.Mkdir(config.Webroot, 0700)
	if os.IsPermission(err) {
		panic(fmt.Sprintf("Unable to create required webroot directory: '%s'", config.Webroot))
	}
	pool = newPool()
	_, err = rdo("PING")
	if err != nil {
		panic(fmt.Sprintf("A working connection to a Redis instance is required: %s - You may need to tweak the config.go file prior to building.", err))
	}
	if exists, err := redis.Bool(rdo("EXISTS", "USER:admin")); err == nil && !exists {
		log.Println("Creating default admin account, since it doesn't currently exist. ('admin'/'password')")
		bp, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		if err != nil {
			panic(fmt.Sprintf("Unable to generate bcrypt from password to create admin account: %s", err))
		}
		rdo("SET", "USER:admin", bp)
		rdo("SET", "root", "admin")
		rdo("SADD", "ADMINS", "admin")
	}
	http.HandleFunc("/", h)
	http.HandleFunc("/dl", dl)
	http.HandleFunc("/toc", t)
	http.HandleFunc("/admin", a)
	http.HandleFunc("/admin/remove", r)
	http.HandleFunc("/user", u)
	http.HandleFunc("/file/", f)
	http.HandleFunc("/lock", l)
	http.HandleFunc("/unlock", ul)
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {})
	log.Println("Listening on " + config.HostAndPort)
	/*
		        tlsConfig := &tls.Config{MinVersion: tls.VersionTLS10}
			server := &http.Server{Addr: config.HostAndPort, Handler: authd(http.DefaultServeMux), TLSConfig: tlsConfig}
			log.Fatal(server.ListenAndServeTLS("cert.pem", "key.pem"))
	*/
	log.Fatal(http.ListenAndServeTLS(config.HostAndPort, "cert.pem", "key.pem", context.ClearHandler(authd(http.DefaultServeMux))))
}

var hashKey = securecookie.GenerateRandomKey(32)
var blockKey = securecookie.GenerateRandomKey(16)
var s = securecookie.New(hashKey, blockKey)
var cookieName = "settings"

func setCookie(w http.ResponseWriter, r *http.Request, value map[string]string) {
	if encoded, encErr := s.Encode(cookieName, value); encErr == nil {
		cookie := &http.Cookie{Name: cookieName, Value: encoded, Path: "/"}
		http.SetCookie(w, cookie)
	}
}

func getUser(r *http.Request) string {
	tmp := string(context.Get(r, userKey).(string))
	if len(tmp) > 0 {
		return tmp
	}
	cookie, _ := r.Cookie(cookieName)
	value := make(map[string]string)
	s.Decode(cookieName, cookie.Value, &value)
	return value["u"]
}

func notDefaultPassword(u string) bool {
	rp, err := redis.String(rdo("GET", "USER:"+u))
	if err == nil && bcrypt.CompareHashAndPassword([]byte(rp), []byte("password")) != nil {
		return true
	}
	log.Println("The given user is using a default password!")
	return false
}

func authdUser(w http.ResponseWriter, r *http.Request) (string, error) {
	if needsAuth(w, r) {
		return "", errors.New("Authentication needed")
	}
	return getUser(r), nil
}

func needsAuth(w http.ResponseWriter, r *http.Request) bool {
	u := ""
	if cookie, reqErr := r.Cookie(cookieName); reqErr == nil {
		value := make(map[string]string)
		if decErr := s.Decode(cookieName, cookie.Value, &value); decErr != nil {
			setCookie(w, r, map[string]string{"u": ""})
			return true
		} else {
			u = value["u"]
		}
	} else {
		setCookie(w, r, map[string]string{"u": ""})
		return true
	}
	if len(u) > 0 {
		if hasAuthd, err := redis.Bool(rdo("EXISTS", "USER:"+u)); err == nil && hasAuthd {
			context.Set(r, userKey, u)
			return false
		}
	}
	tmp := r.Header["Authorization"]
	if len(tmp) > 0 {
		authTmp := strings.TrimPrefix(strings.TrimSpace(tmp[0]), "Basic ")
		b, err := base64.StdEncoding.DecodeString(authTmp)
		if err != nil {
			log.Println("Failed to decode auth:", err)
		} else {
			authSet := strings.SplitN(string(b), ":", 2)
			if len(authSet) != 2 {
				log.Println("Incorrectly formatted auth")
			} else {
				u := authSet[0]
				p := authSet[1]
				rp, err := redis.String(rdo("GET", "USER:"+u))
				if err != nil {
					log.Println("Attempt to edit with a non-existent account:", u, err)
				} else {
					if bcrypt.CompareHashAndPassword([]byte(rp), []byte(p)) == nil {
						setCookie(w, r, map[string]string{"u": u})
						context.Set(r, userKey, u)
						return false
					}
				}
			}
		}
	}
	return true
}

func newPool() *redis.Pool {
	return &redis.Pool{
		MaxIdle:      3,
		IdleTimeout:  240 * time.Second,
		Dial:         func() (redis.Conn, error) { return redis.Dial("tcp", config.RedisHostAndPort) },
		TestOnBorrow: func(c redis.Conn, t time.Time) error { _, err := c.Do("PING"); return err },
	}
}

var pool *redis.Pool

func rdo(command string, args ...interface{}) (interface{}, error) {
	c := pool.Get()
	defer c.Close()
	return c.Do(command, args...)
}

var pageLockKey = "an internal key that should never be used as a users name"
var pageLockTTL float64

func authd(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, err := authdUser(w, r); err == nil {
			rp, err := redis.String(rdo("GET", "USER:"+u))
			if err != nil {
				return
			}
			isDefaultPassword := bcrypt.CompareHashAndPassword([]byte(rp), []byte("password")) == nil
			if r.Method == "GET" || !isDefaultPassword {
				h.ServeHTTP(w, r) // TODO - the problem is that we'll process requests thinking that our user is in a cookie in this request - and they're not yet...
			} else {
				if r.Method == "PUT" && r.URL.Path == "/user" {
					h.ServeHTTP(w, r)
				} else {
					log.Println("Ignoring action since password is still default: ", r)
				}
			}
		} else {
			w.Header().Set("WWW-Authenticate", `Basic realm="edit"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
}

func getBody(r *http.Request) (string, error) {
	b, read_err := ioutil.ReadAll(r.Body)
	if read_err != nil {
		return "", read_err
	}
	if len(b) == 0 {
		return "", errors.New("No input")
	} else {
		return string(b), nil
	}
}

func getJson(r *http.Request) (map[string]string, error) {
	b, err := getBody(r)
	if err != nil {
		return nil, err
	} else {
		var r map[string]string
		if err := json.Unmarshal([]byte(b), &r); err != nil {
			return nil, err
		} else {
			return r, nil
		}
	}
}

func isAdmin(r *http.Request) bool {
	u := getUser(r)
	if len(u) > 0 {
		isAdmin, err := redis.Bool(rdo("SISMEMBER", "ADMINS", u))
		if err == nil {
			return isAdmin
		}
	}
	return false
}

type fileFirstByName []os.FileInfo

func (f fileFirstByName) Len() int { return len(f) }
func (f fileFirstByName) Less(i, j int) bool {
	if !f[i].IsDir() && f[j].IsDir() {
		return true
	}
	if f[i].IsDir() && !f[j].IsDir() {
		return false
	}
	return f[i].Name() < f[j].Name()
}
func (f fileFirstByName) Swap(i, j int) { f[i], f[j] = f[j], f[i] }

func fileFirstReadDir(dirname string) ([]os.FileInfo, error) {
	f, err := os.Open(dirname)
	if err != nil {
		return nil, err
	}
	list, err := f.Readdir(-1)
	f.Close()
	if err != nil {
		return nil, err
	}
	sort.Sort(fileFirstByName(list))
	return list, nil
}

func processDir(r string, filter func(string, os.FileInfo) bool, handler func(string, os.FileInfo, bool) error) error {
	tmp, err := fileFirstReadDir(r)
	if err != nil {
		return err
	}
	contents := []os.FileInfo{}
	for _, fi := range tmp {
		if filter(filepath.Join(r, fi.Name()), fi) {
			contents = append(contents, fi)
		}
	}
	for i, fi := range contents {
		fullPath := filepath.Join(r, fi.Name())
		lastEntry := i == len(contents)-1
		handler(fullPath, fi, lastEntry)
	}
	return nil
}

func dl(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Disposition", "attachment; filename="+strings.Replace(config.RootTitle, " ", "_", -1)+".tgz")
		g := gzip.NewWriter(w)
		defer g.Close()
		t := tar.NewWriter(g)
		defer t.Close()
		addContent := func(name string, size int64, modTime time.Time, content io.Reader) {
			h := new(tar.Header)
			h.Name = name
			h.Size = size
			h.Mode = 0600
			h.ModTime = modTime
			if err := t.WriteHeader(h); err != nil {
				log.Println("Failed to write tar entry header for download:", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if _, err := io.Copy(t, content); err != nil {
				log.Println("Failed to copy file to tar writer for download:", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		addFile := func(path string) error {
			file, err := os.Open(path)
			if err != nil {
				log.Println("Failed to open file for download:", err)
				w.WriteHeader(http.StatusInternalServerError)
				return err
			}
			defer file.Close()
			if stat, err := file.Stat(); err == nil {
				addContent(path, stat.Size(), stat.ModTime(), file)
			}
			return nil
		}
		var tocb bytes.Buffer
		writeToc(&tocb, true)
		addContent("webroot/toc.html", int64(tocb.Len()), time.Now(), &tocb)
		var pDir func(string)
		pDir = func(d string) {
			files, err := ioutil.ReadDir(d)
			if err != nil {
				log.Panicf("Failed to read root dir: %s", err)
			}
			for _, fi := range files {
				if fi.IsDir() {
					pDir(filepath.Join(d, fi.Name()))
				} else {
					if !strings.HasSuffix(fi.Name(), "src") {
						if err := addFile(filepath.Join(d, fi.Name())); err != nil {
							log.Panicf("Failed to add file to TGZ download: %s", err)
						}
					}
				}
			}
		}
		pDir(config.Webroot)
	}
}

func t(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		writeToc(w, false)
	}
}

func writeToc(w io.Writer, appendIndexHtml bool) {
	tocFile, err := os.Open("core/toc_style.html")
	if err != nil {
		panic("Failed to open the required file 'core/toc_style.html': " + err.Error())
	}
	tocStyle, err := ioutil.ReadAll(tocFile)
	if err != nil {
		panic("Failed to read contents of the required file 'core/toc_style.html': " + err.Error())
	}
	fmt.Fprint(w, `<!DOCTYPE html><html><body>`)
	fmt.Fprint(w, string(tocStyle))
	fmt.Fprint(w, `<div class="toc toc-dir lastEntry"><a href="/">/`+"\n")
	filter := func(p string, i os.FileInfo) bool {
		return !strings.HasSuffix(p, "index.html") && !strings.HasSuffix(p, "index.html.src")
	}
	var handler func(string, os.FileInfo, bool) error
	handler = func(p string, i os.FileInfo, lastEntry bool) error {
		np, err := filepath.Rel(config.Webroot, p)
		if err != nil {
			log.Println("Failed to resolve relative path:", p)
			return err
		}
		if np == "." {
			return nil
		}
		dnp := np
		if len(filepath.Ext(np)) > 0 {
			dnp = filepath.Base(dnp)
		}
		extraClass := ""
		if lastEntry {
			extraClass = " lastEntry"
		}
		if i.IsDir() {
			if appendIndexHtml {
				fmt.Fprint(w, `<div class="toc toc-dir`+extraClass+`"><a href="`+np+`/index.html">/`+dnp+`</a>`+"\n")
			} else {
				fmt.Fprint(w, `<div class="toc toc-dir`+extraClass+`"><a href="`+np+`">/`+dnp+`</a>`+"\n")
			}
			err = processDir(p, filter, handler)
			if err != nil {
				return err
			}
			fmt.Fprint(w, "</div>\n")
		} else {
			fmt.Fprint(w, `<div class="toc toc-file`+extraClass+`"><a href="/file/`+np+`">`+dnp+`</a></div>`+"\n")
		}
		return nil
	}
	processDir(config.Webroot, filter, handler)
	fmt.Fprint(w, `</div>`)
}

func l(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) || r.Method != "PATCH" {
		return
	}
	b, err := getBody(r)
	if err != nil {
		log.Println("Failed to lock page:", err)
	} else {
		log.Println("Locking page:", b)
		_, err := rdo("SET", "PAGE:"+b, pageLockKey)
		if err != nil {
			log.Println("Failed to lock page:", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

func ul(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) || r.Method != "PATCH" {
		return
	}
	b, err := getBody(r)
	if err != nil {
		log.Println("Failed to unlock page:", err)
	} else {
		log.Println("Unlocking page:", b)
		_, err := rdo("DEL", "PAGE:"+b)
		if err != nil {
			log.Println("Failed to unlock page:", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

func f(w http.ResponseWriter, r *http.Request) {
	url, err := url.Parse(r.Referer())
	if err != nil {
		log.Println("Failed to process referer:", err)
		return
	}
	path, err := urlToDirPath(url)
	if err != nil {
		fmt.Fprint(w, err.Error())
		return
	}
	if r.Method == "GET" {
		getFile(w, r, path)
	} else if r.Method == "POST" {
		f, handler, err := r.FormFile("f")
		if err != nil {
			fmt.Println("Failed to get file from form:", err)
		}
		if handler.Filename == "index.html" || handler.Filename == "index.html.src" {
			return
		}
		d, err := ioutil.ReadAll(f)
		if err != nil {
			fmt.Println("Failed to read file:", err)
		}
		err = ioutil.WriteFile(filepath.Join(path, handler.Filename), d, 0600)
		if err != nil {
			fmt.Println("Failed to write file:", err)
		}
	} else if r.Method == "PUT" {
		j, err := getJson(r)
		if err != nil {
			log.Println("Failed to remove file:", err)
		} else {
			log.Println("Removing file at:", j["filepath"])
		}
	}
}

func getFile(w http.ResponseWriter, r *http.Request, path string) {
	if r.URL.Path == "/file/" {
		fs, _ := ioutil.ReadDir(path)
		result := []string{}
		for _, f := range fs {
			if f.Name() == "index.html" || f.Name() == "index.html.src" || f.IsDir() {
				continue
			}
			result = append(result, f.Name())
		}
		j, err := json.Marshal(result)
		if err != nil {
			log.Println("Failed to json-ify list of files:", err)
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			fmt.Fprint(w, string(j))
		}
	} else {
		path, err := urlToPath(r.URL)
		if err != nil {
			log.Println("Failed to convert a requested file to a path:", err)
			return
		}
		http.ServeFile(w, r, path)
	}
}

func u(w http.ResponseWriter, r *http.Request) {
	u := getUser(r)
	if r.Method != "PUT" {
		return
	}
	j, err := getJson(r)
	if err != nil {
		log.Println("Failed to change password:", err)
	} else {
		log.Println("Changing password for user:", u)
		bp, err := bcrypt.GenerateFromPassword([]byte(j["password"]), bcrypt.DefaultCost)
		if err != nil {
			panic(fmt.Sprintf("Unable to generate bcrypt from password to change password: %s", err))
		}
		if _, err = rdo("SET", "USER:"+u, bp); err != nil {
			log.Println("Failed to change password:", err)
		} else {
			w.Header().Set("WWW-Authenticate", `Basic realm="edit"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
	}
}

func r(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) || r.Method != "PUT" {
		return
	}
	b, err := getBody(r)
	if err != nil {
		log.Println("Failed to remove user:", err)
	} else {
		rootUser, err := redis.String(rdo("GET", "root"))
		if err != nil {
			log.Println("Unable to verify that user to remove isn't the root user")
			return
		} else {
			if b == rootUser {
				log.Println("You can't remove the root admin user")
				return
			}
		}
		log.Println("Removing user:", b)
		if _, err = rdo("DEL", "USER:"+b); err != nil {
			log.Println("Failed to remove user:", err)
		} else {
			rdo("SREM", "ADMINS", b)
		}
	}
}

func a(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		return
	}
	if r.Method == "POST" {
		b, err := getBody(r)
		if err != nil {
			log.Println("Failed to add a user:", err)
		} else {
			log.Println("Adding user:", b)
			bp, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
			if err != nil {
				panic(fmt.Sprintf("Unable to generate bcrypt from password for adding a user: %s", err))
			}
			added, err := redis.Int(rdo("SETNX", "USER:"+b, bp))
			if err != nil || added != 1 {
				log.Println("Failed to add user:", err)
			}
		}
	} else if r.Method == "PUT" {
		b, err := getBody(r)
		if err != nil {
			log.Println("Failed to grant admin:", err)
		} else {
			log.Println("Granting admin to user:", b)
			if rp, err := redis.String(rdo("GET", "USER:"+b)); err != nil || bcrypt.CompareHashAndPassword([]byte(rp), []byte("password")) == nil {
				log.Println("Failed to grant admin to user, since user does not exist or their password is still the default:", err)
			} else {
				rdo("SADD", "ADMINS", b)
			}
		}
	} else {
		http.ServeFile(w, r, "core/admin.html")
	}
}

func h(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/core") {
		log.Println("Invalid core request:", r.URL.Path)
		return
	}
	u := getUser(r)
	if r.Method == "PATCH" {
		if noLockOnPage(u, r.URL.Path) {
			log.Println("Attempt to unlock a page without lock")
			return
		}
		rdo("DEL", "PAGE:"+r.URL.Path)
		rdo("DEL", "LOCK:"+u)
	} else if r.Method == "POST" {
		postPage(w, r, u)
	} else if r.Method == "PUT" {
		if notDefaultPassword(u) {
			putPage(w, r, u)
		} else {
			log.Printf("Ignoring attempt to act with default password! (user: %s)\n", u)
		}
	} else {
		fBase := filepath.Base(r.URL.Path)
		if fBase == "shell.js" || fBase == "keymaster.js" {
			http.ServeFile(w, r, filepath.Join("core", fBase))
			return
		}
		path, err := requestToPath(r)
		if err != nil {
			fmt.Fprint(w, err.Error())
		} else {
			servePath(w, path)
		}
	}
}

func postPage(w http.ResponseWriter, r *http.Request, u string) {
	if noLockOnPage(u, r.URL.Path) {
		log.Println("Attempt to edit page without lock")
		return
	}
	b, err := getBody(r)
	if err != nil {
		log.Println("Failed to process POST on root:", err)
	} else {
		rdo("EXPIRE", "PAGE:"+r.URL.Path, pageLockTTL)
		rdo("EXPIRE", "LOCK:"+u, pageLockTTL)
		var cmarkOut bytes.Buffer
		c := exec.Command(config.ProcessCommand)
		c.Stdin = bytes.NewBuffer([]byte(b))
		c.Stdout = &cmarkOut
		c.Stderr = &cmarkOut
		if err := c.Run(); err != nil {
			log.Println("Run failed:", err)
		} else {
			path, err := requestToPath(r)
			if err != nil {
				fmt.Fprint(w, err.Error())
				return
			}
			if !strings.HasSuffix(path, "index.html") {
				return
			}
			srcf, err := os.OpenFile(path+".src", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				fmt.Fprint(w, "Failed to open source file")
				return
			}
			fmt.Fprint(srcf, b)
			err = srcf.Close()
			if err != nil {
				panic("Unable to close source out file:" + err.Error())
			}
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				fmt.Fprint(w, "Failed to open file")
				return
			}
			cmarkOut.WriteTo(f)
			err = f.Close()
			if err != nil {
				panic("Unable to close cmark out file:" + err.Error())
			} else {
				f, err := os.Open(path)
				if err != nil {
					fmt.Fprint(w, "Failed to open path: "+err.Error())
				} else {
					if _, err := io.Copy(w, f); err != nil {
						fmt.Fprint(w, "Failed to write from path:"+err.Error())
					}
				}
			}
		}
	}
}

func putPage(w http.ResponseWriter, r *http.Request, u string) {
	userExists, err := redis.Bool(rdo("EXISTS", "USER:"+u))
	if err != nil {
		log.Println("Attempt to edit with a non-existent account:", u, err)
		fmt.Fprint(w, `{"editable":false}`)
	} else {
		if userExists {
			setCookie(w, r, map[string]string{"u": u})
			pageToLock := r.URL.Path
			lockExists, err := redis.Bool(rdo("EXISTS", "PAGE:"+pageToLock))
			if err != nil {
				log.Println("Unable to test existence of lock for page:", pageToLock, err)
				fmt.Fprint(w, `{"editable":true}`)
			} else if lockExists {
				lockingUser, err := redis.String(rdo("GET", "PAGE:"+pageToLock))
				if err != nil {
					log.Println("Unable to get user for locked page:", pageToLock, err)
					fmt.Fprint(w, `{"editable":false, "reason":"Page is already locked by another user"}`)
				} else {
					if lockingUser == u {
						fmt.Fprint(w, `{"editable":true}`)
					} else {
						fmt.Fprint(w, `{"editable":false, "reason":"Page is currently being edited by someone else"}`)
					}
				}
			} else {
				putPageWithoutLock(w, r, u, pageToLock)
			}
		} else {
			log.Println("Attempt to edit with a user that doesn't exist:", u)
			fmt.Fprint(w, `{"editable":false}`)
		}
	}
}

func putPageWithoutLock(w http.ResponseWriter, r *http.Request, u string, pageToLock string) {
	alreadyLocking, err := redis.Bool(rdo("EXISTS", "LOCK:"+u))
	if err != nil {
		log.Println("Unable to verify if user already has a page locked")
		fmt.Fprint(w, `{"editable":false, "reason":"Unable to verify if the page is locked"}`)
	} else if alreadyLocking {
		lockedPage, err := redis.String(rdo("GET", "LOCK:"+u))
		if err != nil {
			log.Println("Unable to get locked page for user:", u, err)
			fmt.Fprint(w, `{"editable":false, "reason":"Unable to locate the page currently locked by the user"}`)
		} else {
			if lockedPage == pageToLock {
				fmt.Fprint(w, `{"editable":true}`)
			} else {
				fmt.Fprint(w, `{"editable":false, "reason":"Your lock is being used on: `+lockedPage+`"}`)
			}
		}
	} else {
		lockObtained, err := redis.Bool(rdo("SETNX", "PAGE:"+pageToLock, u))
		if err != nil {
			log.Println("Failed to get lock on page where lock does not exist:", pageToLock, err)
			fmt.Fprint(w, `{"editable":false, "reason":"Failed to obtain lock on page"}`)
		} else {
			if lockObtained {
				rdo("SET", "LOCK:"+u, pageToLock)
				rdo("EXPIRE", "PAGE:"+pageToLock, pageLockTTL)
				rdo("EXPIRE", "LOCK:"+u, pageLockTTL)
				fmt.Fprint(w, `{"editable":true}`)
			} else {
				fmt.Fprint(w, `{"editable":false, "reason":"Unable to obtain lock on page"}`)
			}
		}
	}
}

func noLockOnPage(u string, path string) bool {
	if userExists, err := redis.Bool(rdo("EXISTS", "USER:"+u)); err == nil && userExists {
		if pageInLock, err := redis.String(rdo("GET", "LOCK:"+u)); err == nil && pageInLock == path {
			return false
		}
	}
	return true
}

func servePath(w http.ResponseWriter, path string) {
	if _, err := os.Stat(path); err != nil {
		os.MkdirAll(filepath.Dir(path), 0700)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		fmt.Fprint(w, "Failed to open file when serving path")
		return
	}
	if !strings.HasSuffix(path, "index.html") {
		return
	}
	srcf, err := os.OpenFile(path+".src", os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		fmt.Fprint(w, "Failed to open source file when serving path")
		return
	}
	sf, err := os.Open("core/shell.html")
	if err != nil {
		log.Println("Failed to open shell file")
		return
	}
	shellTmp, err := ioutil.ReadAll(sf)
	if err != nil {
		fmt.Fprint(w, "Failed to read shell")
		return
	}
	tmp, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Fprint(w, "Failed to read file")
		return
	}
	srcTmp, err := ioutil.ReadAll(srcf)
	if err != nil {
		fmt.Fprint(w, "Failed to read source file")
		return
	}
	tmpl, err := template.New("shell").Funcs(template.FuncMap{"trim": strings.TrimSpace}).Parse(string(shellTmp))
	if err != nil {
		log.Println("Failed to parse template:", err)
		fmt.Fprint(w, "Failed to process file")
	}
	tmpl.Execute(w, map[string]string{"title": pathToTitle(path), "content": string(tmp), "source": string(srcTmp)})
}

func pathToTitle(path string) string {
	path = strings.TrimSuffix(strings.TrimPrefix(path, config.Webroot), "index.html")
	if path == "/" {
		return config.RootTitle
	} else {
		return config.RootTitle + " - " + strings.Title(strings.TrimSpace(strings.Join(strings.Split(path, "/"), " ")))
	}
}

func requestToDirPath(r *http.Request) (string, error) {
	return urlToDirPath(r.URL)
}

func requestToPath(r *http.Request) (string, error) {
	return urlToPath(r.URL)
}

func urlToDirPath(u *url.URL) (string, error) {
	path, err := urlToPath(u)
	if err != nil {
		return "", err
	} else {
		return strings.TrimSuffix(path, "index.html"), nil
	}
}

func urlToPath(u *url.URL) (string, error) {
	page := u.Path
	if strings.HasSuffix(page, "index.html") || strings.HasSuffix(page, "index.html.src") {
		return "", errors.New("URL Paths must not end with index.html or index.html.src")
	}
	if strings.HasPrefix(page, "/file") {
		fileRef := filepath.Join(config.Webroot, strings.TrimPrefix(page, "/file"))
		if _, err := os.Stat(fileRef); !os.IsNotExist(err) {
			return fileRef, nil
		}
	}
	rSource := `^/(([a-z_]/)*[a-z_])*$`
	rx, err := regexp.Compile(rSource)
	if err != nil {
		panic(fmt.Sprintf("Unable to compile page regexp: %s", err))
	}
	if !rx.MatchString(page) {
		log.Printf("Failed to pass regex: %s, %#v\n", page, u)
		return "", errors.New("URL Paths must follow the regexp: " + rSource)
	}
	if page == "/" {
		page = page + "index.html"
	} else {
		page = page + "/index.html"
	}
	path := filepath.Join(config.Webroot, page)
	return path, nil
}
