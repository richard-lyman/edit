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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/garyburd/redigo/redis"
	"github.com/gorilla/securecookie"
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
	cookie, _ := r.Cookie(cookieName)
	value := make(map[string]string)
	s.Decode(cookieName, cookie.Value, &value)
	return value["u"]
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
					if rp == p {
						setCookie(w, r, map[string]string{"u": u})
						return false
					}
				}
			}
		}
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="edit"`)
	w.WriteHeader(http.StatusUnauthorized)
	return true
}

func newPool() *redis.Pool {
	return &redis.Pool{
		MaxIdle:      3,
		IdleTimeout:  240 * time.Second,
		Dial:         func() (redis.Conn, error) { return redis.Dial("tcp", ":6379") },
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

func main() {
	if len(adminPassword) == 0 {
		panic("The admin password supplied in config.go at pre-compile time must be longer that 0 characters")
	}
	err := os.Mkdir(webroot, 0700)
	if os.IsPermission(err) {
		panic(fmt.Sprintf("Unable to create required webroot directory: '%s'", webroot))
	}
	pool = newPool()
	_, err = rdo("PING")
	if err != nil {
		panic(fmt.Sprintf("A working connection to a Redis instance is required: %s - You may need to tweak the config.go file prior to building.", err))
	}
	rdo("SET", "USER:"+adminUsername, adminPassword)
	rdo("SET", "root", adminUsername)
	rdo("SADD", "ADMINS", adminUsername)
	http.HandleFunc("/", h)
	http.HandleFunc("/toc", t)
	http.HandleFunc("/admin", a)
	http.HandleFunc("/admin/remove", r)
	http.HandleFunc("/user", u)
	http.HandleFunc("/file/", f)
	http.HandleFunc("/lock", l)
	http.HandleFunc("/unlock", ul)
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {})
	log.Println("Listening on "+hostAndPort)
	log.Fatal(http.ListenAndServeTLS(hostAndPort, "cert.pem", "key.pem", authd(http.DefaultServeMux)))
}

func authd(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := authdUser(w, r); err == nil {
			h.ServeHTTP(w, r)
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

func t(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tocFile, err := os.Open("core/toc_style.html")
		if err != nil {
			panic("Failed to open the required file 'core/toc_style.html': " + err.Error())
		}
		tocStyle, err := ioutil.ReadAll(tocFile)
		if err != nil {
			panic("Failed to read contents of the required file 'core/toc_style.html': " + err.Error())
		}
		fmt.Fprint(w, string(tocStyle))
		fmt.Fprint(w, `<div class="toc toc-dir lastEntry"><a href="/">/`+"\n")
		filter := func(p string, i os.FileInfo) bool {
			return !strings.HasSuffix(p, "index.html") && !strings.HasSuffix(p, "index.html.src")
		}
		var handler func(string, os.FileInfo, bool) error
		handler = func(p string, i os.FileInfo, lastEntry bool) error {
			np, err := filepath.Rel(webroot, p)
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
				fmt.Fprint(w, `<div class="toc toc-dir`+extraClass+`"><a href="`+np+`">/`+dnp+`</a>`+"\n")
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
		processDir(webroot, filter, handler)
		fmt.Fprint(w, `</div>`)
	}
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
		if _, err = rdo("SET", "USER:"+u, j["password"]); err != nil {
			log.Println("Failed to change password:", err)
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
			added, err := redis.Int(rdo("SETNX", "USER:"+b, "password"))
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
			if _, err := rdo("GET", "USER:"+b); err != nil {
				log.Println("Failed to grant admin to user, since user does not exist:", err)
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
		putPage(w, r, u)
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
		rdo("EXPIRE", "PAGE:"+r.URL.Path, 600)
		rdo("EXPIRE", "LOCK:"+u, 600)
		var pandocOut bytes.Buffer
		c := exec.Command(processCommand)
		c.Stdin = bytes.NewBuffer([]byte(b))
		c.Stdout = &pandocOut
		c.Stderr = &pandocOut
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
			pandocOut.WriteTo(f)
			err = f.Close()
			if err != nil {
				panic("Unable to close pandoc out file:" + err.Error())
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
					fmt.Fprint(w, `{"editable":false}`)
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
		fmt.Fprint(w, `{"editable":false}`)
	} else if alreadyLocking {
		lockedPage, err := redis.String(rdo("GET", "LOCK:"+u))
		if err != nil {
			log.Println("Unable to get locked page for user:", u, err)
			fmt.Fprint(w, `{"editable":false}`)
		} else {
			if lockedPage == pageToLock {
				fmt.Fprint(w, `{"editable":true}`)
			} else {
				fmt.Fprint(w, `{"editable":false, "reason":"Your lock is being used on: "`+lockedPage+`}`)
			}
		}
	} else {
		lockObtained, err := redis.Bool(rdo("SETNX", "PAGE:"+pageToLock, u))
		if err != nil {
			log.Println("Failed to get lock on page where lock does not exist:", pageToLock, err)
			fmt.Fprint(w, `{"editable":false}`)
		} else {
			if lockObtained {
				rdo("SET", "LOCK:"+u, pageToLock)
				rdo("EXPIRE", "PAGE:"+pageToLock, 600)
				rdo("EXPIRE", "LOCK:"+u, 600)
				fmt.Fprint(w, `{"editable":true}`)
			} else {
				fmt.Fprint(w, `{"editable":false}`)
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
	path = strings.TrimSuffix(strings.TrimPrefix(path, webroot), "index.html")
	if path == "/" {
		return rootTitle
	} else {
		return rootTitle + " - " + strings.Title(strings.TrimSpace(strings.Join(strings.Split(path, "/"), " ")))
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
		fileRef := filepath.Join(webroot, strings.TrimPrefix(page, "/file"))
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
	path := filepath.Join(webroot, page)
	return path, nil
}
