### Overview
 * A wiki
 * Minimalist
 * Requires Pandoc
 * Editing a page locks it
 * Users can only have one locked page at a time
 * Accounts can be added or removed easily and pages can be locked from future changes
 * Files can be uploaded and linked inline
 * Output is a static page
 * Requires Redis
 * ACE editor
 * A wiki

### PreReqs
 * A reachable Redis Server
  1. wget http://download.redis.io/redis-stable.tar.gz
  1. tar xzf redis-stable.tar.gz
  1. cd redis-stable
  1. make
  1. sudo make install
  1. cd utils/
  1. sudo ./install_server.sh
  1. sudo /etc/init.d/redis_6379 start
 * A usable pandoc installed
  1. sudo apt-get install haskell-platform
  1. cabal update
  1. cabal install pandoc

### Running
 1. ```git clone https://github.com/richard-lyman/edit.git```
 1. Tweak the config (you must at least provide the admin password)
 1. ```go get ./...```
 1. ```go build```
 1. Provide or generate a cert.pem and key.pem (see below)
 1. ```./edit``` or ```sudo ./edit```

### Using
 1. Open a URL
 1. Login using 'admin' and the password you provided above or some other account
 1. Press Ctrl-e
 1. Enter [Pandoc Markdown](http://johnmacfarlane.net/pandoc/demo/example9/pandocs-markdown.html)
 1. Press Ctrl-s
 1. Click on the Lock icon to let someone else edit the page, or wait for the lock to timeout

### Extra
 * There is an admin page at /admin
 * There is a Table-of-Contents at /toc
 * URLs must all be lowercase a-z or '/' or '_'
 * Ctrl-e will toggle the edit panel

### Generating a cert.pem and key.pem
 1. Generate a new unencrypted rsa private key in PEM format:
  * ```openssl genrsa -out key.pem 1024```
 1. Create a certificate signing request (CSR) using your rsa private key:
  * ```openssl req -new -key key.pem -out cert.csr```
 1. Self-sign your CSR with your own private key:
  * ```openssl x509 -req -days 3650 -in cert.csr -signkey key.pem -out cert.pem```

