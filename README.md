### Overview
 * A wiki
 * Minimalist
 * Requires cmark
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
 * A usable cmark installed (*Note: cmake and cmark are different programs*)
  1. sudo apt-get install cmake
  1. git clone https://github.com/jgm/cmark.git
  1. cd cmark
  1. make
  1. sudo make install

### Running
 1. Download an OS+Architecture appropriate release
 1. Extract and run with the 'gen' flag to create a sample config file (in Linux you might run: ```./edit -gen```)
 1. Tweak the config.json file as needed
 1. Provide or generate a cert.pem and key.pem (see below)
 1. Run the edit binary (in Linux you might run: ```./edit```)
  * If you want to run on a privileged port, I recommend using [CAP_NET_BIND_SERVICE](http://stackoverflow.com/questions/413807/is-there-a-way-for-non-root-processes-to-bind-to-privileged-ports-1024-on-l/414258#414258) instead of sudo

### Using
 1. Open a URL
 1. Login using a valid account. The default is 'admin'/'password' - you can not do anything (other than change the password) without changing this password (see below)
 1. Press Ctrl-e
 1. Enter [CommonMark](http://commonmark.org/)
 1. Press Ctrl-s
 1. Click on the Lock icon to let someone else edit the page, or wait for the lock to timeout

### Extra
 * Change your password by clicking on the menu button in the upper-right corner
 * There is an admin page at /admin
 * There is a Table-of-Contents at /toc
 * URL Paths are only allowed to contain lowercase a-z or '/' or '_'
 * Ctrl-e will toggle the edit panel

### Generating a cert.pem and key.pem
 1. Generate a new unencrypted rsa private key in PEM format:
  * ```openssl genrsa -out key.pem 1024```
 1. Create a certificate signing request (CSR) using your rsa private key:
  * ```openssl req -new -key key.pem -out cert.csr```
 1. Self-sign your CSR with your own private key:
  * ```openssl x509 -req -days 3650 -in cert.csr -signkey key.pem -out cert.pem```

### LICENSE
You can find the license in the LICENSE file.

