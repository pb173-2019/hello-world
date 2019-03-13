## SECURITY MODEL - DETAILED DECRIPTION

### SERVER data
The server has to store some data to be able to perform its duties.

Valuable server data:
- messages from users, (user authentication key bundles)
- user info
- server private key

Who has access?
- only the other user the message was meant to
- all users
- only code

What are the threads?
- unauthorized access to the server data

What is the protection?
- each message is encrypted with key that is known only to the sender and receiver, X3DH ensures, that no other can re-construct
the secure channel establishment, and every message is encrypted with different symmetric key
- user info stored in open form but harmless (e.g. user login, user public key), personal data parts are encrypted (e.g. email if stored - future)
- the key is a part of program not visible from outside

### SERVER - CLIENT communication
The client - server communication is to enable the user to send commands to the server to perform.

Valuable data:
- request & response messages

Who has access?
- only client sending the request and server

What are the threads?
- **DoS** - many requests from unresponsive "users"
- **MitmM** - main in the middle: _Ip spoofing_ - pretend to be the user | _Replay_ - re-sending data
- **Password attack** - guessing or dictionary attack
- **Injection** - sending request in message to database 
- **Eavesdropping** - channel transmission
- **Birthday attack** - against integrity

What is the protection?
- **DoS** - big queue & short server response timeout, possibly temporary IP ban
- **MitmM** - considered below
- **Password attack** - client responsibility to use strong password & do not share it
- **Injection** - do not execute input from user as a code 
- **Eavesdropping** - all communication encrypted, protocol use protection, also below
- **Birthday attack** - each message send along with HMAC, seeded from system entropy source

##### channel establishment
1. Registration - Client app generates asymmetric key pair for new user, generates session key (AES-128), 
sends encrypted session key to the server using server public key and stores user private key encrypted with user hash 
from user password. If attack is performed at this point, key (and data) is safe.
Integrity violation will result in connection failure, as the AES key will be either damaged or unable to encrypt message.
Server keeps the session key for the session lifetime, and from now on, uses it to compute HMAC, so message integrity is secured.
Server also encrypts random data with user public key and sends challenge to the user. User will be required to decrypt data and 
send the original data to the user (optionally append registration data). 
Server verifies the result (optionally saves registration info). From now on, server uses session key for further communication.
No attack is possible, the data cannot be modified and the registration info is harmless (uses the same security level as storage).
2. Authentication - Client app requests password to decrypt private key of user, uses server public key to encrypt new session key, 
sends login and encrypted session key (from now on, HMAC is used), server uses client's public key to encrypt random data, 
and send challenge to the client, who encrypts message and sends it to server to compare. No attack is possible, as either modification is
impossible or will result in establishment failure. Re-sending the request is pointless, as the request in accepted only once.
Attacker might "steal" the challenge "request" (as everything the client sends is request), but has no way of knowing the session key, 
and thuss cannot generate correct HMAC or read data from server).
3. Secure request-response exchange - uses established channel with session key & HMAC.
4. Cleanup - Server and client deletes session key and session other info.


### CLIENT - CLIENT communication
The client - client communication is the app main functionality.

Valuable data:
- messages and other data exchanged

Who has access?
- only sender & receiver

What are the threads?
- **MitmM** - main in the middle: _Ip spoofing_ - pretend to be the user | _Replay_ - re-sending data
- **Eavesdropping** - channel transmission
- **Birthday attack** - against integrity

What is the protection?
- **MitmM** - considered below
- **Eavesdropping** - all communication encrypted, protocol use protection, also below
- **Birthday attack** - each message send along with HMAC, seeded from system entropy source

##### channel establishment
1. **X3DH:** Sender obtains reveiver's public key & signature bundle from server and generates another data, processed by receiver. The initial message acts as a secure key agreement. Further messages are sent using **Ratchet protocol** key derivation, as the key changes with each message. The key agreement procedure cannot be reconstructed by third party, as it uses both sender and receiver private keys.
Also, key derivation uses their private keys. In case the attacker learns any shared key and encrypts one message, other messages are
completely safe and enrypting any message requires (regardless the amount of other messages decrypted) the same effort.
2. Cleanup - Both client sides are required to delete all keys derived in the communication process.

### CLIENT data
The client has to store some data to be able to perform its duties and also to enbale the user to read communication history.

Valuable data:
- messages
- user private keys

Who has access?
- only user
- only user

What are the threads?
- unauthorized access to client storage
- **Password attack** - guessing or dictionary attack

What is the protection?
- encrypt all user data with key obtained from user password (or potentionally use password to encrypt data encryption key)
- **Password attack** - mainly user reponsibility, altough some password form requirements may apply
