# React-Native-Hashing
A Custom Pure Javascript Hashing library to implement SHA1, SHA2, SHA3, md5 and Ripemd160.

- Node.js
- npm (node.js package manager)

```bash
npm install RN-hashing
```
### Usage
 Each Hahing algorithm is designed to operate on the same function call model. HashingFunction(stringData);
 
 ES6 import for typical API calls:
 
 ```javascript
import sha256 from 'RN-hashing/sha256';
import Ripemd160 from 'RN-hashing/ripemd160':

const message, nonce, path, privateKey; // ...
const hashDigest = sha256(nonce + message);
```
Each hashing Function call emulates the template above.

# list of Modules / Hashing Algorithms.
---
- ```RN-hashing/sha1```
- ```RN-hashing/sha224```
- ```RN-hashing/sha256```
- ```RN-hashing/sha384```
- ```RN-hashing/sha512```
- ```RN-hashing/md5```
- ```RN-hashing/Ripemd160```
- ```RN-hashing/md5```
---
