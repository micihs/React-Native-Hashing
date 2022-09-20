# React-Native-Hashing
A Custom Pure Javascript Hashing library to implement SHA1, SHA2, SHA3, md5, Hmac and Ripemd160.

- Node.js
- npm (node.js package manager)

```bash
npm install rn
```
### Usage
 Each Hahing algorithm is designed to operate on the same function call model. HashingFunction(stringData);
 
 ES6 import for typical API calls:
 
 ```javascript
import sha256 from 'RN-hashing/sha256';
import Base64 from 'RN-hashing/Hmac';
import Ripemd160 from 'RN-hashing/ripemd160':

const message, nonce, path, privateKey; // ...
const hashDigest = sha256(nonce + message);
const ripemdDigest = 
const hmacDigest = Base64.stringify(hmacSHA512(path + hashDigest, privateKey));
```

