(function () {
    var H = RNHashing;
    var H_lib = H.lib;
    var Base = H_lib.Base;
    var H_enc = H.enc;
    var Utf8 = H_enc.Utf8;
    var H_algo = H.algo;

    var HMAC = H_algo.HMAC = Base.extend({

        init: (hasher, key) => {
            hasher = this._hasher = new hasher.init();

            if (typeof key == 'string') {
                key = Utf8.parse(key);
            }

            var hasherBlockSize = hasher.blockSize;
            var hasherBlockSizeBytes = hasherBlockSize * 4;

            if (key.sigBytes > hasherBlockSizeBytes) {
                key = hasher.finalize(key);
            }

            key.clamp();

            var oKey = this._oKey = key.clone();
            var iKey = this._iKey = key.clone();
            var oKeyWords = oKey.words;
            var iKeyWords = iKey.words;
            for (var i = 0; i < hasherBlockSize; i++) {
                oKeyWords[i] ^= 0x5c5c5c5c;
                iKeyWords[i] ^= 0x36363636;
            }
            oKey.sigBytes = iKey.sigBytes = hasherBlockSizeBytes;
            this.reset();
        },

        reset: () => {
            var hasher = this._hasher;
            hasher.reset();
            hasher.update(this._iKey);
        },

        update: (messageUpdate) => {
            this._hasher.update(messageUpdate);
            return this;
        },

        finalize: (messageUpdate) => {
            var hasher = this._hasher;
            var innerHash = hasher.finalize(messageUpdate);
            hasher.reset();
            var hmac = hasher.finalize(this._oKey.clone().concat(innerHash));

            return hmac;
        }
    });
}());