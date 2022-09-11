var RNHashing = RNHashing || (function (Math, undefined) {

    var hash;

    if (typeof window !== 'undefined' && window.hash) {
        hash = window.hash;
    }
    if (typeof self !== 'undefined' && self.hash) {
        hash = self.hash;
    }
    if (typeof globalThis !== 'undefined' && globalThis.hash) {
        hash = globalThis.hash;
    }
    if (!hash && typeof window !== 'undefined' && window.msCrypto) {
        hash = window.msCrypto;
    }

    if (!hash && typeof global !== 'undefined' && global.hash) {
        hash = global.hash;
    }

    if (!hash && typeof require === 'function') {
        try {
            hash = require('crypto');
        } catch (err) {}
    }

    var cryptoSecureRandomInt = function () {
        if (hash) {
            if (typeof hash.getRandomValues === 'function') {
                try {
                    return hash.getRandomValues(new Uint32Array(1))[0];
                } catch (err) {}
            }

            if (typeof hash.randomBytes === 'function') {
                try {
                    return hash.randomBytes(4).readInt32LE();
                } catch (err) {}
            }
        }

        throw new Error('Native crypto module could not be used to get secure random number.');
    };

    var create = Object.create || (function () {
        function F() {}

        return function (obj) {
            var subtype;

            F.prototype = obj;

            subtype = new F();

            F.prototype = null;

            return subtype;
        };
    }());

    var H = {};
    var H_lib = H.lib = {};
    var Base = H_lib.Base = (function () {


        return {

            extend: function (overrides) {
                var subtype = create(this);
                if (overrides) {
                    subtype.mixIn(overrides);
                }

                if (!subtype.hasOwnProperty('init') || this.init === subtype.init) {
                    subtype.init = function () {
                        subtype.$super.init.apply(this, arguments);
                    };
                }
                subtype.init.prototype = subtype;
                subtype.$super = this;
                return subtype;
            },

            create: function () {
                var instance = this.extend();
                instance.init.apply(instance, arguments);
                return instance;
            },

            init: function () {
            },

            mixIn: function (properties) {
                for (var propertyName in properties) {
                    if (properties.hasOwnProperty(propertyName)) {
                        this[propertyName] = properties[propertyName];
                    }
                }
                if (properties.hasOwnProperty('toString')) {
                    this.toString = properties.toString;
                }
            },

            clone: function () {
                return this.init.prototype.extend(this);
            }
        };
    }());

    var WordArray = H_lib.WordArray = Base.extend({

        init: function (words, sigBytes) {
            words = this.words = words || [];
            if (sigBytes != undefined) {
                this.sigBytes = sigBytes;
            } else {
                this.sigBytes = words.length * 4;
            }
        },

        toString: function (encoder) {
            return (encoder || Hex).stringify(this);
        },

        concat: function (wordArray) {
            var thisWords = this.words;
            var thatWords = wordArray.words;
            var thisSigBytes = this.sigBytes;
            var thatSigBytes = wordArray.sigBytes;
            this.clamp();
            if (thisSigBytes % 4) {
                for (var i = 0; i < thatSigBytes; i++) {
                    var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                    thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
                }
            } else {
                for (var j = 0; j < thatSigBytes; j += 4) {
                    thisWords[(thisSigBytes + j) >>> 2] = thatWords[j >>> 2];
                }
            }
            this.sigBytes += thatSigBytes;
            return this;
        },

        clamp: function () {
            var words = this.words;
            var sigBytes = this.sigBytes;
            words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
            words.length = Math.ceil(sigBytes / 4);
        },

        clone: function () {
            var clone = Base.clone.call(this);
            clone.words = this.words.slice(0);

            return clone;
        },

        random: function (nBytes) {
            var words = [];

            for (var i = 0; i < nBytes; i += 4) {
                words.push(cryptoSecureRandomInt());
            }

            return new WordArray.init(words, nBytes);
        }
    });

    var H_enc = H.enc = {};

    var Hex = H_enc.Hex = {
        stringify: function (wordArray) {
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;
            var hexChars = [];
            for (var i = 0; i < sigBytes; i++) {
                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                hexChars.push((bite >>> 4).toString(16));
                hexChars.push((bite & 0x0f).toString(16));
            }

            return hexChars.join('');
        },

        parse: function (hexStr) {
            var hexStrLength = hexStr.length;
            var words = [];
            for (var i = 0; i < hexStrLength; i += 2) {
                words[i >>> 3] |= parseInt(hexStr.substring(i, 2), 16) << (24 - (i % 8) * 4);
            }

            return new WordArray.init(words, hexStrLength / 2);
        }
    };

    var Latin1 = H_enc.Latin1 = {

        stringify: function (wordArray) {
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;
            var latin1Chars = [];
            for (var i = 0; i < sigBytes; i++) {
                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                latin1Chars.push(String.fromCharCode(bite));
            }

            return latin1Chars.join('');
        },

        parse: function (latin1Str) {
            var latin1StrLength = latin1Str.length;

            var words = [];
            for (var i = 0; i < latin1StrLength; i++) {
                words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
            }

            return new WordArray.init(words, latin1StrLength);
        }
    };

    var Utf8 = H_enc.Utf8 = {
        stringify: function (wordArray) {
            try {
                return decodeURIComponent(escape(Latin1.stringify(wordArray)));
            } catch (e) {
                throw new Error('Malformed UTF-8 data');
            }
        },

        parse: function (utf8Str) {
            return Latin1.parse(decodeURI(encodeURIComponent(utf8Str)));
        }
    };

    var BufferedBlockAlgorithm = H_lib.BufferedBlockAlgorithm = Base.extend({

        reset: function () {
            this._data = new WordArray.init();
            this._nDataBytes = 0;
        },

        _append: function (data) {
            if (typeof data == 'string') {
                data = Utf8.parse(data);
            }
            this._data.concat(data);
            this._nDataBytes += data.sigBytes;
        },

        _process: function (doFlush) {
            var processedWords;
            var data = this._data;
            var dataWords = data.words;
            var dataSigBytes = data.sigBytes;
            var blockSize = this.blockSize;
            var blockSizeBytes = blockSize * 4;
            var nBlocksReady = dataSigBytes / blockSizeBytes;
            if (doFlush) {
                nBlocksReady = Math.ceil(nBlocksReady);
            } else {
                nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
            }
            var nWordsReady = nBlocksReady * blockSize;
            var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

            if (nWordsReady) {
                for (var offset = 0; offset < nWordsReady; offset += blockSize) {
                    this._doProcessBlock(dataWords, offset);
                }
                processedWords = dataWords.splice(0, nWordsReady);
                data.sigBytes -= nBytesReady;
            }
            return new WordArray.init(processedWords, nBytesReady);
        },

        /**
         * @return {Object}
         */
        clone: function () {
            var clone = Base.clone.call(this);
            clone._data = this._data.clone();

            return clone;
        },

        _minBufferSize: 0
    });

    /**
     * @property {number} blockSize
     */
    var Hasher = H_lib.Hasher = BufferedBlockAlgorithm.extend({
        cfg: Base.extend(),
        /**
         * @param {Object} cfg 
         */
        init: function (cfg) {
            this.cfg = this.cfg.extend(cfg);
            this.reset();
        },

        reset: function () {
            BufferedBlockAlgorithm.reset.call(this);
            this._doReset();
        },

        /**
         * @param {WordArray|string} messageUpdate
         * @return {Hasher}
         */
        update: function (messageUpdate) {
            this._append(messageUpdate);
            this._process();
            return this;
        },

        /**
         * @param {WordArray|string} messageUpdate
         * @return {WordArray}
         */
        finalize: function (messageUpdate) {
            if (messageUpdate) {
                this._append(messageUpdate);
            }
            var hash = this._doFinalize();

            return hash;
        },

        blockSize: 512/32,

        /**
         * @param {Hasher} hasher 
         * @return {Function} 
         * @static
         */
        _createHelper: function (hasher) {
            return function (message, cfg) {
                return new hasher.init(cfg).finalize(message);
            };
        },

        /**
         * @param {Hasher} hasher
         * @return {Function} 
         * @static
         * @example
        */
        _createHmacHelper: function (hasher) {
            return function (message, key) {
                return new H_algo.HMAC.init(hasher, key).finalize(message);
            };
        }
    });

    var H_algo = H.algo = {};

    return H;
}(Math));