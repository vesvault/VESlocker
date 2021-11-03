/***************************************************************************
 *          ___       ___
 *         /   \     /   \    VESvault
 *         \__ /     \ __/    Encrypt Everything without fear of losing the Key
 *            \\     //                   https://vesvault.com https://ves.host
 *             \\   //
 *     ___      \\_//
 *    /   \     /   \         VESlocker:        Hardware-level PIN Security API
 *    \__ /     \ __/
 *       \\     //            https://veslocker.com
 *        \\   //
 *         \\_//
 *         /   \
 *         \___/
 *
 *
 * (c) 2021 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * GNU General Public License v3
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

function VESlocker(optns) {
    for (var k in optns) this[k] = optns[k];
    if (!this.defaultUrl) this.defaultUrl = this.apiUrl;
    return this;
};

VESlocker.prototype.prefix = "VESlocker_";

VESlocker.prototype.getKey = function(id, seed, pin, url) {
    var self = this;
    var s = VESlocker.B64ToByteArray(seed);
    var p = VESlocker.StringToByteArray(pin);
    var b = new Uint8Array(s.byteLength + p.byteLength);
    b.set(new Uint8Array(s), 0);
    b.set(new Uint8Array(p), s.byteLength);
    return crypto.subtle.digest("SHA-256", b).then(function(hash) {
	var frm = "id=" + escape(id) + "&challenge=" + escape(VESlocker.ByteArrayToB64(hash));
	return new Promise(function(resolve,reject) {
	    var xhr = new XMLHttpRequest();
	    xhr.open("POST", (url ? url : self.apiUrl));
	    xhr.onreadystatechange = function() {
		switch(xhr.readyState) {
		    case 4:
			switch (xhr.status) {
			    case 200:
				var ac = xhr.getResponseHeader("X-VESlocker-Access-Count");
				if (ac) try {
				    var at = xhr.getResponseHeader("Last-Modified");
				    self.accessFn(id, Number(ac), (at ? new Date(at) : null));
				} catch (e) {}
				return resolve(crypto.subtle.importKey('raw', VESlocker.B64ToByteArray(xhr.response), 'AES-GCM', true, ['encrypt', 'decrypt']));
			    case 403:
				var rf = xhr.getResponseHeader("Refresh");
				if (rf) {
				    var secs = Number(rf.split(';')[0]);
				    if (!isNaN(secs)) return reject({code: -1, name: "Retry", retry: secs});
				}
			    default:
				return reject({code: xhr.status, name: "HttpError", message: xhr.response});
			}
		}
	    };
	    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
	    xhr.send(frm);
	});
    });
};

VESlocker.prototype.accessFn = function(id, access_count, access_at) {
/* Override this function to issue VESlocker access alerts */
    if (access_count > 0) console.log("VESlocker Key '" + id + "' has been accessed " + access_count + " times, last access on " + access_at);
};

VESlocker.prototype.newId =
VESlocker.prototype.newSeed = function() {
    return VESlocker.rand32();
};

VESlocker.prototype.encrypt = function(pin, val) {
    var self = this;
    var id = this.newId();
    var seed = this.newSeed();
    return this.getKey(id, seed, pin).then(function(key) {
	return crypto.subtle.encrypt(VESlocker.algoInfo(seed), key, VESlocker.StringToByteArray(val)).then(function(ctext) {
	    return self.apiUrl + '#' + id + '.' + seed + '.' + VESlocker.ByteArrayToB64(ctext);
	}).catch(function(e) {
	    throw {code: -12, name: "CryptoError", message: "Encryption Error", error: e};
	});
    });
};

VESlocker.prototype.decrypt = function(pin, ctoken) {
    var csp = ctoken.match(/^(.*)\#(.*)$/);
    var url = csp ? csp[1] : this.defaultUrl;
    var lsp = (csp ? csp[2] : ctoken).split(/\./);
    return this.getKey(lsp[0], lsp[1], pin, url).then(function(key) {
	return crypto.subtle.decrypt(VESlocker.algoInfo(lsp[1]), key, VESlocker.B64ToByteArray(lsp[2])).then(function(ptext) {
	    return VESlocker.ByteArrayToString(ptext);
	}).catch(function(e) {
	    throw {code: -12, name: "CryptoError", message: "Decryption Error (wrong pin?)", error: e};
	});
    });
};

VESlocker.prototype.store = function(name, pin, val) {
    var self = this;
    return self.encrypt(pin, val).then(function(ctoken) {
	localStorage[self.prefix + name] = ctoken;
	return val;
    });
};

VESlocker.prototype.peek = function(name, pin) {
    var ls = localStorage[this.prefix + name];
    if (!ls) return Promise.reject({code: -11, name: "NotFound", message: "Not stored in local VESlocker"});
    return this.decrypt(pin, ls);
};

VESlocker.prototype.fetch = function(name, pin, new_pin) {
    var self = this;
    if (new_pin == null) new_pin = pin;
    return self.peek(name, pin).then(function(val) {
	return self.store(name, new_pin, val);
    });
};

VESlocker.prototype.exists = function(name) {
    return !!localStorage[this.prefix + name];
};

VESlocker.prototype.delete = function(name) {
    delete(localStorage[this.prefix + name]);
};

VESlocker.prototype.rename = function(name, newname) {
    var v = localStorage[this.prefix + name];
    delete(localStorage[this.prefix + name]);
    return localStorage[this.prefix + newname] = v;
};



VESlocker.B64ToByteArray = function(s) {
    var buf = new Uint8Array(s.length);
    var boffs = 0;
    for (var i = 0; i < s.length; i++) {
	var p = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_".indexOf(s[i]);
	if (p >= 0) {
	    if (p >= 64) p -= 2;
	    buf[boffs >> 3] |= p << 2 >> (boffs & 7);
	    boffs += 6;
	    if ((boffs & 7) < 6) buf[boffs >> 3] |= p << (8 - (boffs & 7));
	}
    }
    var l = boffs >> 3;
    return buf.slice(0, l).buffer;
};

VESlocker.ByteArrayToB64 = function(b) {
    var buf = new Uint8Array(b);
    var s = "";
    var boffs = 0;
    while ((boffs >> 3) < buf.byteLength) {
	var c = (buf[boffs >> 3] << (boffs & 7)) & 0xfc;
	boffs += 6;
	if (((boffs & 7) < 6) && ((boffs >> 3) < buf.byteLength)) c |= (buf[boffs >> 3] >> (6 - (boffs & 7)));
	s += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[c >> 2];
    }
    return s;
};

VESlocker.StringToByteArray = function(s) {
    var rs = new Uint8Array(4 * s.length);
    var j = 0;
    for (var i = 0; i < s.length;i++) {
	var c = s.charCodeAt(i);
	if (c >= 0x80) {
	    if (c >= 0x0800) {
		if (c >= 0x10000) {
		    rs[j++] = (c >> 16) | 0xf0;
		    rs[j++] = ((c >> 12) & 0x3f) | 0x80;
		} else rs[j++] = ((c >> 12) & 0x0f) | 0xe0;
		rs[j++] = ((c >> 6) & 0x3f) | 0x80;
	    } else rs[j++] = ((c >> 6) & 0x1f) | 0xc0;
	    rs[j++] = (c & 0x3f) | 0x80;
	} else rs[j++] = c;
    }
    return rs.slice(0,j).buffer;
};

VESlocker.ByteArrayToString = function(b) {
    var buf = new Uint8Array(b);
    var rs = '';
    var c;
    for (var i = 0; i < buf.length; i++) {
	var v = buf[i];
	if (v & 0x80) {
	    if (v & 0x40) {
		c = ((v & 0x1f) << 6) | (buf[++i] & 0x3f);
		if (v & 0x20) {
		    c = (c << 6) | (buf[++i] & 0x3f);
		    if (v & 0x10) c = ((c & 0xffff) << 6) | (buf[++i] & 0x3f);
		}
	    } else c = -1;
	} else c = buf[i];
	rs += String.fromCharCode(c);
    }
    return rs;
};

VESlocker.rand32 = function() {
    var buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    return VESlocker.ByteArrayToB64(buf);
};

VESlocker.algoInfo = function(seed) {
    var iv = new Uint8Array(12);
    iv.set(new Uint8Array(VESlocker.B64ToByteArray(seed).slice(0, 12)), 0);
    return {name: "AES-GCM", iv: iv};
};
