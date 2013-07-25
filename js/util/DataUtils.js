/**
 * This class contains utilities to help parse the data
 * author: Meki Cheraoui, Jeff Thompson
 * See COPYING for copyright and distribution information.
 */
 
var DataUtils = function DataUtils () {};


/**
 * Uint8Array to Hex String
 */
//http://ejohn.org/blog/numbers-hex-and-colors/
DataUtils.toHex = function(args){
    var ret = "";
    for ( var i = 0; i < args.length; i++ )
    	ret += (args[i] < 16 ? "0" : "") + args[i].toString(16);
    if (LOG>4) console.log('Converted to: ' + ret);
    return ret;
};

/**
 * Raw string to hex string.
 */
DataUtils.stringToHex = function(args){
    var ret = "";
    for (var i = 0; i < args.length; ++i) {
	var value = args.charCodeAt(i);
	ret += (value < 16 ? "0" : "") + value.toString(16);
    }
    return ret;
};

/**
 * Uint8Array to raw string.
 */
DataUtils.toString = function(args){
    var ret = "";
    for (var i = 0; i < args.length; i++ )
	ret += String.fromCharCode(args[i]);
    return ret;
};

/**
 * Hex String to Uint8Array.
 */
DataUtils.toNumbers = function(str) {
    if (typeof str == 'string') {
	var ret = new Uint8Array(Math.floor(str.length / 2));
	var i = 0;
	str.replace(/(..)/g, function(str) {
		ret[i++] = parseInt(str, 16);
	    });
	return ret;
    }
};

/**
 * Raw String to Uint8Array.
 */
DataUtils.toNumbersFromString = function(str) {
    var bytes = new Uint8Array(str.length);
    for(var i=0;i<str.length;i++)
	bytes[i] = str.charCodeAt(i);
    return bytes;
};


/**
 * Convert a base64 string to Uint8Array
 */
DataUtils.toNumbersFromBase64 = function (s) {
    //piggyback on b64tohex for now, optimize later
    var h = b64tohex(s);  // Requires 'securityLib/base64.js'
    var i;
    var a = new Uint8Array(h.length / 2);
    for(i = 0; 2*i < h.length; ++i) {
	a[i] = parseInt(h.substring(2*i,2*i+2),16);
    }
    return a;
};


/**
 * Uint8Array to base64 string
 */
DataUtils.toBase64 = function (arg) {
    var hex = DataUtils.toHex(arg);
    return hex2b64(hex);  // Requires 'securityLib/base64.js'
};

/**
 * arrays is an array of Uint8Array. Return a new Uint8Array which is the concatenation of all.
 */
DataUtils.concatArrays = function(arrays) {
    var totalLength = 0;
    for (var i = 0; i < arrays.length; ++i)
	totalLength += arrays[i].length;
    
    var result = new Uint8Array(totalLength);
    var offset = 0;
    for (var i = 0; i < arrays.length; ++i) {
	result.set(arrays[i], offset);
	offset += arrays[i].length;
    }
    return result;
};
 

/**
 * Return true if a1 and a2 are the same length with equal elements.
 */
DataUtils.arraysEqual = function(a1, a2){
    if (a1.length != a2.length)
        return false;
    
    for (var i = 0; i < a1.length; ++i) {
        if (a1[i] != a2[i])
            return false;
    }

    return true;
};

/**
 * Convert the big endian Uint8Array to an unsigned int.
 */
DataUtils.bigEndianToUnsignedInt = function (bytes) {
    return parseInt(DataUtils.toHex(bytes), 16);
};

/**
 * Convert the int value to a new big endian Uint8Array.
 * Throw an Error if value is 0 or negative. 
 */
DataUtils.unsignedIntToBigEndian = function (value) {
    if (value < 0)
        throw new Error('Require unsigned int but get negative value: ' + value);

    var hex = Math.round(value).toString(16);
    if (hex.length % 2 == 1)
	hex = '0' + hex;
    
    return DataUtils.toNumbers(hex);
};
