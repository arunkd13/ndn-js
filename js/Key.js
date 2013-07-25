/**
 * @author: Meki Cheraoui, Wentao Shang
 * See COPYING for copyright and distribution information.
 * This class represents Key Objects
 */

var Key = function Key () {
    this.publicKeyDer = null;     // Uint8Array
    this.publicKeyDigest = null;  // Uint8Array
    this.publicKeyPem = null;     // String
    this.privateKeyPem = null;    // String
};

Key.prototype.publicToDER = function () {
    return this.publicKeyDer;  // Buffer
};

Key.prototype.privateToDER = function () {
    // Remove the '-----XXX-----' from the beginning and the end of the key
    // and also remove any \n in the key string
    var lines = this.privateKeyPem.split('\n');
    priKey = "";
    for (var i = 1; i < lines.length - 1; i++)
	priKey += lines[i];
    return DataUtils.toNumbersFromBase64(priKey);    
};

Key.prototype.publicToPEM = function () {
    return this.publicKeyPem;
};

Key.prototype.privateToPEM = function () {
    return this.privateKeyPem;
};

Key.prototype.getKeyID = function () {
    return this.publicKeyDigest;
};

Key.prototype.readDerPublicKey = function (pub_der) {
    if (LOG > 4) console.log("Encode DER public key:\n" + DataUtils.toHex(pub_der));

    this.publicKeyDer = pub_der;

    var md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "cryptojs"});
    md.updateHex(DataUtils.toHex(this.publicKeyDer));
    var mdHex = md.digest();
    this.publicKeyDigest = DataUtils.toNumbers(mdHex);
    
    var keyStr = DataUtils.toBase64(pub_der);
    var keyPem = "-----BEGIN PUBLIC KEY-----\n";
    for (var i = 0; i < keyStr.length; i += 64)
	keyPem += (keyStr.substr(i, 64) + "\n");
    keyPem += "-----END PUBLIC KEY-----";

    this.publicKeyPem = keyPem;

    if (LOG > 4) console.log("Convert public key to PEM format:\n" + this.publicKeyPem);
};

Key.prototype.fromPem = function (pub, pri) {
    if (pub == null && pri == null) {
	throw new Error('Cannot create Key object if both public and private PEM strings are empty.');
    }

    // Read public key
    if (pub != null && pub.length > 0) {
	this.publicKeyPem = pub;
	if (LOG>4) console.log("Key.publicKeyPem: \n" + this.publicKeyPem);
	
	// Remove the '-----XXX-----' from the beginning and the end of the public key
	// and also remove any \n in the public key string
	var lines = pub.split('\n');
	pub = "";
	for (var i = 1; i < lines.length - 1; i++)
	    pub += lines[i];
	this.publicKeyDer = DataUtils.toNumbersFromBase64(pub);
	if (LOG>4) console.log("Key.publicKeyDer: \n" + DataUtils.toHex(this.publicKeyDer));
	
	var md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "cryptojs"});
	md.updateHex(DataUtils.toHex(this.publicKeyDer));
	var mdHex = md.digest();
	this.publicKeyDigest = DataUtils.toNumbers(mdHex);
	if (LOG>4) console.log("Key.publicKeyDigest: \n" + DataUtils.toHex(this.publicKeyDigest));
    }

    // Read private key
    if (pri != null && pri.length > 0) {
	this.privateKeyPem = pri;
	if (LOG>4) console.log("Key.privateKeyPem: \n" + this.privateKeyPem);
    }
};

/**
 * Static method that create a Key object.
 * Parameter 'obj' is a JSON object that has two properties:
 *   pub: the PEM string for the public key
 *   pri: the PEM string for the private key
 * Will throw an Error if both obj.pub and obj.pri are null.
 */
Key.createFromPEM = function (obj) {
    var key = new Key();
    key.fromPem(obj.pub, obj.pri);
    return key;
};

Key.getSubjectPublicKeyPosFromHex = function (hPub) {  
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(hPub, 0); 
    if (a.length != 2) return -1;
    var pBitString = a[1];
    if (hPub.substring(pBitString, pBitString + 2) != '03') return -1;
    var pBitStringV = ASN1HEX.getStartPosOfV_AtObj(hPub, pBitString);
    if (hPub.substring(pBitStringV, pBitStringV + 2) != '00') return -1;
    return pBitStringV + 2;
};

Key.readPublicDER = function (pub_der) {
    var hex = DataUtils.toHex(pub_der);
    var p = Key.getSubjectPublicKeyPosFromHex(hex);
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(hex, p);
    if (a.length != 2) return null;
    var hN = ASN1HEX.getHexOfV_AtObj(hex, a[0]);
    var hE = ASN1HEX.getHexOfV_AtObj(hex, a[1]);
    var rsaKey = new RSAKey();
    rsaKey.setPublic(hN, hE);
    return rsaKey;
};

/**
 * KeyLocator
 */
var KeyLocatorType = {
    KEY:1,
    CERTIFICATE:2,
    KEYNAME:3
};

var KeyLocator = function KeyLocator(_input,_type){ 
    this.type = _type;
    
    if (_type == KeyLocatorType.KEYNAME){
    	if (LOG>3) console.log('KeyLocator: SET KEYNAME');
    	this.keyName = new KeyName(_input);  // KeyName
    }
    else if (_type == KeyLocatorType.KEY){
    	if (LOG>3) console.log('KeyLocator: SET KEY');
    	this.publicKey = _input;  // Key
    }
    else if (_type == KeyLocatorType.CERTIFICATE){
    	if (LOG>3) console.log('KeyLocator: SET CERTIFICATE');
    	this.certificate = _input;  // Uint8Array
    }
};

KeyLocator.prototype.from_ccnb = function (decoder) {
    decoder.readStartElement(this.getElementLabel());

    if (decoder.peekStartElement(CCNProtocolDTags.Key)) {
	encodedKey = decoder.readBinaryElement(CCNProtocolDTags.Key);
	    
	this.publicKey = new Key();
	this.publicKey.readDerPublicKey(encodedKey);
	this.type = KeyLocatorType.KEY;

	if(LOG>4) console.log('Public key in PEM format: '+ this.publicKey.publicToPEM());
    } else if (decoder.peekStartElement(CCNProtocolDTags.Certificate)) {
	encodedCert = decoder.readBinaryElement(CCNProtocolDTags.Certificate);
			
	/*
	 * Certificates not yet working
	 */
			
	this.certificate = encodedCert;
	this.type = KeyLocatorType.CERTIFICATE;

	if(LOG>4) console.log('CERTIFICATE FOUND: '+ this.certificate);
    } else {
	this.type = KeyLocatorType.KEYNAME;
	this.keyName = new KeyName();
	this.keyName.from_ccnb(decoder);
    }
    decoder.readEndElement();
};
	

KeyLocator.prototype.to_ccnb = function (encoder) {
    if (!this.validate()) {
	throw new Error("Cannot encode KeyLocator because field values missing.");
    }
	
    encoder.writeStartElement(this.getElementLabel());
	
    if (this.type == KeyLocatorType.KEY) {
	if(LOG>4)console.log('About to encode a public key' + DataUtils.toHex(this.publicKey.publicToDER()));
	encoder.writeElement(CCNProtocolDTags.Key, this.publicKey.publicToDER());
    } else if (this.type == KeyLocatorType.CERTIFICATE) {
	try {
	    encoder.writeElement(CCNProtocolDTags.Certificate, this.certificate);
	} catch (e) {
	    throw new Error("Cannot encode certificate.");
	}
    } else if (this.type == KeyLocatorType.KEYNAME) {
	this.keyName.to_ccnb(encoder);
    }
    encoder.writeEndElement();	
};


KeyLocator.prototype.to_xml = function () {
    var xml = '<KeyLocator>';

    if (this.type == KeyLocatorType.KEY) {
	xml += '<Key ccnbencoding="hexBinary">' + DataUtils.toHex(this.publicKey.publicKeyDer).toUpperCase() + '</Key>';
    } else if (this.type == KeyLocatorType.CERTIFICATE) {
	throw new Error("Don't know how to encode certificate into XML.");
    } else if (this.type == KeyLocatorType.KEYNAME) {
	xml += this.keyName.to_xml();
    }
    xml += '</KeyLocator>';
    return xml;
};


KeyLocator.prototype.getElementLabel = function() {
    return CCNProtocolDTags.KeyLocator; 
};

KeyLocator.prototype.validate = function() {
    return ((null != this.keyName) || (null != this.publicKey) || (null != this.certificate));
};


/**
 * KeyName is only used by KeyLocator.
 * Currently publisherID is never set by NDN.JS
 */
var KeyName = function KeyName(name, id) {
	this.name = name;  // Name
	this.publisherID = id;  // PublisherID

};

KeyName.prototype.from_ccnb = function (decoder) {
    decoder.readStartElement(this.getElementLabel());

    this.name = new Name();
    this.name.from_ccnb(decoder);
	
    if ( PublisherID.peek(decoder) ) {
	this.publisherID = new PublisherID();
	this.publisherID.from_ccnb(decoder);
    }
	
    decoder.readEndElement();
};

KeyName.prototype.to_ccnb = function (encoder) {
    if (!this.validate()) {
	throw new Error("Cannot encode KeyName: field values missing.");
    }
	
    encoder.writeStartElement(this.getElementLabel());
	
    this.name.to_ccnb(encoder);

    if (null != this.publisherID)
	this.publisherID.to_ccnb(encoder);

    encoder.writeEndElement();   		
};

KeyName.prototype.to_xml = function () {
    var xml = '<KeyName>';

    xml += this.name.to_xml();

    if (this.publisherID != null)
	xml += this.publisherID.to_xml();

    xml += '</KeyName>';
    return xml;
};

KeyName.prototype.getElementLabel = function() { return CCNProtocolDTags.KeyName; };

KeyName.prototype.validate = function() {
    // DKS -- do we do recursive validation?
    // null publisherID is ok
    return (null != this.name);
};

