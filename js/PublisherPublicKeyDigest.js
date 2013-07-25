/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents PublisherPublicKeyDigest Objects
 */

var PublisherPublicKeyDigest = function PublisherPublicKeyDigest(_pkd){ 
    this.PUBLISHER_ID_LEN = 256/8;
    this.publisherPublicKeyDigest = _pkd;
};

PublisherPublicKeyDigest.prototype.from_ccnb = function( decoder) {		
    this.publisherPublicKeyDigest = decoder.readBinaryElement(this.getElementLabel());
		
    if(LOG>4) console.log('Publisher public key digest is ' + DataUtils.toString(this.publisherPublicKeyDigest));

    if (null == this.publisherPublicKeyDigest) {
	throw new Error("Cannot parse publisher key digest.");
    }
		
    if (this.publisherPublicKeyDigest.length != this.PUBLISHER_ID_LEN) {
	console.log('LENGTH OF PUBLISHER ID IS WRONG! Expected ' + this.PUBLISHER_ID_LEN + ", got " + this.publisherPublicKeyDigest.length);
    }
};

PublisherPublicKeyDigest.prototype.to_ccnb= function( encoder) {
    //TODO Check that the ByteArray for the key is present
    if (!this.validate()) {
	throw new Error("Cannot encode : field values missing.");
    }
    if(LOG>4) console.log('PUBLISHER KEY DIGEST IS'+this.publisherPublicKeyDigest);
    encoder.writeElement(this.getElementLabel(), this.publisherPublicKeyDigest);
};

PublisherPublicKeyDigest.prototype.to_xml = function () {
    var xml = '<PublisherPublicKeyDigest ccnbencoding="hexBinary">';
    if (this.publisherPublicKeyDigest != null)
	xml += DataUtils.toHex(this.publisherPublicKeyDigest).toUpperCase();
    xml += '</PublisherPublicKeyDigest>';
    return xml;
};
	
PublisherPublicKeyDigest.prototype.getElementLabel = function() { return CCNProtocolDTags.PublisherPublicKeyDigest; };

PublisherPublicKeyDigest.prototype.validate = function() {
    return (null != this.publisherPublicKeyDigest);
};
