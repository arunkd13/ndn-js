/**
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents Publisher and PublisherType Objects
 */

var isTypeTagVal = function(tagVal) {
    if ((tagVal == CCNProtocolDTags.PublisherPublicKeyDigest) ||
	(tagVal == CCNProtocolDTags.PublisherCertificateDigest) ||
	(tagVal == CCNProtocolDTags.PublisherIssuerKeyDigest) ||
	(tagVal == CCNProtocolDTags.PublisherIssuerCertificateDigest)) {
	return true;
    }
    return false;
};


/**
 * id is the SHA-256 hash of the publisher public key Buffer
 * type can be either of CCNProtocolDtags.PublisherPublicKeyDigest | PublisherCertificateDigest | PublisherIssuerKeyDigest | PublisherIssuerCertificateDigest
 * while the latter three are usually not used
 */
var PublisherID = function PublisherID(id, type) {
    this.id = id;
    this.type = type;
};


PublisherID.prototype.from_ccnb = function(decoder) {
    // We have a choice here of one of 4 binary element types.
    var nextTag = decoder.peekStartElementAsLong();
		
    if (null == nextTag) {
	throw new Error("Cannot parse publisher ID.");
    } 
		
    this.publisherType = new PublisherType(nextTag); 
		
    if (!isTypeTagVal(nextTag)) {
	throw new Error("Invalid publisher ID, got unexpected type: " + nextTag);
    }
    this.id = decoder.readBinaryElement(nextTag);
    if (null == this.id) {
	throw new Error("Cannot parse publisher ID of type : " + nextTag + ".");
    }

    this.type = nextTag;
};

PublisherID.prototype.to_ccnb = function(encoder) {
    if (!this.validate()) {
	throw new Error("Cannot encode PublisherID values missing.");
    }

    encoder.writeElement(this.getElementLabel(), this.id);
};

PublisherID.prototype.to_xml = function () {
    var xml = '<' + CCNProtocolDTagsStrings[this.type] + ' ccnbencoding="hexBinary">' 
    + DataUtils.toHex(this.id).toUpperCase() + '</' + CCNProtocolDTagsStrings[this.type] + '>';
    return xml;
};

PublisherID.peek = function(/* XMLDecoder */ decoder) {
    nextTag = decoder.peekStartElementAsLong();
		
    if (null == nextTag) {
	return false;
    }
    return (isTypeTagVal(nextTag));
};

PublisherID.prototype.getElementLabel = function() { 
    return this.type;
};

PublisherID.prototype.validate = function () {
    return ((null != this.id) && (null != this.type));
};



