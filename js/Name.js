/**
 * @author: Meki Cheraoui, Jeff Thompson, Wentao Shang
 * See COPYING for copyright and distribution information.
 * This class represents a Name as an array of components where each is a byte array.
 */
 
/**
 * Create a new Name from _components.
 * If _components is a string, parse it as a URI.  Otherwise it is an array of components
 * where each is a string, byte array, ArrayBuffer or Uint8Array. 
 * Convert and store as an array of Uint8Array.
 * If a component is a string, encode as utf8.
 */
var Name = function Name(_components) {
    if (_components == null)
	this.components = [];
    else if (typeof _components == 'string') {
	this.components = Name.createComponentArray(_components);
    } else if (typeof _components == 'object') {
	this.components = [];
        if (_components instanceof Name)
            this.add(_components);
        else {
            for (var i = 0; i < _components.length; i++)
                this.add(_components[i]);
        }
    }
};


/**
 * Get the number of components in the Name object
 */
Name.prototype.size = function () {
    return this.components.length;
};


/**
 * component is a string, byte array, ArrayBuffer, Uint8Array or Name.
 * Convert to Uint8Array and add to this Name.
 * If a component is a string, encode as utf8.
 * Return this Name object to allow chaining calls to add.
 */
Name.prototype.add = function (component) {
    if (component == null)
	return this;

    var result;
    if (typeof component == 'string')
        result = Name.stringComponentToBuffer(component);
    else if(typeof component == 'object' && component instanceof Uint8Array)
        result = new Uint8Array(component);
    else if(typeof component == 'object' && component instanceof ArrayBuffer) {
        // Make a copy.  Don't use ArrayBuffer.slice since it isn't always supported.
        result = new Uint8Array(new ArrayBuffer(component.byteLength));
        result.set(new Uint8Array(component));
    } else if (typeof component == 'object' && component instanceof Name) {
        var components;
        if (component == this)
            // special case, when we need to create a copy
            components = this.components.slice(0, this.components.length);
        else
            components = component.components;
        
        for (var i = 0; i < components.length; ++i)
            this.components.push(new Uint8Array(components[i]));
        
	return this;
    } else 
	throw new Error("Cannot add Name element at index " + this.components.length + ": invalid type.");
    
    this.components.push(result);
    return this;
};


// Alias for Name.add()
Name.prototype.append = function (component) {
    return this.add(component);
};

Name.prototype.appendVersion = function () {
    var d = new Date();
    var time = d.getTime().toString(16);

    if (time.length % 2 == 1)
	time = '0' + time;

    time = 'fd' + time;
    var binTime = DataUtils.toNumbers(time);
    return this.add(binTime);
};

Name.prototype.appendSegment = function (seg) {
    if (seg == null || seg == 0)
	return this.add(new Uint8Array([0]));

    var segStr = seg.toString(16);

    if (segStr.length % 2 == 1)
	segStr = '0' + segStr;

    segStr = '00' + segStr;
    return this.add(DataUtils.toNumbers(segStr));
};

Name.prototype.appendKeyID = function (/*Key*/ key) {
    var cmd = 'c12e4d2e4b00';  // '%C1.M.K%00'
    var digest = DataUtils.toHex(key.getKeyID());
    var keyID = cmd + digest;
    return this.add(DataUtils.toNumbers(keyID));
};


/**
 * Convert URI string to Uint8Array. Handles special characters such as '%00' and '%C1'
 */
Name.stringComponentToBuffer = function (component) {
    var buf = new Uint8Array(component.length);  // at least this length
    var pos = 0;  // # of bytes encoded into the Buffer
    var i = 0;
    while (i < component.length) {
	if (component[i] == '%') {
	    var hex = component.substr(i+1, 2);
	    buf[pos] = parseInt(hex, 16);
	    i += 2;
	} else
	    buf[pos] = component.charCodeAt(i);

	i++;
	pos++;
    }
    return buf.subarray(0, pos);
};

/** 
 * Parse name as a URI and return an array of Uint8Array components
 */
Name.createComponentArray = function(name) {
    name = name.trim();
    if (name.length <= 0)
        return [];

    var iColon = name.indexOf(':');
    if (iColon >= 0) {
        // Make sure the colon came before a '/'.
        var iFirstSlash = name.indexOf('/');
        if (iFirstSlash < 0 || iColon < iFirstSlash)
            // Omit the leading protocol such as ndn:
            name = name.substr(iColon + 1, name.length - iColon - 1).trim();
    }
    
    if (name[0] == '/') {
        if (name.length >= 2 && name[1] == '/') {
            // Strip the authority following "//".
            var iAfterAuthority = name.indexOf('/', 2);
            if (iAfterAuthority < 0)
                // Unusual case: there was only an authority.
                return [];
            else
                name = name.substr(iAfterAuthority + 1, name.length - iAfterAuthority - 1).trim();
        }
        else
            name = name.substr(1, name.length - 1).trim();
    }

    var array = name.split('/');
    
    // Unescape the components.
    for (var i = 0; i < array.length; ++i) {
        var component = unescape(array[i].trim());
        
        if (component.match(/[^.]/) == null) {
            // Special case for component of only periods.  
            if (component.length <= 2) {
                // Zero, one or two periods is illegal.  Ignore this componenent to be
                //   consistent with the C implmentation.
                // This also gets rid of a trailing '/'.
                array.splice(i, 1);
                --i;  
                continue;
            }
            else
                // Remove 3 periods.
                array[i] = component.substr(3, component.length - 3);
        }
        else
            array[i] = component;
        
        // Change the component to Uint8Array now.
        array[i] = Name.stringComponentToBuffer(array[i]);
    }

    return array;
};


Name.prototype.from_ccnb = function (decoder) {
    decoder.readStartElement(this.getElementLabel());
    
    this.components = new Array();

    while (decoder.peekStartElement(CCNProtocolDTags.Component)) {
	this.add(decoder.readBinaryElement(CCNProtocolDTags.Component));
    }
		
    decoder.readEndElement();
};


Name.prototype.to_ccnb = function (encoder) {
    if (this.components == null) 
	throw new Error("Cannot encode empty name");

    encoder.writeStartElement(this.getElementLabel());
    var count = this.components.length;
    for (var i=0; i < count; i++) {
	encoder.writeElement(CCNProtocolDTags.Component, this.components[i]);
    }
    encoder.writeEndElement();
};

Name.prototype.encodeToBinary = function () {
    var enc = new BinaryXMLEncoder();
    this.to_ccnb(enc);
    return enc.getReducedOstream();
};

/**
 * Static method to parse a Buffer containing ccnb-formated Name bytes.
 * Return a parsed Name object.
 */
Name.parse = function (buf) {
    var dec = new BinaryXMLDecoder(buf);
    var name = new Name();
    name.from_ccnb(dec);
    return name;
};

Name.prototype.getElementLabel = function () { return CCNProtocolDTags.Name; };

/**
 * Return component as an escaped string according to "CCNx URI Scheme".
 * We can't use encodeURIComponent because that doesn't encode all the characters we want to.
 */
Name.toEscapedString = function(component) {
    var result = "";
    var gotNonDot = false;
    for (var i = 0; i < component.length; ++i) {
        if (component[i] != 0x2e) {
            gotNonDot = true;
            break;
        }
    }

    if (!gotNonDot) {
        // Special case for component of zero or more periods.  Add 3 periods.
        result = "...";
        for (var i = 0; i < component.length; ++i)
            result += ".";
    } else {
        for (var i = 0; i < component.length; ++i) {
            var value = component[i];
            // Check for 0-9, A-Z, a-z, (+), (-), (.), (_)
            if (value >= 0x30 && value <= 0x39 || value >= 0x41 && value <= 0x5a ||
                value >= 0x61 && value <= 0x7a || value == 0x2b || value == 0x2d || 
                value == 0x2e || value == 0x5f)
                result += String.fromCharCode(value);
            else
                result += "%" + (value < 16 ? "0" : "") + value.toString(16).toUpperCase();
        }
    }
    return result;
};


// Return the escaped name string according to "CCNx URI Scheme".
Name.prototype.to_uri = function() {	
    if (this.components.length == 0)
        return "/";
    
    var result = "";
	
    for(var i = 0; i < this.components.length; ++i)
	result += "/"+ Name.toEscapedString(this.components[i]);
	
    return result;	
};

Name.is_text_encodable = function (/*Uint8Array*/ blob) {
    if (blob.length == 0) return false;

    for (var i = 0; i < blob.length; i++) {
	var c = blob[i];
	if (c < 0x20 || c > 0x7E) return false;
	if (c == 0x3C || c == 0x3E || c == 0x26) return false;
    }
    return true;
};

/**
 * Return a string of XML representation of the Name object
 */
Name.prototype.to_xml = function () {
    var xml = '<Name>';

    for(var i = 0; i < this.components.length; i++) {
	var blob = this.components[i];
	if (Name.is_text_encodable(blob))
	    xml += '<Component ccnbencoding="text">' + DataUtils.toString(blob) + '</Component>';
	else 
	    xml += '<Component ccnbencoding="hexBinary">' + DataUtils.toHex(blob).toUpperCase() + '</Component>';
    }
    xml += '</Name>';
    return xml;
};

/**
 * Return a new Name with the first nComponents components of this Name.
 */
Name.prototype.getPrefix = function(nComponents) {
    return new Name(this.components.slice(0, nComponents));
};

/**
 * Return a new Name with the suffix starting at the p-th component of this Name.
 */
Name.prototype.getSuffix = function (p) {
    return new Name(this.components.slice(p));
};

/**
 * Return a new Uint8Array of the component at i.
 */
Name.prototype.getComponent = function(i) {
    var result = new ArrayBuffer(this.components[i].length);
    var ret = new Uint8Array(result);
    ret.set(this.components[i]);
    return ret;
};

/**
 * Return true if this Name has the same components as name.
 */
Name.prototype.equals = function (name) {
    if (this.components.length != name.components.length)
        return false;
    
    // Start from the last component because they are more likely to differ.
    for (var i = this.components.length - 1; i >= 0; --i) {
        if (!DataUtils.arraysEqual(this.components[i], name.components[i]))
            return false;
    }
    
    return true;
};


/**
 * Returns true if 'this' is a prefix of 'name'
 */
Name.prototype.matches = function(name) {
    var i_name = this.components;
    var o_name = name.components;

    // The intrest name is longer than the name we are checking it against.
    if (i_name.length > o_name.length)
	return false;

    // Check if at least one of given components doesn't match.
    for (var i = 0; i < i_name.length; ++i) {
        if (!DataUtils.arraysEqual(i_name[i], o_name[i]))
            return false;
    }

    return true;
};

/**
 * Alias for Name.prototype.matches()
 * This function name is less confusing.
 */
Name.prototype.isPrefixOf = function (name) {
    return this.matches(name);
};


/**
 * Compare two name components according to CCNx canonical ordering rule
 * If comp1 < comp2, return -1
 * If comp1 = comp2, return 0
 * If comp1 > comp2, return 1
 * components can be either string or Buffer objects
 */
Name.compareComponents = function (comp1, comp2) {
    if (typeof comp1 == 'string')
	comp1 = Name.stringComponentToBuffer(comp1);

    if (typeof comp2 == 'string')
	comp2 = Name.stringComponentToBuffer(comp2);

    if (!(comp1 instanceof Uint8Array) || !(comp2 instanceof Uint8Array))
	throw new Error('Cannot compare components of unsupported type.');

    if (comp1.length < comp2.length)
        return -1;
    if (comp1.length > comp2.length)
        return 1;
    
    for (var i = 0; i < comp1.length; ++i) {
        if (comp1[i] < comp2[i])
            return -1;
        if (comp1[i] > comp2[i])
            return 1;
    }

    return 0;
};