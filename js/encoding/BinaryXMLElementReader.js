/**
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 */

/*
 * A BinaryXmlElementReader lets you call onReceivedData multiple times which uses a
 *   BinaryXMLStructureDecoder to detect the end of a binary XML element and calls
 *   elementListener.onReceivedElement(element) with the element. 
 * This handles the case where a single call to onReceivedData may contain multiple elements.
 */
var BinaryXmlElementReader = function BinaryXmlElementReader(elementListener) {
    this.elementListener = elementListener;
    this.dataParts = [];
    this.structureDecoder = new BinaryXMLStructureDecoder();
};

BinaryXmlElementReader.prototype.onReceivedData = function(/* Uint8Array */ rawData) {
    // Process multiple objects in the data.
    while(true) {
        // Scan the input to check if a whole ccnb object has been read.
        this.structureDecoder.seek(0);
        if (this.structureDecoder.findElementEnd(rawData)) {
            // Got the remainder of an object.  Report to the caller.
            this.dataParts.push(rawData.subarray(0, this.structureDecoder.offset));
            this.elementListener.onMessage(DataUtils.concatArrays(this.dataParts));
        
            // Need to read a new object.
            rawData = rawData.subarray(this.structureDecoder.offset, rawData.length);
            this.dataParts = [];
            this.structureDecoder = new BinaryXMLStructureDecoder();
            if (rawData.length == 0)
                // No more data in the packet.
                return;
            
            // else loop back to decode.
        }
        else {
            // Save for a later call to concatArrays so that we only copy data once.
            this.dataParts.push(rawData);
	    if (LOG>3) console.log('Incomplete packet received. Length ' + rawData.length + '. Wait for more input.');
            return;
        }
    }    
};