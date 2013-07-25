/**
 * @author: Wentao Shang
 * See COPYING for copyright and distribution information.
 * This class represents CCNTime Objects
 */

/**
 * Create CCNTime object. If input is null, set input to current JavaScript time
 */
var CCNTime = function CCNTime(input) {
    if (input == null) {
	var d = new Date()
	input = d.getTime();
    } else if (typeof input != 'number')
	throw new Error('CCNTime: invalid input type ' + (typeof input));
    
    this.msec = input;  // in milliseconds
    this.binary = DataUtils.unsignedIntToBigEndian((input / 1000) * 4096);
};


CCNTime.prototype.encodeToBinary = function() {
    return this.binary;
};


CCNTime.prototype.getJavascriptDate = function () {
    var d = new Date();
    d.setTime( this.msec );
    return d
};
