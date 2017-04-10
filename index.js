
var yara = require ("./build/Release/yara");

function Scanner(options) {
	this.yara = new yara.ScannerWrap()
}

exports.Scanner = Scanner

exports.createScanner = function(options) {
	return new Scanner(options || {})
}
