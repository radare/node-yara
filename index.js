
var yara = require ("./build/Release/yara");

function _expandConstantObject(object) {
   var keys = []
   for (var key in object)
      keys.push([key, object[key]])
   for (var i = 0; i < keys.length; i++)
		object[keys[i][1]] = keys[i][0]
}

_expandConstantObject(yara.ErrorCode)

function Scanner(options) {
	this.yara = new yara.ScannerWrap()
}

Scanner.prototype.addRules = function(rules, cb) {
	return this.yara.addRules(rules, cb)
}

exports.ErrorCode = yara.ErrorCode

exports.Scanner = Scanner

exports.createScanner = function(options) {
	return new Scanner(options || {})
}
