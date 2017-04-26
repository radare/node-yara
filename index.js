
var util = require("util")
var yara = require ("./build/Release/yara");

function _expandConstantObject(object) {
	var keys = []
	for (var key in object)
		keys.push([key, object[key]])
	for (var i = 0; i < keys.length; i++)
		object[keys[i][1]] = keys[i][0]
}

_expandConstantObject(yara.ErrorCode)

function CompileRulesError(message) {
	this.name = "CompileRulesError"
	this.message = message
}

util.inherits(CompileRulesError, Error)

function Scanner(options) {
	this.yara = new yara.ScannerWrap()
}

Scanner.prototype.configure = function(options, cb) {
	return this.yara.configure(options, function(error) {
		if (error) {
			if (error.errors) {
				var errors = []

				error.errors.forEach(function(item) {
					var fields = item.split(":")
					errors.push({
						index: parseInt(fields[0]),
						line: parseInt(fields[1]),
						message: fields[2]
					})
				})

				error = new CompileRulesError(error.message)
				error.errors = errors
			}
			cb(error)
		} else {
			cb()
		}
	})
}

Scanner.prototype.scan = function(req, cb) {
	return this.yara.scan(req, cb)
}

exports.CompileRulesError = CompileRulesError

exports.Scanner = Scanner

exports.VariableType = yara.VariableType;

exports.createScanner = function(options) {
	return new Scanner(options || {})
}

exports.initialize = function(cb) {
	return yara.initialize(cb)
}
