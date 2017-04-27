
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
	if (req.buffer) {
		if (! req.offset)
			req.offset = 0
		if (! req.length)
			req.length = req.buffer.length
	}

	return this.yara.scan(req, function(error, result) {
		if (error) {
			cb(error)
		} else {
			result.rules.forEach(function(rule) {
				for (var i = 0; i < rule.metas.length; i++) {
					var fields = rule.metas[i].split(":")

					var meta = {
						type: fields[0],
						identifier: fields[1],
						value: fields[2]
					}

					if (meta.type == yara.MetaType.Integer)
						meta.value = parseInt(meta.value)
					else if (meta.type == yara.MetaType.Integer)
						meta.value = parseInt(meta.value) ? true : false

					rule.metas[i] = meta
				}
			})

			cb(null, result)
		}
	})
}

exports.CompileRulesError = CompileRulesError

exports.Scanner = Scanner

exports.MetaType = yara.MetaType

exports.ScanFlag = yara.ScanFlag

exports.VariableType = yara.VariableType

exports.createScanner = function(options) {
	return new Scanner(options || {})
}

exports.initialize = function(cb) {
	return yara.initialize(cb)
}
