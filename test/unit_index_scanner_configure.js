
var assert = require("assert")

var yara = require ("../")

before(function(done) {
	yara.initialize(function(error) {
		assert.ifError(error)
		done()
	})
})

describe("index.js", function() {
	describe("Scanner.configure()", function() {
		it("options must be an object", function() {
			var scanner = yara.createScanner()
			assert.throws(function() {
				scanner.configure()
			}, /Options argument must be an object/)
		})

		it("callback must be a function", function() {
			var scanner = yara.createScanner()
			assert.throws(function() {
				scanner.configure({})
			}, /Callback argument must be a function/)
		})
		
		it("calls the callback", function(done) {
			var scanner = yara.createScanner()
			scanner.configure({}, done)
		})
	})
})
