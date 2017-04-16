
var assert = require("assert")

var yara = require ("../")

before(function(done) {
	yara.initialize(function(error) {
		assert.ifError(error)
		done()
	})
})

describe("index.js", function() {
	describe("createScanner()", function() {
		it("returns a Scanner object", function() {
			var scanner = yara.createScanner()
			assert(typeof scanner, "Scanner")
		})
	})
})
