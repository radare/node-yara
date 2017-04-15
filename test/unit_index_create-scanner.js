
var assert = require("assert")

var yara = require ("../")

describe("index.js", function() {
	describe("createScanner()", function() {
		it("returns a Scanner object", function() {
			yara.initialize(function(error) {
				assert.ifError(error)
				var scanner = yara.createScanner()
				assert(typeof scanner, "Scanner")
			})
		})
	})
})
