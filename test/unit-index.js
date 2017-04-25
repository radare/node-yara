
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
		it("rules.string missing is ignored", function(done) {
			var scanner = yara.createScanner()
			scanner.configure({
					rules: [
						{}
					]
				}, done)
		})

		it("rules.string empty is ignored", function(done) {
			var scanner = yara.createScanner()
			scanner.configure({
					rules: [
						{string: ""}
					]
				}, done)
		})

		it("rules.string errors", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{string: "rule bad {}"}
					]
				}, function(error) {
					assert(error instanceof yara.CompileRulesError)
					assert(error.message == "Error compiling rules")

					var expErrors = [{
						index: 0,
						line: 1,
						message: "syntax error, unexpected '}', expecting _CONDITION_"
					}]

					assert.deepEqual(error.errors, expErrors)

					done()
				})
		})

		it("rules.string valid", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{string: "rule good {\ncondition:\ntrue\n}"}
					]
				}, function(error) {
					assert.ifError(error)
					done()
				})
		})
		
		it("rules.file empty is ignored", function(done) {
			var scanner = yara.createScanner()
			scanner.configure({
					rules: [
						{file: ""}
					]
				}, done)
		})

		it("rules.file invalid path", function(done) {
			var scanner = yara.createScanner()
			scanner.configure({
					rules: [
						{file: "test/data/unit-index/invalid.yara"}
					]
				}, function(error) {
					assert(error)
					assert.equal(error.message, "fopen(test/data/unit-index/invalid.yara) failed: No such file or directory")
					done()
				})
		})

		it("rules.file errors", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{file: "test/data/unit-index/bad.yara"}
					]
				}, function(error) {
					assert(error instanceof yara.CompileRulesError)
					assert(error.message == "Error compiling rules")

					var expErrors = [{
						index: 0,
						line: 4,
						message: "syntax error, unexpected _HEX_STRING_, expecting _IDENTIFIER_"
					}]

					assert.deepEqual(error.errors, expErrors)

					done()
				})
		})

		it("rules.files valid", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{file: "test/data/unit-index/good.yara"}
					]
				}, function(error) {
					assert.ifError(error)
					done()
				})
		})

		it("variables.integer valid", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{file: "test/data/unit-index/good.yara"}
					],
					variables: [
						{type: yara.VariableType.Integer, id: "skill_level", value: 34}
					]
				}, function(error) {
					assert.ifError(error)
					done()
				})
		})

		it("variables.float valid", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{file: "test/data/unit-index/good.yara"}
					],
					variables: [
						{type: yara.VariableType.Float, id: "percent", value: 0.45}
					]
				}, function(error) {
					assert.ifError(error)
					done()
				})
		})

		it("variables.float valid", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{file: "test/data/unit-index/good.yara"}
					],
					variables: [
						{type: yara.VariableType.Boolean, id: "isYara", value: true}
					]
				}, function(error) {
					assert.ifError(error)
					done()
				})
		})

		it("variables.string valid", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{file: "test/data/unit-index/good.yara"}
					],
					variables: [
						{type: yara.VariableType.String, id: "name", value: "stephen"}
					]
				}, function(error) {
					assert.ifError(error)
					done()
				})
		})

		it("variables.notype invalid", function(done) {
			var scanner = yara.createScanner()

			scanner.configure({
					rules: [
						{file: "test/data/unit-index/good.yara"}
					],
					variables: [
						{id: "skill_level", value: 34}
					]
				}, function(error) {
					assert(error instanceof Error)
					assert.equal(error.message, "unknown variable type: 0")
					done()
				})
		})
	})
})
