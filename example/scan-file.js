
var fs = require("fs")
var yara = require ("../")

if (process.argv.length < 4) {
	console.log ("usage: node scan-file <rules.yara> <file>")
	process.exit (-1)
}

var rulesFile  = process.argv[2]
var objectFile = process.argv[3]

var scanner = yara.createScanner()

fs.readFile(rulesFile, function(error, data) {
	if (error) {
		console.error(error)
	} else {
		scanner.addRules(data.toString("ascii"), function(error) {
			if (error) {
				console.error(error)
			} else {
				console.log("Rules loaded")
			}
		})
	}
})

