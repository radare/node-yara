
var fs = require("fs")

var yara = require ("../")

if (process.argv.length < 4) {
	console.log ("usage: node scan-dir <rules.yara> <dir>")
	process.exit (-1)
}

var rules = process.argv[2]
var dir   = process.argv[3]

var scanner = yara.createScanner()

var files = fs.readdirSync(dir);

function doOne(file) {
	path = dir + "/" + file
	console.log("scanning: %s", path)

	scanner.scan({filename: path}, function(path, error, result) {
		if (error) {
			console.error("scan %s failed: %s", path, error.message)
		} else {
			console.error("scan %s done: %s", path, JSON.stringify(result))
		}
	}.bind(this, path))
}

yara.initialize(function(error) {
	if (error) {
		console.error(error)
	} else {
		var options = {
			rules: [
				{file: rules}
			]
		}

		scanner.configure(options, function(error) {
			if (error) {
				if (error instanceof yara.CompileRulesError) {
					console.error(error.message + ": " + JSON.stringify(error.errors))
				} else {
					console.error(error)
				}
			} else {
				files.forEach(function(file) {
					doOne(file)
				})
			}
		})
	}
})
