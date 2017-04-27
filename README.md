
# yara 

**WORK IN PROGRESS - ALMOST DONE**

# Example

	##
	## Linux only (for now), and builds software using node-gyp.
	##
	npm install yara

	var yara = require("yara")

	yara.initialize(function(error) {
		if (error) {
			console.error(error)
		} else {
			var rule =
					"rule is_good : tag1 tag2 {\n"
					+ "	meta:\n"
					+ "		created_by = \"stephen\"\n"
					+ "	condition:\n"
					+ "		true\n"
					+ "}"
		
			var options = {
				rules: [
					{filename: "rules.yara"},
					{string: rule}
				],
				variables: [
					{type: yara.VariableType.Integer, id: "goodness_level", value: 100}
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
					fs.readdirSync("/lib64").forEach(function(file) {
						scanner.scan({filename: "/lib64/" + file}, function(path, error, result) {
							if (error) {
								console.error("scan %s failed: %s", path, error.message)
							} else {
								console.error("scan %s done: %s", path, JSON.stringify(result))
							}
						}.bind(this, "/lib64/" + file))
					})
				}
			})
		}
	})

# License

Copyright (c) 2017 Stephen Vickers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

# Author

Stephen Vickers <stephen.vickers.sv@gmail.com>
