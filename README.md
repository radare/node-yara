
# raw-socket 

This module implements support for YARA.

This module is installed using [node package manager (npm)][npm]:

    # This module contains C++ source code which will be compiled
    # during installation using node-gyp.  A suitable build chain
    # must be configured before installation.
    
    npm install yara

It is loaded using the `require()` function:

    var yara = require("yara");

YARA rules can then be created and used to scan content: 

    var scanner = yara.createScanner();

    scanner.addRules(["rule ..."], function(error) {
        scanner.addRulesFiles(["file.yara"], function(error) {
            scanner.scan("file", function(error, result) {

				});
        });
    });

[nodejs]: http://nodejs.org "Node.js"
[npm]: https://npmjs.org/ "npm"

# Constants

The following sections describe constants exported and used by this module.

## yara.ErrorCodes

**TODO Add a description**

The following constants are defined in this object (as per the YARA docs):

 * `ERROR_SUCCESS`

# Using This Module

YARA compilers are represented by an instance of the `Scanner` class.  This
module exports the `createScanner()` function which is used to create
instances of the `Socket` class.

## yara.createScanner([options])

The `createScanner()` function instantiates and returns an instance of the
`Scanner` class:

    // Default options
    var options = {
    };
    
    var scanner = yara.createScanner(options);

The optional `options` parameter is an object, and can contain the following
items:

An exception will be thrown if...
The error will be an instance of the `Error` class.


## Other API's

# Example Programs

Example programs are included under the modules `example` directory.

# Bugs & Known Issues

None, yet!

Bug reports should be sent to <stephen.vickers.sv@gmail.com>.

# Changes

## Version 1.0.0 - 10/04/2017

 * Initial release

# Roadmap

Suggestions and requirements should be sent to <stephen.vickers.sv@gmail.com>.

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
