var querystring = require('querystring')
    , http = require('http')
    , fs = require('fs');

var xmlInput = process.argv[2];
var regex = /test\/test([0-9]+)-*/
var result = xmlInput.match(regex);
var num = result[1];

var data = fs.readFileSync(__dirname + '/' + xmlInput);
console.log(data)

var options = {
    host: '127.0.0.1',
    port: 8888,
    path: '/encrypt',
    method: 'POST',
    headers: {
        'Content-Type': 'text/xml',
        'Content-Length': data.length
    }
};


var req = http.request(options, function(res) {
    res.setEncoding('ascii');
    var fullBody = '';

    res.on('data', function(chunk) {
      // append the current chunk of data to the fullBody variable
      fullBody += chunk.toString();
    });

    res.on('end', function() {
      fs.writeFile(__dirname + '/test/test'+num+'-encrypted.xml', fullBody, function(err) {
        if(err) {
          console.log(err);
        } else {
          console.log("The file was saved!");
        }
      });

    });
});

req.write(data);
req.end();
