'use strict';

const https = require('https');

function checkQueries(queries) {
  if (typeof queries !== 'object') {
    return false;
  }
  const { branch, token, repos } = queries || {};
  if (!branch || !token || !repos) {
    return false;
  }
  return true;
}

module.exports.handler = function(req, resp) {
  const validQueries = checkQueries(req.queries);
  if (!validQueries) {
    resp.setStatusCode(400);
    return resp.send('{"success": false}');
  }
  const { branch, message = 'yuque update', token, repos } = req.queries;

  const payload = JSON.stringify({
    message,
    branch,
  });
  const headers = {
    'Content-Type': 'application/json',
    'Travis-API-Version': '3',
    Authorization: `token ${token}`,
    'Conent-Length': Buffer.byteLength(payload),
  };
  const options = {
    hostname: 'api.travis-ci.org',
    port: 443,
    path: `/repo/${encodeURIComponent(repos)}/requests`,
    method: 'POST',
    headers,
  };

  let result = '';
  const request = https.request(options, function(res) {
    res.setEncoding('utf8');
    res.on('data', function(chunk) {
      result += chunk;
    });
    res.on('end', function() {
      resp.setStatusCode(200);
      resp.setHeader('content-type', 'application/json');
      resp.send(result);
    });
  });
  request.on('error', function() {
    resp.setStatusCode(500);
    resp.send('{"success": false}');
  });
  request.write(payload);
  request.end();

  // https
  //   .request(options)
  //   .write(payload)
  //   .pipe(resp);
};
