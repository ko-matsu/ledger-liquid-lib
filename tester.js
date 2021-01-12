var loadtest = require('loadtest');
var options = {
    url: 'http://localhost:40000',
    maxRequests: 100,
    concurrency: 100,
    timeout: 0,
    Connection: 'Close',
};
loadtest.loadTest(options, function(error, result)
{
    if (error)
    {
        return console.error('Got an error: %s', error);
    }
    console.log('Tests run successfully:', result);
});