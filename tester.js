var loadtest = require('loadtest');
var options = {
    url: 'http://localhost:40000',
    maxRequests: 1000,
};
loadtest.loadTest(options, function(error, result)
{
    if (error)
    {
        return console.error('Got an error: %s', error);
    }
    console.log('Tests run successfully:', result);
});