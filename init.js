const rsaWrapper = require('./Server/component/rsa-wrapper')

rsaWrapper.generate('server');
rsaWrapper.generate('client');

console.log('Keys generated... ');