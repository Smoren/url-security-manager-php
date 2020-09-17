# url-security-manager
Class for building, parsing, signing, signature checking, encrypting and decrypting URLs.

### Install to your project
```shell script
composer require smoren/url-security-manager
``` 

### Unit testing
```shell script
composer install
./vendor/bin/codecept build
./vendor/bin/codecept run unit tests/unit
```

### Demo
##### Signing
```php
use Smoren\UrlSecurityManager\UrlSecurityManager;

$inputUrl = 'http://localhost:8080/test/path?p1=1&p2=2&p3=3&p4=4';
$secretKey = 'fvd76df89g7fdg89';

// Let's sign some url with our secret key to send signed request to receiver
$usmSender = UrlSecurityManager::parse($inputUrl)
    // signature will be stored as value of query param "sign"
    // only query params from array (2nd argument) will be signed
    ->setSignParams('sign', ['p1', 'p2', 'p3'])
    ->setSecretKey($secretKey) // giving secret key for signing
    ->sign(); // create signature

$signedUrl = $usmSender->stringify();
echo $signedUrl;
// http://localhost:8080/test/path?p1=1&p2=2&p3=3&p4=4&sign=5342af44ed716002a81a2872734729f5

// Now we will try to check the signature of URL:
$usmReceiver = UrlSecurityManager::parse($signedUrl)
    ->setSignParams('sign', ['p1', 'p2', 'p3'])
    ->setSecretKey($secretKey);
$usmReceiver->check(); // will be executed without WrongSignatureException

$usmReceiver
    ->setSignParams('sign', ['p1', 'p2', 'p3'])
    ->setSecretKey('123');
$usmReceiver->check(); // will throw WrongSignatureException

$usmSender = UrlSecurityManager::parse($inputUrl)
    ->setSignParams('sign') // all query params will be signed
    ->setSecretKey($secretKey)
    ->sign();
$signedUrl = $usmSender->stringify();
echo $signedUrl;
// http://localhost:8080/test/path?p1=1&p2=2&p3=3&p4=4&sign=50489186458519f9f141e616dc02af73
```

##### Encrypting/decrypting
```php
use Smoren\UrlSecurityManager\UrlSecurityManager;

$inputUrl = 'http://localhost:8080/test/path?p1=1&p2=2&p3=3&p4=4';
$secretKey = 'fvd76df89g7fdg89';

// Let's encrypt url with our secret key to send some secret data to receiver:
$usmSender = UrlSecurityManager::parse($inputUrl)
    // encrypted string will be stored as value of query param "encrypted"
    // all query params will be encrypted
    ->setEncryptParams('encrypted') 
    ->setSecretKey($secretKey)
    ->encrypt(); // encrypting data

$encryptedUrl = $usmSender->stringify();
echo $encryptedUrl;
// someting like this:
// http://localhost:8080/test/path?encrypted=X4oxVda3u%2FD2NX...

// Now we will try to decrypt received secret data:
$usmReceiver = UrlSecurityManager::parse($encryptedUrl)
    ->setEncryptParams('encrypted')
    ->setSecretKey($secretKey)
    ->decrypt();

$decryptedUrl = $usmReceiver->stringify();
echo $decryptedUrl;
// http://localhost:8080/test/path?p1=1&p2=2&p3=3&p4=4

$usmSender->decrypt();

// encrypt only query params: p1, p2
$usmSender->setEncryptParams('encrypted', ['p1', 'p2']);
$usmSender->encrypt();

echo $usmSender->stringify();
// something like this:
// http://localhost:8080/test/path?p3=3&p4=4&encrypted=CTNdFXZDlBwYwwvQV2L8mGjQg5YydC3...

$usmSender->decrypt();
echo $usmSender->stringify();
// http://localhost:8080/test/path?p3=3&p4=4&p1=1&p2=2
```

##### Building URLs
```php
use Smoren\UrlSecurityManager\UrlSecurityManager;

$usm = UrlSecurityManager::create()
    ->setScheme('https')
    ->setHost('test.com')
    ->setPort(8080)
    ->setPath('/test/path')
    ->setParams(['a' => 1, 'b' => 2]);

echo $usm->stringify();
// https://test.com:8080/test/path?a=1&b=2

$usm
    ->setSignParams('sign')
    ->setSecretKey('q1w2e3r4t5y6u7')
    ->sign();

echo $usm->stringify();
// https://test.com:8080/test/path?a=1&b=2&sign=89727a40dc08dc9f12d91b5d6e627c17

$usm = UrlSecurityManager::create([
    'scheme' => 'http',
    'host' => 'test.com',
    'port' => 8080,
    'path' => '/test/path',
    'params' => ['a' => 1, 'b' => 2],
]);

echo $usm->stringify();
// http://test.com:8080/test/path?a=1&b=2
```

##### Parse URL from server request
```php
use Smoren\UrlSecurityManager\UrlSecurityManager;

$usm = UrlSecurityManager::parse();

echo $usm->stringify();
// you will see full URL of your current server request
```
