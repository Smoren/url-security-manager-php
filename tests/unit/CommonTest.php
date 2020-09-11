<?php

namespace app\tests\unit;

use app\models\Address;
use app\models\City;
use app\models\Comment;
use app\models\Place;
use Smoren\UrlSecurityManager\Exceptions\DecryptException;
use Smoren\UrlSecurityManager\Exceptions\UrlSecurityManagerException;
use Smoren\UrlSecurityManager\Exceptions\WrongSignatureException;
use Smoren\UrlSecurityManager\UrlSecurityManager;
use Smoren\Yii2\QueryRelationManager\Base\QueryRelationManagerException;
use Smoren\Yii2\QueryRelationManager\Yii2\QueryRelationManager;
use yii\db\Query;
use yii\helpers\ArrayHelper;

class CommonTest extends \Codeception\Test\Unit
{
    /**
     * @throws UrlSecurityManagerException
     */
    public function testBuilding()
    {
        $usm = UrlSecurityManager::create()
            ->setScheme('https')
            ->setHost('test.com')
            ->setPort(8080)
            ->setPath('/test/path')
            ->setParams(['a' => 1, 'b' => 2]);

        $this->assertSame($usm->stringify(), 'https://test.com:8080/test/path?a=1&b=2');

        $usm
            ->setSignParams('sign')
            ->setSecretKey('q1w2e3r4t5y6u7')
            ->sign();

        $this->assertSame($usm->stringify(), 'https://test.com:8080/test/path?a=1&b=2&sign=89727a40dc08dc9f12d91b5d6e627c17');

        $usm = UrlSecurityManager::create([
            'scheme' => 'http',
            'host' => 'test.com',
            'port' => 8080,
            'path' => '/test/path',
            'params' => ['a' => 1, 'b' => 2],
        ]);
        $this->assertSame($usm->stringify(), 'http://test.com:8080/test/path?a=1&b=2');
    }

    /**
     * @throws UrlSecurityManagerException
     */
    public function testServerRequest()
    {
        global $_SERVER;

        $_SERVER = [
            'SERVER_NAME' => 'localhost',
            'SERVER_PORT' => 8081,
            'REQUEST_SCHEME' => 'http',
            'REQUEST_URI' => '/123/index.php?req=456',
        ];

        $usm = UrlSecurityManager::parse();
        $this->assertSame($usm->stringify(), 'http://localhost:8081/123/index.php?req=456');
    }

    /**
     * @throws UrlSecurityManagerException
     * @throws WrongSignatureException
     */
    public function testSigning()
    {
        $secretKey = 'dfgfd4566fdgd';
        $a = UrlSecurityManager::parse('https://user:sdfsdfds@php.ru/forum/threads/ne-rabotaet-bazovaja-autentifikacija.28262/?asd=%D0%B0%D0%BF%D1%80%D0%B0%D0%BF%D1%80&fgh=456')
            ->setSignParams('sign')
            ->setSecretKey($secretKey)
            ->sign();
        $a->check();

        $url = $a->stringify();
        $b = UrlSecurityManager::parse($url)
            ->setSignParams('sign')
            ->setSecretKey($secretKey);
        $b->check();
    }

    /**
     * @throws UrlSecurityManagerException
     * @throws WrongSignatureException
     * @throws DecryptException
     */
    public function testEncrypting()
    {
        $secretKey = 'fvd76df89g7fdg89';
        $inputUrl = 'http://localhost:8080/test/path?p1=1&p2=2&p3=3&p4=4';
        $a = UrlSecurityManager::parse($inputUrl)
            ->setSignParams('sign', ['p1', 'p2', 'p3'])
            ->setEncryptParams('encrypted')
            ->setSecretKey($secretKey)
            ->sign();
        $a->check();

        $signedUrl = $a->stringify();
        $encryptedUrl = $a->encrypt()->stringify();
        $decryptedUrl = $a->decrypt()->stringify();
        $this->assertSameParams($signedUrl, $decryptedUrl);

        $b = UrlSecurityManager::parse($encryptedUrl)
            ->setEncryptParams('encrypted')
            ->setSecretKey($secretKey)
            ->decrypt()
            ->setSignParams('sign', ['p1', 'p2', 'p3']);

        $b->check();
        $this->assertSameParams($signedUrl, $b->stringify());
    }

    /**
     * @throws UrlSecurityManagerException
     * @throws WrongSignatureException
     * @throws DecryptException
     */
    public function testErrors()
    {
        $secretKey = 'dfgfd4566fdgd';
        $inputUrl = 'http://localhost:8080/test/path?p1=1&p2=2&p3=3&p4=4';
        $a = UrlSecurityManager::parse($inputUrl)
            ->setSignParams('sign', ['p1', 'p2', 'p3'])
            ->setEncryptParams('encrypted')
            ->setSecretKey($secretKey)
            ->sign();
        $a->check();

        $a->setSecretKey('asd');
        try {
            $a->check();
            $this->assertTrue(false);
        } catch(WrongSignatureException $e) {}

        $a->setSecretKey($secretKey);
        $a->check();

        $a->encrypt();
        try {
            $a->check();
            $this->assertTrue(false);
        } catch(UrlSecurityManagerException $e) {}
        $a->decrypt();
        $a->check();

        $params = $a->getParams();
        $params['p1'] = 111;
        $a->setParams($params);
        try {
            $a->check();
            $this->assertTrue(false);
        } catch(WrongSignatureException $e) {}

        $a->encrypt();
        $a->setSecretKey('aaa');

        try {
            $a->decrypt();
            $this->assertTrue(false);
        } catch(DecryptException $e) {}

        $a->setSecretKey($secretKey);
        $a->decrypt();
    }

    /**
     * @throws \Exception
     */
    public function testCipherMethods()
    {
        $availableMethods = openssl_get_cipher_methods();
        $testingMethods = array_intersect(['aes-128-cbc', 'aes-128-ccm', 'aria-256-ccm'], $availableMethods);

        foreach($testingMethods as $method) {
            try {
                $secretKey = 'dfgfd4566fdgd';
                $inputUrl = 'http://localhost:8080/test/path?p1=1&p2=2&p3=3&p4=4';
                $a = UrlSecurityManager::parse($inputUrl)
                    ->setCipherMethod($method)
                    ->setEncryptParams('encrypted')
                    ->setSecretKey($secretKey);

                $b = UrlSecurityManager::parse($a->encrypt()->stringify())
                    ->setEncryptParams('encrypted')
                    ->setSecretKey($secretKey);

                $this->assertSameParams($a->decrypt()->stringify(), $b->decrypt()->stringify());
            } catch(\Exception $e) {
                if(
                    strpos($e->getMessage(), 'openssl_encrypt') !== false &&
                    strpos($e->getMessage(), 'AEAD') !== false
                ) {
                    continue;
                }

                throw $e;
            }
        }


        try {
            $a->setCipherMethod('NonExistingCipherMethod');
            $this->assertTrue(false);
        } catch(UrlSecurityManagerException $e) {}
    }

    /**
     * @throws UrlSecurityManagerException
     * @throws WrongSignatureException
     */
    public function testDemoSigning()
    {
        $inputUrl = 'http://localhost:8080/test/path?p1=1&p2=2&p3=3&p4=4';
        $secretKey = 'fvd76df89g7fdg89';

        // Let's sign some url with our secret key to send signed request to receiver
        $usmSender = UrlSecurityManager::parse($inputUrl)
            // signature will be stored as value of query param "sign"
            // only query aparms from array (2nd argument) will be signed
            ->setSignParams('sign', ['p1', 'p2', 'p3'])
            ->setSecretKey($secretKey) // giving secret key for signing
            ->sign(); // create signature

        $signedUrl = $usmSender->stringify();
        $this->assertSame($signedUrl, 'http://localhost:8080/test/path?p1=1&p2=2&p3=3&p4=4&sign=5342af44ed716002a81a2872734729f5');

        // Now we will try to check the signature of URL:
        $usmReceiver = UrlSecurityManager::parse($signedUrl)
            ->setSignParams('sign', ['p1', 'p2', 'p3'])
            ->setSecretKey($secretKey);
        $usmReceiver->check(); // will be executed without WrongSignatureException

        $usmReceiver
            ->setSignParams('sign', ['p1', 'p2', 'p3'])
            ->setSecretKey('123');

        try {
            $usmReceiver->check(); // will throw WrongSignatureException
        } catch(WrongSignatureException $e) {}

        $usmSender = UrlSecurityManager::parse($inputUrl)
            ->setSignParams('sign') // all query params will be signed
            ->setSecretKey($secretKey)
            ->sign();

        $signedUrl = $usmSender->stringify();
        $this->assertSame($signedUrl, 'http://localhost:8080/test/path?p1=1&p2=2&p3=3&p4=4&sign=50489186458519f9f141e616dc02af73');
    }

    /**
     * @throws DecryptException
     * @throws UrlSecurityManagerException
     */
    public function testDemoEncrypting()
    {
        $inputUrl = 'http://localhost:8080/test/path?p1=1&p2=2&p3=3&p4=4';
        $secretKey = 'fvd76df89g7fdg89';

        // Let's encrypt url with our secret key to send some secret data to receiver:
        $usmSender = UrlSecurityManager::parse($inputUrl)
            // encrypted string will be stored as value of query param "sign"
            // all query params will be encrypted
            ->setEncryptParams('encrypted')
            ->setSecretKey($secretKey)
            ->encrypt(); // encrypting data

        $encryptedUrl = $usmSender->stringify();

        // Now we will try to decrypt received secret data:
        $usmReceiver = UrlSecurityManager::parse($encryptedUrl)
            ->setEncryptParams('encrypted')
            ->setSecretKey($secretKey)
            ->decrypt();

        $decryptedUrl = $usmReceiver->stringify();
        $this->assertSame($decryptedUrl, 'http://localhost:8080/test/path?p1=1&p2=2&p3=3&p4=4');

        $usmSender->decrypt();

        // encrypt only query params: p1, p2
        $usmSender->setEncryptParams('encrypted', ['p1', 'p2']);
        $usmSender->encrypt();

        $usmSender->decrypt();
        $this->assertSame($usmSender->stringify(), 'http://localhost:8080/test/path?p3=3&p4=4&p1=1&p2=2');
    }

    /**
     * @param string $lhs
     * @param string $rhs
     * @return $this
     * @throws UrlSecurityManagerException
     */
    protected function assertSameParams(string $lhs, string $rhs): self
    {
        $lhs = UrlSecurityManager::parse($lhs)->getParams();
        $rhs = UrlSecurityManager::parse($rhs)->getParams();

        ksort($lhs);
        ksort($rhs);

        $this->assertSame($lhs, $rhs);

        return $this;
    }
}