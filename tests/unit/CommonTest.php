<?php

namespace app\tests\unit;

use app\models\Address;
use app\models\City;
use app\models\Comment;
use app\models\Place;
use Smoren\UrlSecurityManager\Exceptions\UrlSecurityManagerException;
use Smoren\UrlSecurityManager\Exceptions\WrongSignatureException;
use Smoren\UrlSecurityManager\UrlSecurityManager;
use Smoren\Yii2\QueryRelationManager\Base\QueryRelationManagerException;
use Smoren\Yii2\QueryRelationManager\Yii2\QueryRelationManager;
use yii\db\Query;
use yii\helpers\ArrayHelper;

class CommonTest extends \Codeception\Test\Unit
{
    public function testFirst()
    {
        $sk = 'asdasdasd';
        $i = serialize(['a' => 1, 'b' => 2, 'c' => 3]);
        $method = 'AES-256-CTR';
        $i = 'Testing...';
        $a = openssl_encrypt($i, $method, $sk, OPENSSL_RAW_DATA, openssl_random_pseudo_bytes(openssl_cipher_iv_length($method)));
        $b = openssl_decrypt($a, $method, $sk, OPENSSL_RAW_DATA);
        $c = 1;

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
     */
    public function testEncrypting()
    {
        $secretKey = 'dfgfd4566fdgd';
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
        $this->assertSame($signedUrl, $decryptedUrl);

        $b = UrlSecurityManager::parse($encryptedUrl)
            ->setEncryptParams('encrypted')
            ->setSecretKey($secretKey)
            ->decrypt()
            ->setSignParams('sign', ['p1', 'p2', 'p3']);

        $b->check();
        $url = $b->stringify();

        $c = 1;

//        $url = $a->stringify();
//        $b = UrlSecurityManager::parse($url)
//            ->setSignParams(['asd', 'fgh'], 'sign')
//            ->setSecretKey($secretKey);
//        $b->check();
    }
}