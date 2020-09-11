<?php

namespace Smoren\UrlSecurityManager;


use Smoren\UrlSecurityManager\Exceptions\UrlSecurityManagerException;
use Smoren\UrlSecurityManager\Exceptions\WrongSignatureException;

class UrlSecurityManager
{
    protected $scheme;
    protected $host;
    protected $port;
    protected $user;
    protected $pass;
    protected $path;
    protected $params;
    protected $fieldsToSign;
    protected $fieldsToEncrypt;
    protected $signatureField;
    protected $encryptedStringField;
    protected $secretKey;
    protected $signature;

    protected static $defaultProtocolPortMap = [
        'http' => 80,
        'https' => 443,
        'ftp' => 21,
    ];

    /**
     * Making an UrlSecurityManager instance from URL string or request URL
     * @param string|null $url URL string
     * @return static new manager instance from parsed URL
     * @throws UrlSecurityManagerException
     */
    public static function parse(?string $url = null): self
    {
        if($url === null) {
            $port = static::getPortSubstring($_SERVER['SERVER_PORT']);
            $auth = static::getAuthSubstring($_SERVER['PHP_AUTH_USER'] ?? null, $_SERVER['PHP_AUTH_PW'] ?? null);
            $url = "{$_SERVER['REQUEST_SCHEME']}://{$auth}{$_REQUEST['SERVER_NAME']}{$port}{$_SERVER['REQUEST_URI']}";
        }

        $urlParsed = parse_url($url);
        $urlData = [
            'scheme' => $urlParsed['scheme'] ?? null,
            'host' => $urlParsed['host'] ?? null,
            'port' => $urlParsed['port'] ?? null,
            'user' => $urlParsed['user'] ?? null,
            'pass' => $urlParsed['pass'] ?? null,
            'path' => $urlParsed['path'] ?? null,
            'params' => [],
        ];
        if(isset($urlParsed['query'])) {
            parse_str($urlParsed['query'], $urlData['params']);
        }

        return static::create($urlData);
    }

    /**
     * Creates new manager instance with given params
     * @param array|null $urlData params of URL
     * @return static new manager instance
     * @throws UrlSecurityManagerException
     */
    public static function create(?array $urlData = null): self
    {
        return new static($urlData);
    }

    /**
     * Building URL string from instance data
     * @param bool $withQueryParams with query params flag
     * @return string
     */
    public function stringify(bool $withQueryParams = true): string
    {
        $port = static::getPortSubstring($this->scheme, $this->port);
        $auth = static::getAuthSubstring($this->user, $this->pass);

        if($withQueryParams) {
            $params = $this->params;
            if($this->signature !== null && $this->signatureField !== null) {
                $params[$this->signatureField] = $this->signature;
            }
            if(count($params)) {
                $query = '?' . http_build_query($params);
            } else {
                $query = '';
            }
        } else {
            $query = '';
        }

        if($this->host === null) {
            return "{$this->path}{$query}";
        }

        return "{$this->scheme}://{$auth}{$this->host}{$port}{$this->path}{$query}";
    }

    /**
     * Signing of URL
     * @return $this
     * @throws UrlSecurityManagerException
     */
    public function sign(): self
    {
        $this->signature = $this->genSignature();

        return $this;
    }

    /**
     * @return $this
     * @throws UrlSecurityManagerException
     */
    public function encrypt(): self
    {
        if($this->secretKey === null) {
            throw new UrlSecurityManagerException('cannot encrypt: no secretKey specified');
        }

        if($this->fieldsToEncrypt === null) {
            throw new UrlSecurityManagerException('cannot encrypt: no fieldsToEncrypt specified');
        }

        $paramsToEncrypt = [];
        foreach($this->fieldsToEncrypt as $field) {
            if(!isset($this->params[$field])) {
                throw new UrlSecurityManagerException("no field '{$field}' found in url query params");
            }
            $paramsToEncrypt[$field] = $this->params[$field];
            unset($this->params[$field]);
        }

        $this->params[$this->encryptedStringField] = $this->encryptString(serialize($paramsToEncrypt));

        return $this;
    }

    /**
     * @return $this
     * @throws UrlSecurityManagerException
     */
    public function decrypt(): self
    {
        if($this->secretKey === null) {
            throw new UrlSecurityManagerException('cannot decrypt: no secretKey specified');
        }

        if($this->fieldsToEncrypt === null) {
            throw new UrlSecurityManagerException('cannot decrypt: no fieldsToEncrypt specified');
        }

        $decryptedParams = unserialize(
            $this->decryptString($this->params[$this->encryptedStringField]),
            ['allowed_classes' => false]
        );

        $encryptedFields = [];
        foreach($decryptedParams as $key => $val) {
            $this->params[$key] = $val;
            $encryptedFields[] = $key;
        }
        $this->fieldsToEncrypt = $encryptedFields;

        unset($this->params[$this->encryptedStringField]);

        return $this;
    }

    /**
     * Checking signature of URL
     * @return $this
     * @throws UrlSecurityManagerException
     * @throws WrongSignatureException
     */
    public function check(): self
    {
        $signature = $this->genSignature();

        if($signature !== $this->signature) {
            throw new WrongSignatureException('signature is wrong');
        }

        return $this;
    }

    /**
     * Setting scheme of URL (e.g. http, https, ftp, ...)
     * @param string|null $scheme name of scheme
     * @return $this
     */
    public function setScheme(?string $scheme = null): self
    {
        $this->scheme = $scheme;
        return $this;
    }

    /**
     * Setting hostname of URL
     * @param string|null $host hostname
     * @return $this
     */
    public function setHost(?string $host = null): self
    {
        $this->host = $host;
        return $this;
    }

    /**
     * Setting port of URL
     * @param string|null $port port
     * @return $this
     */
    public function setPort(?string $port = null): self
    {
        $this->port = $port;
        return $this;
    }

    /**
     * Setting username of URL (for basic auth)
     * @param string|null $user username
     * @return $this
     */
    public function setUser(?string $user = null): self
    {
        $this->user = $user;
        return $this;
    }

    /**
     * Setting password of URL (for basic auth)
     * @param string|null $pass password
     * @return $this
     */
    public function setPass(?string $pass = null): self
    {
        $this->pass = $pass;
        return $this;
    }

    /**
     * Setting path of URL
     * @param string|null $path path
     * @return $this
     */
    public function setPath(?string $path = null): self
    {
        $this->path = $path;
        return $this;
    }

    /**
     * Setting query params of URL
     * @param array $params query params
     * @return $this
     */
    public function setParams(array $params): self
    {
        $this->params = $params;
        return $this;
    }

    /**
     * Setting params of signing URL
     * @param string $signatureField query param name to store signature
     * @param array $fieldsToSign list of query params' names which will be used for signing
     * @return $this
     * @throws UrlSecurityManagerException
     */
    public function setSignParams(string $signatureField, array $fieldsToSign = []): self
    {
        if(!count($fieldsToSign)) {
            foreach($this->params as $field => $val) {
                if($field !== $signatureField) {
                    $fieldsToSign[] = $field;
                }
            }
        }

        foreach($fieldsToSign as $field) {
            if(!isset($this->params[$field])) {
                throw new UrlSecurityManagerException("no field '{$field}' found in url query params");
            }
        }

        $this->fieldsToSign = $fieldsToSign;
        $this->signatureField = $signatureField;

        if(isset($this->params[$signatureField])) {
            $this->signature = $this->params[$signatureField];
        }

        return $this;
    }

    /**
     * Setting list of encrypted query params' names
     * @param string $encryptedStringField query param name for storing encrypted data
     * @param array $fieldsToEncrypt names of query params to encrypt
     * @return $this
     */
    public function setEncryptParams(string $encryptedStringField, array $fieldsToEncrypt = []): self
    {
        if(!count($fieldsToEncrypt)) {
            foreach($this->params as $field => $val) {
                if($field !== $encryptedStringField) {
                    $fieldsToEncrypt[] = $field;
                }
            }
        }

        $this->fieldsToEncrypt = $fieldsToEncrypt;
        $this->encryptedStringField = $encryptedStringField;
        return $this;
    }

    /**
     * Setting secret key for signing URL
     * @param string $secretKey secret key string
     * @return $this
     */
    public function setSecretKey(string $secretKey): self
    {
        $this->secretKey = $secretKey;
        return $this;
    }

    /**
     * Setting signature of URL
     * @param string $signature signature value string
     * @return $this
     */
    public function setSignature(string $signature): self
    {
        $this->signature = $signature;
        return $this;
    }

    /**
     * Getting all query params of URL
     * @return array
     */
    public function getParams(): array
    {
        return $this->params;
    }

    /**
     * UrlSigner constructor.
     * @param array|null $urlData all params of URL
     * @throws UrlSecurityManagerException
     */
    protected function __construct(?array $urlData = null)
    {
        $this->scheme = 'http';
        $this->host = null;
        $this->port = null;
        $this->user = null;
        $this->pass = null;
        $this->path = '';
        $this->params = [];
        $this->fieldsToSign = [];
        $this->fieldsToEncrypt = [];
        $this->signatureField = null;
        $this->encryptedStringField = null;
        $this->secretKey = null;
        $this->signature = null;

        if($urlData !== null) {
            foreach($urlData as $key => $val) {
                $methodName = 'set'.ucfirst($key);
                if(!method_exists($this, $methodName)) {
                    throw new UrlSecurityManagerException("unknown param '{$key}'");
                }
                $this->$methodName($val);
            }
        }
    }

    /**
     * Generates signature of URL
     * @return string
     * @throws UrlSecurityManagerException
     */
    protected function genSignature(): string
    {
        if($this->secretKey === null) {
            throw new UrlSecurityManagerException('cannot sign: secretKey is not specified');
        }
        if($this->fieldsToSign === null || !count($this->fieldsToSign)) {
            throw new UrlSecurityManagerException('cannot sign: fieldsToSign are not specified');
        }

        return md5(md5($this->secretKey).md5($this->stringify(false)).md5($this->getStringToSign()));
    }

    /**
     * Getting string of URL params to sign
     * @return string string ready to sign
     */
    protected function getStringToSign(): string
    {
        $result = [];
        foreach($this->fieldsToSign as $field) {
            $result[] = "{$field}_{$this->params[$field]}";
        }

        return implode('-', $result);
    }

    /**
     * Decrypting input string
     * @param string $input encrypted string to decrypt
     * @return string decrypted string
     */
    protected function encryptString(string $input): string
    {
        $method   = 'aes-128-cbc';

        $ivLen = openssl_cipher_iv_length($method);
        $iv = openssl_random_pseudo_bytes($ivLen);
        $cipherText = openssl_encrypt($input, $method, $this->secretKey, $options=OPENSSL_RAW_DATA, $iv);
        $hmac = hash_hmac('sha256', $cipherText, $this->secretKey, $as_binary=true);

        return base64_encode($iv.$hmac.$cipherText);
    }

    /**
     * Encrypting input string
     * @param string $input string to encrypt
     * @return string encrypted string
     */
    protected function decryptString(string $input): string
    {
        $c = base64_decode($input);
        $method   = 'aes-128-cbc';

        $ivLen = openssl_cipher_iv_length($method);
        $iv = substr($c, 0, $ivLen);
        $hmac = substr($c, $ivLen, $sha2len=32);
        $cipherText = substr($c, $ivLen+$sha2len);
        return openssl_decrypt($cipherText, $method, $this->secretKey, $options=OPENSSL_RAW_DATA, $iv);
    }

    /**
     * Getting substring of username and password (for basic auth) for building URL string
     * @param string|null $user username
     * @param string|null $pass password
     * @return string substring of username and password
     */
    protected static function getAuthSubstring(?string $user = null, ?string $pass = null): string
    {
        if($user === null) {
            return '';
        }

        if($pass === null) {
            return "{$user}@";
        }

        return "{$user}:{$pass}@";
    }

    /**
     * Getting substring of port for building URL string
     * @param string $scheme scheme of URL (e.g. http, https, ftp, ...)
     * @param int|null $port port
     * @return string substring of port
     */
    protected static function getPortSubstring(string $scheme, ?int $port = null): string
    {
        $port = static::getPort($scheme, $port);
        if($port === null) {
            return '';
        }

        return ":{$port}";
    }

    /**
     * Getting port of URL
     * @param string $scheme scheme of URL (e.g. http, https, ftp, ...)
     * @param int|null $port port
     * @return int|null
     */
    protected static function getPort(string $scheme, ?int $port = null)
    {
        if(isset(static::$defaultProtocolPortMap[$scheme])) {
            return $port;
        }

        if(static::$defaultProtocolPortMap[$scheme] === $port) {
            return null;
        }

        return $port;
    }
}