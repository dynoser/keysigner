<?php
namespace dynoser\keysigner;

interface KeySignerIf
{
    public function signIt($msg);
    public function verifySign($signature, $msg, $pub_key = false);
}
class KeySigner implements KeySignerIf
{
    public $pub_key;
    private $priv_key;
    public $can_sign = false; // set true if can

    public $remote_API_obj;

    public function __construct($keypair_or_pubkey = false, $password = false, $remote_API_obj = false)
    {
        $keypair_or_pubkey && $this->init($keypair_or_pubkey, $password, $remote_API_obj);
    }
    
    public function initPrivKey($priv_key, $password = false) {
        if ($password) {
            $priv_key = self::aes256ende(false, $priv_key, $password);
        }
        if (!\is_string($priv_key) || \strlen($priv_key) != 64) {
            throw new \Exception("Invalid priv_key");
        }
        $this->pub_key = \substr($priv_key, -32);
        $this->priv_key = $priv_key;
        $this->can_sign = true;
    }

    public function init($keypair_or_pubkey = false, $password = false, $remote_API_obj = false)
    {
        $this->remote_API_obj = $remote_API_obj;
        if (false === $remote_API_obj) {
            $keypair = $keypair_or_pubkey;
            if (false === $keypair) {
                $keypair = \sodium_crypto_sign_keypair();
            } elseif ($password && \is_string($keypair)) {
                $keypair = $this->decryptKeyPair($keypair, $password);
                if (false === $keypair) {
                    throw new \Exception("Can't decrypt keypair");
                }
            }
            if (!\is_string($keypair)) {
                throw new \Exception("Bad keypair");
            }
            $l = \strlen($keypair);
            if ((192 === $l || 128 === $l) && \ctype_xdigit($keypair)) {
                $keypair = \hex2bin($keypair);
                $l = \strlen($keypair);
            }
            if (128 === $l) { // probably 96 bytes keypair in base64
                $keypair = \base64_decode($keypair);
                $l = \strlen($keypair);
            }
            // length must be 96 or 64 bytes
            if ($l === 64) {
                // if only private key
                $pub_key = $this->pubkeyFromPrivate($keypair);
                if (!\is_string($pub_key) || \strlen($pub_key) !== 32) {
                    throw new \Exception("Can't get pub_key from priv_key");
                }
                // add pub_key to keypair
                $keypair .= $pub_key;
            } elseif ($l != 96) {
                throw new \Exception("Unexpected keypair length=" . $l);
            }
            // set own parameters
            $this->pub_key = \sodium_crypto_sign_publickey($keypair); // 32 bytes bin (right part from keypair)
            $this->priv_key = \sodium_crypto_sign_secretkey($keypair); // 64 bytes bin
            $this->can_sign = true;
            // finally check keypair format
            if ($this->pub_key !== \substr($keypair, -32) || $this->priv_key !== \substr($keypair, 0, 64)) {
                throw new \Exception("KeyPair have NOT sodium_crypto_sign format");
            }
        } else {
            // For remote_API - need only pubkey
            $pub_key = $keypair_or_pubkey;
            // try hex-decode
            if (\strlen($pub_key) === 64) {
                $pub_key = \hex2bin($pub_key);
            }
            if (\strlen($pub_key) !== 32) {
                throw new \Exception("Unexpected pub_key length");
            }
            // set own parameters
            $this->pub_key = $pub_key;
            $this->priv_key = false;

            // quick-check remote API object
            if (!\property_exists($remote_API_obj, 'api_url')) {
                throw new \Exception("Incorrect remote_API object");
            }
        }
    }

    public function decryptKeyPair($aes_data, $password)
    {
        if (\strlen($aes_data) > 96) {
            $aes_data = \base64_decode($aes_data, true);
        }
        return self::aes256ende(false, $aes_data, $password);
    }

    public function dumpKeyPair($password = false, $raw_output = false, $only_priv_key = false)
    {
        if (!$this->can_sign) {
            throw new \Exception("No private key for dump");
        }
        if (!empty($this->remote_API_obj)) {
            throw new \Exception("Can't get private_key from remote API");
        }
        $data = $this->priv_key . ($only_priv_key ? '' : $this->pub_key);
        if (false !== $password) {
            $data = self::aes256ende(true, $data, $password);
        }
        if ($raw_output) {
            return $data;
        }
        return \base64_encode($data);
    }

    public function pubkeyFromPrivate($priv_key)
    {
        return
            \sodium_crypto_sign_publickey_from_secretkey($priv_key);
    }

    public function signIt($msg)
    {
        if (!$this->can_sign) {
            return false; // can't sign
        }
        if ($this->remote_API_obj) {
            $ansAPI = $this->remote_API_obj->doAPIreq('signIt', \compact('msg'));
            if (empty($ansAPI['response']) || !\is_string($ansAPI['response'])) {
                throw new \Exception("Bad response from remote KeySigner API");
            }
            $ans = $ansAPI['response']; //string
        } else {
            $ans = \sodium_crypto_sign_detached($msg, $this->priv_key); // 64 bytes
        }
        return $ans;
    }

    public function verifySign($signature, $msg, $pub_key = false)
    {
        if (false === $pub_key) {
            $pub_key = $this->pub_key;
        }
        if ($this->remote_API_obj) {
            $ansAPI = $this->remote_API_obj->doAPIreq('verifySign', \compact('pub_key', 'msg', 'signature'));
            if (empty($ansAPI['response'])) {
                throw new \Exception("Bad response from remote KeySigner API");
            }
            $ans = $ansAPI['response']; //string
            $ans = ($ans === '1') || ($ans === 'true') || ($ans === true) || ($ans === 1);
        } else {
            $ans = \sodium_crypto_sign_verify_detached($signature, $msg, $pub_key);
        }
        return $ans;
    }

    public static function aes256ende(
        $true_for_encrypt,
        $data,
        $password
    ) {
        $key = \hash('sha256', $password, true);
        $iv = \substr($key, -16);
        return
            $true_for_encrypt ?
            \openssl_encrypt($data, 'AES-256-CBC', $key, \OPENSSL_RAW_DATA, $iv)
          : \openssl_decrypt($data, 'AES-256-CBC', $key, \OPENSSL_RAW_DATA, $iv);
    }
}