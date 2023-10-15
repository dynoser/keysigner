<?php

namespace dynoser\keysigner;

class KeyEd25519PPK
{
    public static function extractKeysfromPPKString(string $ppkStr, bool $retBin = false): ?array
    {
        $private_key_pattern = '/Private-Lines: \d+\s+(.+)\s+Private-MAC:/s';
        $public_key_pattern = '/Public-Lines: \d+\s+(.+)\s+Private-Lines:/s';
        \preg_match($private_key_pattern, $ppkStr, $private_key_matches);
        \preg_match($public_key_pattern, $ppkStr, $public_key_matches);

        $private_key_base64 = \trim($private_key_matches[1]);
        $public_key_base64 = \trim($public_key_matches[1]);

        $private_key_bytes = \base64_decode($private_key_base64);
        $public_key_bytes = \base64_decode($public_key_base64);
        
        $ed25519_sk32 = \substr($private_key_bytes, -32);
        $ed25519_pubkey = \substr($public_key_bytes, -32);
        
        $ed25519_privkey = $ed25519_sk32 . $ed25519_pubkey;

        $ed25519_pubkey_chk = \sodium_crypto_sign_publickey_from_secretkey($ed25519_privkey);
        if ($ed25519_pubkey_chk !== $ed25519_pubkey) {
            return null;
        }
        $ed25519_keypair = sodium_crypto_sign_keypair_from_secretkey_and_publickey($ed25519_privkey, $ed25519_pubkey);
        
        $curve25519_privkey = \sodium_crypto_sign_ed25519_sk_to_curve25519($ed25519_privkey);
        if (!$curve25519_privkey) {
            return null;
        }

        $curve25519_pubkey = \sodium_crypto_box_publickey_from_secretkey($curve25519_privkey);
        
        $retArr = \compact(
            'ed25519_pubkey',
            'ed25519_privkey',
            'ed25519_keypair',
            'curve25519_pubkey',
            'curve25519_privkey',
            );
        if (!$retBin) {
            foreach($retArr as $k => $v) {
                $retArr[$k] = \bin2hex($v);
            }
        }
        
        return $retArr;
    }

    public static function publicKeysFromPPKString(string $ppkStr, bool $retBin = false): ?array
    {
        if (empty($ppkStr)) {
            return null;
        }

        foreach([
            '/---- BEGIN SSH2 PUBLIC KEY ----(.*?)---- END SSH2 PUBLIC KEY ----/ms',
            '/^ssh-ed25519\s+([A-Za-z0-9+\/=\s]+)\s+ed25519-key-\d{8}$/m',
            '/^ssh-ed25519\s+([A-Za-z0-9+\/=\s]+)\s+eddsa-key-\d{8}$/m',
        ] as $pattern) {
            if (\preg_match($pattern, $ppkStr, $matches)) {
                break;
            }
        }
        if (!isset($matches[1])) {
            return null;
        }
        $publicKey = \trim($matches[1]);

        $publicKeyParts = \explode("\n", $publicKey);

        $actualPublicKey = '';
        foreach ($publicKeyParts as $part) {
            if (false === \strpos($part, ':')) {
                $actualPublicKey .= \trim($part);
            }
        }

        $ed25519_pubkey = \base64_decode($actualPublicKey);
        if (!$ed25519_pubkey) {
            throw new \Exception("Can't decode public key from base64");
        }
        $ed25519_pubkey = \substr($ed25519_pubkey, -32);

        $curve25519_pubkey = \sodium_crypto_sign_ed25519_pk_to_curve25519($ed25519_pubkey);
        if (!$curve25519_pubkey) {
            throw new \Exception("Bad public key (expected ed25519");
        }

        $retArr = \compact('ed25519_pubkey', 'curve25519_pubkey');
        if (!$retBin) {
            foreach($retArr as $k => $v) {
                $retArr[$k] = \bin2hex($v);
            }
        }

        return $retArr;
    }

}