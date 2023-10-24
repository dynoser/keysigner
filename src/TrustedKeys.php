<?php
namespace dynoser\tools;

class TrustedKeys
{
    const PUB_KEY_BIN_LEN = 32;

    public array $trustedKeysArr = []; // [pubkey-bin]
    
    public function __construct(array $trustedKeysArr = []) {
        $this->trustedKeysArr = $trustedKeysArr;
    }
    
    public function setTrust(string $str, bool $isTrusted = true) {
        $str = $this->tryDecode($str, self::PUB_KEY_BIN_LEN, true);
        $this->trustedKeysArr[$str] = $isTrusted;
    }

    public function removeTrust(string $str) {
        $str = $this->tryDecode($str, self::PUB_KEY_BIN_LEN, true);
        unset($this->trustedKeysArr[$str]);
    }
    
    private function tryDecode(string $str, int $expectedLen, bool $thrBadPubKey = false): ?string {
        $l = \strlen($str);
        if ($l > $expectedLen) {
            if ($l === $expectedLen * 2 && \ctype_xdigit($str)) {
                $str = \hex2bin($str);
            } else {
                $str = \base64_decode($str);
            }
            $l = \strlen($str);
        }
        if ($l !== $expectedLen) {
            if ($thrBadPubKey) {
                throw new \Exception("Bad public key length");
            }
            $str = null;
        }
        return $str;
    }

    public function isTrusted(string $keyPubStr): bool {
        $expectedLen = self::PUB_KEY_BIN_LEN;
        $keyPubBin = self::tryDecode($keyPubStr, $expectedLen, false);
        if (!$keyPubBin) {
            return false;
        }
        if (\array_key_exists($keyPubBin, $this->trustedKeysArr)) {
            return $this->trustedKeysArr[$keyPubBin];
        }
        
        $pubKeyIsTrusted = false;
        foreach($this->trustedKeysArr as $k => $isTrust) {
            if (\is_numeric($k) && \is_string($isTrust)) {
                $chkPub = $isTrust;
                $isTrust = true;
            } else {
                $chkPub = $k;
            }
            if (\strlen($chkPub) !== $expectedLen) {
                $newPubBin = self::tryDecode($chkPub, $expectedLen, true);
                unset($this->trustedKeysArr[$k]);
                $this->trustedKeysArr[$newPubBin] = $isTrust;
                if ($newPubBin === $keyPubBin) {
                    $pubKeyIsTrusted = $isTrust;
                    break;
                }
    
            }
        }

        return $pubKeyIsTrusted;
    }
}
