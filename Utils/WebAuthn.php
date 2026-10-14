<?php
/**
 * WebAuthn 工具类 - 使用统一 Crypto 接口
 */
if (!defined('__TYPECHO_ROOT_DIR__')) exit;

require_once 'Crypto.php';

class Passkey_Utils_WebAuthn
{
    /**
     * Base64 URL 安全编码
     */
    public static function base64UrlEncode($data)
    {
        return Passkey_Utils_Crypto::base64UrlEncode($data);
    }

    /**
     * Base64 URL 安全解码
     */
    public static function base64UrlDecode($data)
    {
        return Passkey_Utils_Crypto::base64UrlDecode($data);
    }

    /**
     * 生成安全随机数
     */
    public static function generateSecureRandom($length)
    {
        return Passkey_Utils_Crypto::generateSecureRandom($length);
    }

    /**
     * 生成注册挑战
     */
    public static function generateRegistrationChallenge($userId, $userName, $displayName, $timeout = 120000)
    {
        $challenge = self::generateSecureRandom(32);
        return [
            'challenge' => self::base64UrlEncode($challenge),
            'rp' => ['name' => $displayName, 'id' => self::getRpId()],
            'user' => [
                'id' => self::base64UrlEncode($userId),
                'name' => $userName,
                'displayName' => $displayName
            ],
            'pubKeyCredParams' => [['type' => 'public-key', 'alg' => -7]],
            'timeout' => $timeout,
            'attestation' => 'none',
            'authenticatorSelection' => [
                'userVerification' => 'required'
            ]
        ];
    }

    /**
     * 生成认证挑战
     */
    public static function generateAuthenticationChallenge($credentials, $timeout = 120000)
    {
        $challenge = self::generateSecureRandom(32);
        $allowCredentials = [];
        foreach ($credentials as $cred) {
            $allowCredentials[] = ['id' => $cred['credential_id'], 'type' => 'public-key'];
        }
        return [
            'challenge' => self::base64UrlEncode($challenge),
            'timeout' => $timeout,
            'rpId' => self::getRpId(),
            'userVerification' => 'required',
            'allowCredentials' => $allowCredentials
        ];
    }

    /**
     * 将 COSE 公钥转换为 PEM 格式
     */
    public static function coseToPem($coseKey)
    {
        $offset = 0;
        $key = self::decodeCbor($coseKey, $offset);
        if ($offset !== strlen($coseKey)) {
            throw new Exception(Passkey_Plugin::translate('cose_public_key_invalid'));
        }

        return self::coseMapToPem($key);
    }

    /**
     * 验证签名
     */
    public static function verifySignature($publicKeyPem, $signatureBase, $signature)
    {
        return Passkey_Utils_Crypto::verifySignature($publicKeyPem, $signatureBase, $signature);
    }

    /**
     * 哈希
     */
    public static function hash($data, $length = 32)
    {
        return hash('sha256', $data, true);
    }

    public static function createChallenge($key)
    {
        self::assertSecureRequest();
        self::startSession();
        $challenge = self::base64UrlEncode(self::generateSecureRandom(32));
        $_SESSION['passkey_challenges'][$key][hash('sha256', $challenge)] = time() + 300;
        return $challenge;
    }

    public static function consumeClientChallenge($key, $clientDataJson, $expectedType)
    {
        self::assertSecureRequest();
        self::startSession();
        $clientData = json_decode($clientDataJson, true);
        $challenge = is_array($clientData) ? ($clientData['challenge'] ?? '') : '';
        $challengeHash = is_string($challenge) ? hash('sha256', $challenge) : '';
        $expires = $_SESSION['passkey_challenges'][$key][$challengeHash] ?? 0;
        unset($_SESSION['passkey_challenges'][$key][$challengeHash]);
        if (empty($_SESSION['passkey_challenges'][$key])) {
            unset($_SESSION['passkey_challenges'][$key]);
        }

        if (!$expires || $expires < time()) {
            throw new Exception(Passkey_Plugin::translate('challenge_expired'));
        }

        if (!is_array($clientData)
            || ($clientData['type'] ?? '') !== $expectedType
            || !isset($clientData['challenge'], $clientData['origin'])
            || !hash_equals($challenge, $clientData['challenge'])
            || !empty($clientData['crossOrigin'])
            || $clientData['origin'] !== self::getExpectedOrigin()) {
            throw new Exception(Passkey_Plugin::translate('webauthn_response_invalid'));
        }

        return $clientData;
    }

    public static function parseAttestationObject($encodedAttestation)
    {
        $attestation = self::base64UrlDecode($encodedAttestation);
        $offset = 0;
        $object = self::decodeCbor($attestation, $offset);

        if ($offset !== strlen($attestation)
            || !is_array($object)
            || ($object['fmt'] ?? '') !== 'none'
            || !isset($object['authData'])
            || !is_array($object['attStmt'] ?? null)
            || count($object['attStmt']) !== 0) {
            throw new Exception(Passkey_Plugin::translate('attestation_unsupported'));
        }

        $authData = $object['authData'];
        if (strlen($authData) < 55) {
            throw new Exception(Passkey_Plugin::translate('authenticator_data_invalid'));
        }

        self::verifyAuthenticatorData($authData);
        if ((ord($authData[32]) & 0x40) === 0) {
            throw new Exception(Passkey_Plugin::translate('authenticator_missing_public_key'));
        }
        $credentialIdLength = unpack('n', substr($authData, 53, 2))[1];
        $credentialKeyOffset = 55 + $credentialIdLength;
        if ($credentialIdLength < 1 || $credentialKeyOffset >= strlen($authData)) {
            throw new Exception(Passkey_Plugin::translate('credential_data_invalid'));
        }

        $credentialId = substr($authData, 55, $credentialIdLength);
        $keyOffset = $credentialKeyOffset;
        $coseKey = self::decodeCbor($authData, $keyOffset);

        return [
            'credentialId' => $credentialId,
            'publicKey' => self::coseMapToPem($coseKey),
            'counter' => self::readCounter($authData)
        ];
    }

    public static function verifyAuthenticatorData($authData)
    {
        if (strlen($authData) < 37
            || !hash_equals(hash('sha256', self::getRpId(), true), substr($authData, 0, 32))) {
            throw new Exception(Passkey_Plugin::translate('rp_id_mismatch'));
        }

        $flags = ord($authData[32]);
        if (($flags & 0x01) === 0 || ($flags & 0x04) === 0) {
            throw new Exception(Passkey_Plugin::translate('user_verification_required'));
        }
    }

    public static function readCounter($authData)
    {
        return unpack('N', substr($authData, 33, 4))[1];
    }

    private static function coseMapToPem($key)
    {
        if (!is_array($key)
            || ($key[1] ?? null) !== 2
            || ($key[3] ?? null) !== -7
            || ($key[-1] ?? null) !== 1
            || !isset($key[-2], $key[-3])
            || strlen($key[-2]) !== 32
            || strlen($key[-3]) !== 32) {
            throw new Exception(Passkey_Plugin::translate('algorithm_unsupported'));
        }

        $point = "\x04" . $key[-2] . $key[-3];
        $spki = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00" . $point;
        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
        if (openssl_pkey_get_public($pem) === false) {
            throw new Exception(Passkey_Plugin::translate('p256_public_key_invalid'));
        }
        return $pem;
    }

    private static function getRpId()
    {
        $siteUrl = Typecho_Widget::widget('Widget_Options')->siteUrl;
        $host = parse_url($siteUrl, PHP_URL_HOST);
        if (!$host) {
            throw new Exception(Passkey_Plugin::translate('site_url_invalid'));
        }
        return strtolower($host);
    }

    private static function getExpectedOrigin()
    {
        $parts = parse_url(Typecho_Widget::widget('Widget_Options')->siteUrl);
        if (empty($parts['scheme']) || strtolower($parts['scheme']) !== 'https' || empty($parts['host'])) {
            throw new Exception(Passkey_Plugin::translate('https_required'));
        }

        $origin = 'https://' . strtolower($parts['host']);
        $isDefaultPort = isset($parts['port'])
            && (($parts['scheme'] === 'https' && (int)$parts['port'] === 443)
                || ($parts['scheme'] === 'http' && (int)$parts['port'] === 80));
        if (isset($parts['port']) && !$isDefaultPort) {
            $origin .= ':' . $parts['port'];
        }
        return $origin;
    }

    private static function assertSecureRequest()
    {
        $expectedOrigin = self::getExpectedOrigin();
        $requestOrigin = $_SERVER['HTTP_ORIGIN'] ?? '';
        if ($requestOrigin !== $expectedOrigin) {
            throw new Exception(Passkey_Plugin::translate('same_origin_https_required'));
        }
    }

    private static function startSession()
    {
        if (session_status() === PHP_SESSION_DISABLED
            || (session_status() !== PHP_SESSION_ACTIVE && !session_start())) {
            throw new Exception(Passkey_Plugin::translate('session_failed'));
        }
    }

    private static function decodeCbor($data, &$offset, $depth = 0)
    {
        if ($depth > 16 || $offset >= strlen($data)) {
            throw new Exception(Passkey_Plugin::translate('cbor_data_invalid'));
        }

        $initial = ord($data[$offset++]);
        $major = $initial >> 5;
        $additional = $initial & 0x1f;

        if ($major === 7) {
            if ($additional === 20) return false;
            if ($additional === 21) return true;
            if ($additional === 22 || $additional === 23) return null;
            throw new Exception(Passkey_Plugin::translate('cbor_type_unsupported'));
        }

        if ($additional < 24) {
            $length = $additional;
        } elseif ($additional <= 27) {
            $byteCount = 1 << ($additional - 24);
            if ($offset + $byteCount > strlen($data) || $byteCount > 4) {
                throw new Exception(Passkey_Plugin::translate('cbor_length_invalid'));
            }
            $length = 0;
            for ($index = 0; $index < $byteCount; $index++) {
                $length = ($length * 256) + ord($data[$offset++]);
            }
        } elseif ($additional === 31) {
            throw new Exception(Passkey_Plugin::translate('cbor_indefinite_unsupported'));
        } else {
            throw new Exception(Passkey_Plugin::translate('cbor_length_invalid'));
        }

        if ($major === 0) return $length;
        if ($major === 1) return -1 - $length;
        if ($major === 2 || $major === 3) {
            if ($length > strlen($data) - $offset) {
                throw new Exception(Passkey_Plugin::translate('cbor_field_out_of_range'));
            }
            $value = substr($data, $offset, $length);
            $offset += $length;
            return $value;
        }
        if ($major === 4 || $major === 5) {
            if ($length > 1024) {
                throw new Exception(Passkey_Plugin::translate('cbor_collection_too_large'));
            }
            $result = [];
            for ($index = 0; $index < $length; $index++) {
                if ($major === 4) {
                    $result[] = self::decodeCbor($data, $offset, $depth + 1);
                } else {
                    $key = self::decodeCbor($data, $offset, $depth + 1);
                    $result[$key] = self::decodeCbor($data, $offset, $depth + 1);
                }
            }
            return $result;
        }
        if ($major === 6) {
            return self::decodeCbor($data, $offset, $depth + 1);
        }

        throw new Exception(Passkey_Plugin::translate('cbor_unsupported'));
    }
}