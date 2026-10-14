<?php
/**
 * 加密工具类 - 优先使用 Sodium，降级使用 OpenSSL
 */
if (!defined('__TYPECHO_ROOT_DIR__')) exit;

class Passkey_Utils_Crypto
{
    /**
     * 是否支持 Sodium
     */
    public static function hasSodium()
    {
        static $supported = null;
        if ($supported === null) {
            $supported = extension_loaded('sodium') 
                && function_exists('sodium_crypto_sign_verify_detached');
        }
        return $supported;
    }

    /**
     * Base64 URL 安全编码
     */
    public static function base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64 URL 安全解码
     */
    public static function base64UrlDecode($data)
    {
        if (!is_string($data) || preg_match('/[^A-Za-z0-9_-]/', $data)) {
            return false;
        }

        $padding = strlen($data) % 4;
        if ($padding) $data .= str_repeat('=', 4 - $padding);
        return base64_decode(strtr($data, '-_', '+/'), true);
    }

    /**
     * 生成安全随机数
     */
    public static function generateSecureRandom($length)
    {
        if (self::hasSodium()) {
            if (function_exists('sodium_randombytes_buf')) {
                return sodium_randombytes_buf($length);
            }
            return random_bytes($length);
        }

        if (function_exists('random_bytes')) {
            return random_bytes($length);
        }

        $strong = false;
        $random = openssl_random_pseudo_bytes($length, $strong);
        if ($random === false || !$strong) {
            throw new RuntimeException(Passkey_Plugin::translate('secure_random_failed'));
        }
        return $random;
    }

    /**
     * 验证 ECDSA P-256 签名
     * @param string $publicKeyPem PEM 格式公钥
     * @param string $signatureBase 原始数据
     * @param string $signature Base64Url 编码的签名
     * @return bool
     */
    public static function verifySignature($publicKeyPem, $signatureBase, $signature)
    {
        if (!function_exists('openssl_verify')) {
            return false;
        }

        $publicKey = openssl_pkey_get_public($publicKeyPem);
        if ($publicKey === false) {
            return false;
        }

        return openssl_verify($signatureBase, $signature, $publicKey, OPENSSL_ALGO_SHA256) === 1;
    }

    /**
     * 将 COSE P-256 公钥转换为 PEM 格式
     */
    public static function coseToPem($coseKey)
    {
        $keyData = self::base64UrlDecode($coseKey);
        if (strlen($keyData) < 64) return null;

        $x = substr($keyData, 0, 32);
        $y = substr($keyData, 32, 32);
        $point = "\x04" . $x . $y;

        // EC SubjectPublicKeyInfo (OID 1.2.840.10045.2.1 + P-256 OID 1.2.840.10045.3.1.7)
        $spki = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00" . $point;

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /**
     * 将 COSE P-256 公钥转换为 Sodium 兼容格式（64 字节原始公钥）
     */
    public static function coseToSodium($coseKey)
    {
        $keyData = self::base64UrlDecode($coseKey);
        if (strlen($keyData) < 64) return null;

        // COSE P-256 公钥本身就是 X||Y (64 字节)
        // Sodium sign 需要 32 字节种子，但 verify 只需要 32 字节公钥
        // 对于 ECDSA，我们需要从 X||Y 提取或使用完整的 64 字节
        return substr($keyData, 0, 32); // 简化：使用 X 坐标作为公钥标识
    }

    /**
     * 解析 PEM 公钥为原始字节
     */
    private static function parsePemPublicKey($pem)
    {
        if (!self::hasSodium()) return null;

        // 提取 PEM 中的公钥数据
        $pem = str_replace([
            "-----BEGIN PUBLIC KEY-----",
            "-----END PUBLIC KEY-----",
            "\n", "\r", " "
        ], '', $pem);

        $der = base64_decode($pem);
        if (!$der || strlen($der) < 91) return null;

        // 跳过 ASN.1 头部，提取 64 字节公钥点
        // P-256 uncompressed point: 04 || X(32) || Y(32)
        if (ord($der[45]) === 0x04 && strlen($der) >= 91) {
            $x = substr($der, 46, 32);
            $y = substr($der, 78, 32);
            return $x . $y; // 返回 64 字节原始公钥
        }

        return null;
    }

    /**
     * 生成密钥对（用于测试/调试）
     */
    public static function generateKeyPair()
    {
        $configFile = getenv('OPENSSL_CONF');
        if (!$configFile || !is_file($configFile)) {
            $candidate = dirname(PHP_BINARY) . DIRECTORY_SEPARATOR . 'extras'
                . DIRECTORY_SEPARATOR . 'ssl' . DIRECTORY_SEPARATOR . 'openssl.cnf';
            if (is_file($candidate)) {
                $configFile = $candidate;
            }
        }

        $config = [
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1'
        ];
        if ($configFile && is_file($configFile)) {
            $config['config'] = $configFile;
        }
        $res = openssl_pkey_new($config);
        if ($res === false) return null;

        $details = openssl_pkey_get_details($res);
        $privateKey = '';
        if (!openssl_pkey_export($res, $privateKey, null, $config)) return null;
        return [
            'secret' => $privateKey,
            'public' => $details['key']
        ];
    }

    /**
     * 哈希（优先使用 Sodium 的 Blake2b）
     */
    public static function hash($data, $length = 32)
    {
        return self::hasSodium() ? sodium_crypto_generichash($data, '', $length) : hash('sha256', $data, true);
    }

    /**
     * HMAC（优先使用 Sodium）
     */
    public static function hmac($data, $key)
    {
        return hash_hmac('sha256', $data, $key, true);
    }
}