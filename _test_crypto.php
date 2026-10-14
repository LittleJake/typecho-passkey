<?php
/**
 * 加密库测试脚本
 * 用于检测服务器加密库支持情况
 */

// 模拟 Typecho 环境
if (!defined('__TYPECHO_ROOT_DIR__')) {
    define('__TYPECHO_ROOT_DIR__', __DIR__);
}

// 加载 Crypto 类
require_once 'Utils/Crypto.php';

echo "=== Typecho Passkey 加密库检测 ===\n\n";

// 检测 Sodium
echo "1. Sodium 扩展检测:\n";
if (extension_loaded('sodium')) {
    echo "   ✅ Sodium 已启用\n";
    echo "   版本：" . SODIUM_LIBRARY_VERSION . "\n";
} else {
    echo "   ❌ Sodium 未启用\n";
}

// 检测 OpenSSL
echo "\n2. OpenSSL 扩展检测:\n";
if (extension_loaded('openssl')) {
    echo "   ✅ OpenSSL 已启用\n";
    echo "   版本：" . OPENSSL_VERSION_TEXT . "\n";
} else {
    echo "   ❌ OpenSSL 未启用\n";
}

// 测试加密功能
echo "\n3. 功能测试:\n";

// 测试随机数生成
try {
    $random = Passkey_Utils_Crypto::generateSecureRandom(32);
    echo "   ✅ 随机数生成：" . bin2hex($random) . "\n";
} catch (Exception $e) {
    echo "   ❌ 随机数生成失败：" . $e->getMessage() . "\n";
}

// 测试哈希
try {
    $hash = Passkey_Utils_Crypto::hash('test data');
    echo "   ✅ 哈希生成：" . bin2hex($hash) . "\n";
} catch (Exception $e) {
    echo "   ❌ 哈希生成失败：" . $e->getMessage() . "\n";
}

// 测试 HMAC
try {
    $hmac = Passkey_Utils_Crypto::hmac('test data', 'secret key');
    echo "   ✅ HMAC 生成：" . bin2hex($hmac) . "\n";
} catch (Exception $e) {
    echo "   ❌ HMAC 生成失败：" . $e->getMessage() . "\n";
}

// 测试密钥对生成
echo "\n4. 密钥对生成测试:\n";
try {
    $pair = Passkey_Utils_Crypto::generateKeyPair();
    if ($pair) {
        $message = 'Passkey ES256 test';
        $signature = '';
        if (openssl_sign($message, $signature, $pair['secret'], OPENSSL_ALGO_SHA256)
            && Passkey_Utils_Crypto::verifySignature($pair['public'], $message, $signature)) {
            echo "   ✅ P-256 密钥生成及 ECDSA 签名验证成功\n";
        } else {
            echo "   ❌ P-256 ECDSA 签名验证失败\n";
        }
    } else {
        echo "   ⚠️ 密钥对生成失败\n";
    }
} catch (Exception $e) {
    echo "   ❌ 密钥对生成异常：" . $e->getMessage() . "\n";
}

// 总结
echo "\n=== 总结 ===\n";
if (extension_loaded('sodium')) {
    echo "Sodium 可用；Passkey ES256 签名由 OpenSSL 验证 ✅\n";
} elseif (extension_loaded('openssl')) {
    echo "Passkey ES256 使用 OpenSSL 验证 ⚠️\n";
} else {
    echo "⚠️ 警告：未检测到可用的加密库，插件无法正常工作！\n";
}

echo "\n";