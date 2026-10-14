<?php
/**
 * Passkey 通行密钥
 * 
 * @package Passkey 
 * @author Jake Liu
 * @version 1.0.1
 * @link https://github.com/LittleJake/typecho-passkey
 */

if (!defined('__TYPECHO_ROOT_DIR__')) exit;

require_once 'Utils/Crypto.php';
require_once 'Utils/WebAuthn.php';

class Passkey_Plugin implements Typecho_Plugin_Interface
{
    const VERSION = '1.0.0';
    const TABLE_NAME = 'passkeys';

    /**
     * 激活插件
     * @return string
     */
    public static function activate()
    {
        $db = Typecho_Db::get();
        $p = $db->getPrefix();
        $adapter = $db->getAdapterName();

        // 创建数据表
        if (stripos($adapter, 'mysql') !== false || stripos($adapter, 'mysqli') !== false) {
            $db->query("CREATE TABLE IF NOT EXISTS `{$p}passkeys` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `uid` INT UNSIGNED NOT NULL,
                `credential_id` VARCHAR(255) NOT NULL,
                `public_key` TEXT NOT NULL,
                `name` VARCHAR(255) DEFAULT 'Passkey',
                `counter` BIGINT UNSIGNED DEFAULT 0,
                `created_at` INT UNSIGNED NOT NULL,
                `last_used_at` INT UNSIGNED NULL,
                PRIMARY KEY (`id`),
                KEY `uid` (`uid`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        } elseif (stripos($adapter, 'pgsql') !== false) {
            $db->query("CREATE TABLE IF NOT EXISTS \"{$p}passkeys\" (
                \"id\" SERIAL,
                \"uid\" INTEGER,
                \"credential_id\" VARCHAR(255),
                \"public_key\" TEXT,
                \"name\" VARCHAR(255) DEFAULT 'Passkey',
                \"counter\" BIGINT DEFAULT 0,
                \"created_at\" INTEGER,
                \"last_used_at\" INTEGER,
                PRIMARY KEY (\"id\")
            )");
        } else {
            $db->query("CREATE TABLE IF NOT EXISTS \"{$p}passkeys\" (
                \"id\" INTEGER PRIMARY KEY AUTOINCREMENT,
                \"uid\" INTEGER,
                \"credential_id\" VARCHAR(255),
                \"public_key\" TEXT,
                \"name\" VARCHAR(255) DEFAULT 'Passkey',
                \"counter\" INTEGER DEFAULT 0,
                \"created_at\" INTEGER,
                \"last_used_at\" INTEGER
            )");
        }

        self::ensureSchema();
        Helper::addPanel(1, 'Passkey/admin/passkey.php', self::translate('manage_title'), self::translate('panel_description'), 'administrator');
        self::ensureActions();

        // 注入登录页
        Typecho_Plugin::factory('admin/footer.php')->begin = [__CLASS__, 'renderFooter'];

        return self::translate('plugin_enabled');
    }

    /**
     * 禁用插件
     * @return string
     */
    public static function deactivate()
    {
        Helper::removePanel(1, 'Passkey/admin/passkey.php');
        Helper::removeAction('passkey-auth');
        Helper::removeAction('passkey-register');
        Helper::removeAction('passkey-delete');
        Helper::removeAction('passkey-rename');

        return self::translate('plugin_disabled');
    }

    public static function getLanguage()
    {
        $options = Typecho_Widget::widget('Widget_Options');
        $language = strtolower((string)($options->lang ?? 'zh_CN'));
        $language = substr($language, 0, 2);

        return in_array($language, ['en', 'ru'], true) ? $language : 'zh';
    }

    public static function getMessages()
    {
        $messages = [
            'zh' => [
                'manage_title' => 'Passkey 管理',
                'panel_description' => '管理 Passkey',
                'plugin_enabled' => '插件已启用',
                'plugin_disabled' => '插件已禁用',
                'config_description' => '插件已启用。请通过后台“Passkey 管理”页面管理 Passkey。',
                'account_security' => '账号安全',
                'register_title' => '注册新的 Passkey',
                'register_description' => '为这台设备设置一个容易辨认的名称，然后按提示完成验证。',
                'name_label' => 'Passkey 名称',
                'name_placeholder' => '例如：我的 iPhone',
                'register_button' => '注册 Passkey',
                'list_title' => '我的 Passkey',
                'list_description' => '已添加的设备和安全密钥',
                'empty_list' => '暂无 Passkey，请点击上方按钮注册',
                'database_warning' => '当前用户 UID：%d；数据库中有 %d 条记录，UID：%s。请核对登录账号或 Typecho 使用的 SQLite 数据库文件。',
                'column_id' => 'ID',
                'column_name' => '名称',
                'column_credential' => 'Credential ID',
                'column_created' => '创建时间',
                'column_last_used' => '最后使用',
                'column_actions' => '操作',
                'never_used' => '从未',
                'rename' => '重命名',
                'delete' => '删除',
                'empty_name' => '请输入 Passkey 名称',
                'module_missing' => 'Passkey 模块未加载',
                'confirm_delete' => '确定删除此 Passkey？删除后将无法使用此设备登录。',
                'delete_failed' => '删除失败',
                'rename_prompt' => '请输入新名称:',
                'rename_failed' => '重命名失败',
                'http_error' => 'HTTP {status}，服务器未返回 JSON：',
                'invalid_response' => '服务器响应无效',
                'unsupported' => '浏览器不支持 Passkey',
                'login_failed' => '登录失败',
                'register_failed' => '注册失败',
                'register_cancelled' => 'Passkey 注册未完成：请求被取消或超时。请在浏览器弹窗中完成验证，或改用可用的安全密钥后重试。',
                'login_button' => '使用 Passkey 登录',
                'login_required' => '请先登录',
                'post_only' => '仅支持 POST',
                'invalid_request' => '无效请求',
                'unknown_action' => '未知操作',
                'missing_credential' => '缺少凭证数据',
                'credential_mismatch' => 'Credential ID 校验失败',
                'credential_not_found' => '凭证不存在',
                'invalid_public_key' => '公钥无效',
                'signature_invalid' => '签名验证失败',
                'replay_detected' => '可能的重放攻击',
                'user_not_found' => '用户不存在',
                'already_registered' => '该 Passkey 已注册',
                'invalid_passkey_name' => 'Passkey 名称长度无效',
                'invalid_rename_length' => '名称长度为 1-50 字符',
                'cose_public_key_invalid' => 'COSE 公钥数据无效',
                'challenge_expired' => 'Challenge 已过期，请重试',
                'webauthn_response_invalid' => 'WebAuthn 响应校验失败',
                'attestation_unsupported' => '不支持的 attestation 格式',
                'authenticator_data_invalid' => 'Authenticator 数据无效',
                'authenticator_missing_public_key' => 'Authenticator 未返回注册公钥',
                'credential_data_invalid' => 'Credential 数据无效',
                'rp_id_mismatch' => 'RP ID 校验失败',
                'user_verification_required' => 'Authenticator 未完成用户验证',
                'algorithm_unsupported' => '仅支持 ES256 (P-256) Passkey',
                'p256_public_key_invalid' => 'P-256 公钥无效',
                'site_url_invalid' => 'Typecho 站点地址无效',
                'https_required' => 'Passkey 仅允许通过 HTTPS 使用，请先将 Typecho 站点地址配置为 HTTPS',
                'same_origin_https_required' => 'Passkey 请求必须来自 HTTPS 同源页面',
                'session_failed' => '无法创建 WebAuthn 会话',
                'cbor_data_invalid' => 'CBOR 数据无效',
                'cbor_type_unsupported' => '不支持的 CBOR 类型',
                'cbor_length_invalid' => 'CBOR 长度无效',
                'cbor_indefinite_unsupported' => '不支持不定长 CBOR 数据',
                'cbor_field_out_of_range' => 'CBOR 字段长度超出范围',
                'cbor_collection_too_large' => 'CBOR 集合过大',
                'cbor_unsupported' => '不支持的 CBOR 数据',
                'secure_random_failed' => '无法生成安全随机数'
            ],
            'en' => [
                'manage_title' => 'Passkey Management',
                'panel_description' => 'Manage Passkeys',
                'plugin_enabled' => 'The plugin has been enabled.',
                'plugin_disabled' => 'The plugin has been disabled.',
                'config_description' => 'The plugin is enabled. Manage Passkeys from the Passkey Management page in the dashboard.',
                'account_security' => 'Account security',
                'register_title' => 'Register a Passkey',
                'register_description' => 'Give this device a recognizable name, then follow the prompts to verify your identity.',
                'name_label' => 'Passkey name',
                'name_placeholder' => 'For example: My iPhone',
                'register_button' => 'Register Passkey',
                'list_title' => 'My Passkeys',
                'list_description' => 'Registered devices and security keys',
                'empty_list' => 'No Passkeys yet. Use the form above to register one.',
                'database_warning' => 'Current user UID: %d; %d database records were found for UIDs: %s. Check the signed-in account or the SQLite database file used by Typecho.',
                'column_id' => 'ID',
                'column_name' => 'Name',
                'column_credential' => 'Credential ID',
                'column_created' => 'Created',
                'column_last_used' => 'Last used',
                'column_actions' => 'Actions',
                'never_used' => 'Never',
                'rename' => 'Rename',
                'delete' => 'Delete',
                'empty_name' => 'Enter a Passkey name.',
                'module_missing' => 'The Passkey module did not load.',
                'confirm_delete' => 'Delete this Passkey? This device will no longer be able to sign in with it.',
                'delete_failed' => 'Could not delete the Passkey.',
                'rename_prompt' => 'Enter a new name:',
                'rename_failed' => 'Could not rename the Passkey.',
                'http_error' => 'HTTP {status}; the server did not return JSON: ',
                'invalid_response' => 'The server returned an invalid response.',
                'unsupported' => 'This browser does not support Passkeys.',
                'login_failed' => 'Sign-in failed',
                'register_failed' => 'Passkey registration failed',
                'register_cancelled' => 'Passkey registration was cancelled or timed out. Complete the browser prompt, or try again with an available security key.',
                'login_button' => 'Sign in with Passkey',
                'login_required' => 'Please sign in first.',
                'post_only' => 'Only POST requests are supported.',
                'invalid_request' => 'Invalid request.',
                'unknown_action' => 'Unknown action.',
                'missing_credential' => 'Credential data is missing.',
                'credential_mismatch' => 'Credential ID verification failed.',
                'credential_not_found' => 'Credential not found.',
                'invalid_public_key' => 'The public key is invalid.',
                'signature_invalid' => 'Signature verification failed.',
                'replay_detected' => 'A possible replay attack was detected.',
                'user_not_found' => 'User not found.',
                'already_registered' => 'This Passkey is already registered.',
                'invalid_passkey_name' => 'The Passkey name must be between 1 and 255 characters.',
                'invalid_rename_length' => 'The name must be between 1 and 50 characters.',
                'cose_public_key_invalid' => 'The COSE public key data is invalid.',
                'challenge_expired' => 'The challenge has expired. Please try again.',
                'webauthn_response_invalid' => 'WebAuthn response verification failed.',
                'attestation_unsupported' => 'This attestation format is not supported.',
                'authenticator_data_invalid' => 'Authenticator data is invalid.',
                'authenticator_missing_public_key' => 'The authenticator did not return a registration public key.',
                'credential_data_invalid' => 'Credential data is invalid.',
                'rp_id_mismatch' => 'RP ID verification failed.',
                'user_verification_required' => 'The authenticator did not verify the user.',
                'algorithm_unsupported' => 'Only ES256 (P-256) Passkeys are supported.',
                'p256_public_key_invalid' => 'The P-256 public key is invalid.',
                'site_url_invalid' => 'The Typecho site URL is invalid.',
                'https_required' => 'Passkeys require HTTPS. Configure the Typecho site URL to use HTTPS.',
                'same_origin_https_required' => 'Passkey requests must come from a same-origin HTTPS page.',
                'session_failed' => 'Could not create a WebAuthn session.',
                'cbor_data_invalid' => 'CBOR data is invalid.',
                'cbor_type_unsupported' => 'This CBOR type is not supported.',
                'cbor_length_invalid' => 'The CBOR length is invalid.',
                'cbor_indefinite_unsupported' => 'Indefinite-length CBOR data is not supported.',
                'cbor_field_out_of_range' => 'The CBOR field length is out of range.',
                'cbor_collection_too_large' => 'The CBOR collection is too large.',
                'cbor_unsupported' => 'This CBOR data is not supported.',
                'secure_random_failed' => 'Could not generate secure random data.'
            ],
            'ru' => [
                'manage_title' => 'Управление Passkey',
                'panel_description' => 'Управление Passkey',
                'plugin_enabled' => 'Плагин включён.',
                'plugin_disabled' => 'Плагин отключён.',
                'config_description' => 'Плагин включён. Управляйте Passkey на странице управления Passkey в панели администратора.',
                'account_security' => 'Безопасность аккаунта',
                'register_title' => 'Добавить Passkey',
                'register_description' => 'Укажите понятное название устройства и выполните проверку по подсказкам.',
                'name_label' => 'Название Passkey',
                'name_placeholder' => 'Например: мой iPhone',
                'register_button' => 'Добавить Passkey',
                'list_title' => 'Мои Passkey',
                'list_description' => 'Зарегистрированные устройства и ключи безопасности',
                'empty_list' => 'Passkey пока нет. Зарегистрируйте ключ с помощью формы выше.',
                'database_warning' => 'UID текущего пользователя: %d; в базе найдено записей: %d, UID: %s. Проверьте аккаунт или файл базы SQLite, используемый Typecho.',
                'column_id' => 'ID',
                'column_name' => 'Название',
                'column_credential' => 'ID учётных данных',
                'column_created' => 'Создан',
                'column_last_used' => 'Последнее использование',
                'column_actions' => 'Действия',
                'never_used' => 'Никогда',
                'rename' => 'Переименовать',
                'delete' => 'Удалить',
                'empty_name' => 'Введите название Passkey.',
                'module_missing' => 'Модуль Passkey не загружен.',
                'confirm_delete' => 'Удалить этот Passkey? Это устройство больше не сможет входить с его помощью.',
                'delete_failed' => 'Не удалось удалить Passkey.',
                'rename_prompt' => 'Введите новое название:',
                'rename_failed' => 'Не удалось переименовать Passkey.',
                'http_error' => 'HTTP {status}; сервер вернул не JSON: ',
                'invalid_response' => 'Сервер вернул некорректный ответ.',
                'unsupported' => 'Этот браузер не поддерживает Passkey.',
                'login_failed' => 'Не удалось войти',
                'register_failed' => 'Не удалось зарегистрировать Passkey',
                'register_cancelled' => 'Регистрация Passkey отменена или истекло время ожидания. Выполните проверку в окне браузера или повторите попытку с ключом безопасности.',
                'login_button' => 'Войти с помощью Passkey',
                'login_required' => 'Сначала войдите в систему.',
                'post_only' => 'Поддерживаются только POST-запросы.',
                'invalid_request' => 'Некорректный запрос.',
                'unknown_action' => 'Неизвестное действие.',
                'missing_credential' => 'Данные учётных данных отсутствуют.',
                'credential_mismatch' => 'Проверка ID учётных данных не пройдена.',
                'credential_not_found' => 'Учётные данные не найдены.',
                'invalid_public_key' => 'Недействительный открытый ключ.',
                'signature_invalid' => 'Проверка подписи не пройдена.',
                'replay_detected' => 'Обнаружена возможная повторная атака.',
                'user_not_found' => 'Пользователь не найден.',
                'already_registered' => 'Этот Passkey уже зарегистрирован.',
                'invalid_passkey_name' => 'Название Passkey должно содержать от 1 до 255 символов.',
                'invalid_rename_length' => 'Название должно содержать от 1 до 50 символов.',
                'cose_public_key_invalid' => 'Некорректные данные открытого ключа COSE.',
                'challenge_expired' => 'Срок действия challenge истёк. Повторите попытку.',
                'webauthn_response_invalid' => 'Проверка ответа WebAuthn не пройдена.',
                'attestation_unsupported' => 'Этот формат attestation не поддерживается.',
                'authenticator_data_invalid' => 'Некорректные данные аутентификатора.',
                'authenticator_missing_public_key' => 'Аутентификатор не вернул открытый ключ для регистрации.',
                'credential_data_invalid' => 'Некорректные данные учётных данных.',
                'rp_id_mismatch' => 'Проверка RP ID не пройдена.',
                'user_verification_required' => 'Аутентификатор не подтвердил пользователя.',
                'algorithm_unsupported' => 'Поддерживаются только Passkey с ES256 (P-256).',
                'p256_public_key_invalid' => 'Некорректный открытый ключ P-256.',
                'site_url_invalid' => 'Некорректный адрес сайта Typecho.',
                'https_required' => 'Для Passkey требуется HTTPS. Настройте адрес сайта Typecho с использованием HTTPS.',
                'same_origin_https_required' => 'Запросы Passkey должны поступать с одноимённой страницы по HTTPS.',
                'session_failed' => 'Не удалось создать сеанс WebAuthn.',
                'cbor_data_invalid' => 'Некорректные данные CBOR.',
                'cbor_type_unsupported' => 'Этот тип CBOR не поддерживается.',
                'cbor_length_invalid' => 'Некорректная длина CBOR.',
                'cbor_indefinite_unsupported' => 'CBOR с неопределённой длиной не поддерживается.',
                'cbor_field_out_of_range' => 'Длина поля CBOR выходит за допустимые пределы.',
                'cbor_collection_too_large' => 'Коллекция CBOR слишком велика.',
                'cbor_unsupported' => 'Эти данные CBOR не поддерживаются.',
                'secure_random_failed' => 'Не удалось создать криптографически стойкие случайные данные.'
            ]
        ];

        return $messages[self::getLanguage()];
    }

    public static function translate($key)
    {
        $messages = self::getMessages();
        return $messages[$key] ?? $key;
    }

    /**
     * 插件配置界面
     */
    public static function config(Typecho_Widget_Helper_Form $form)
    {
        self::ensureActions();
        self::ensureSchema();

        $form->addInput(new Typecho_Widget_Helper_Form_Element_Hidden('initialized', null, '1'));

        $notice = new Typecho_Widget_Helper_Layout('div', ['class' => 'typecho-page-description']);
        $notice->html('<h3>Passkey</h3><p>' . htmlspecialchars(self::translate('config_description'), ENT_QUOTES, 'UTF-8') . '</p>');
        $form->addItem($notice);
    }

    public static function ensureActions()
    {
        $actions = [
            'passkey-auth' => 'Passkey_Auth',
            'passkey-register' => 'Passkey_Register',
            'passkey-delete' => 'Passkey_Delete',
            'passkey-rename' => 'Passkey_Rename'
        ];
        $options = Typecho_Widget::widget('Widget_Options');
        $registered = $options->actionTable;
        $registered = is_array($registered) ? $registered : [];

        foreach ($actions as $action => $widget) {
            if (!isset($registered[$action]) || $registered[$action] !== $widget) {
                Helper::addAction($action, $widget);
            }
        }
    }

    public static function ensureSchema()
    {
        $db = Typecho_Db::get();
        $table = $db->getPrefix() . self::TABLE_NAME;
        $adapter = strtolower($db->getAdapterName());
        $needsAlter = false;

        if (strpos($adapter, 'mysql') !== false || strpos($adapter, 'mysqli') !== false) {
            $quotedTable = '`' . str_replace('`', '``', $table) . '`';
            $columns = $db->fetchAll("SHOW COLUMNS FROM {$quotedTable} LIKE 'last_used_at'");
            $alter = "ALTER TABLE {$quotedTable} ADD COLUMN `last_used_at` INT UNSIGNED NULL";
            $needsAlter = empty($columns);
        } elseif (strpos($adapter, 'pgsql') !== false) {
            $quotedTable = '"' . str_replace('"', '""', $table) . '"';
            $tableValue = $db->getAdapter()->quoteValue($table);
            $columns = $db->fetchAll(
                "SELECT column_name FROM information_schema.columns "
                . "WHERE table_schema = current_schema() AND table_name = {$tableValue} "
                . "AND column_name = 'last_used_at'"
            );
            $alter = "ALTER TABLE {$quotedTable} ADD COLUMN \"last_used_at\" INTEGER NULL";
            $needsAlter = empty($columns);
        } else {
            $quotedTable = '"' . str_replace('"', '""', $table) . '"';
            $columns = $db->fetchAll("PRAGMA table_info({$quotedTable})");
            foreach ($columns as $column) {
                if (($column['name'] ?? '') === 'last_used_at') {
                    return;
                }
            }
            $alter = "ALTER TABLE {$quotedTable} ADD COLUMN \"last_used_at\" INTEGER NULL";
            $needsAlter = true;
        }

        if ($needsAlter) {
            $db->query($alter, Typecho_Db::WRITE, '');
        }
    }

    /**
     * 个人配置界面
     */
    public static function personalConfig(Typecho_Widget_Helper_Form $form)
    {
    }

    /**
     * 渲染页脚
     */
    public static function renderFooter()
    {
        self::ensureActions();
        $pluginUrl = self::getPluginUrl();
        $scriptPath = 'assets/js/passkey.js';
        $scriptUrl = $pluginUrl . '/assets/js/passkey.js';
        if (is_file($scriptPath)) {
            $scriptUrl .= '?v=' . filemtime($scriptPath);
        }
        $messagesJson = json_encode(self::getMessages(), JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT);
        echo '<script>window.PasskeyI18n=' . $messagesJson . ';</script>' . "\n";
        echo '<script src="' . htmlspecialchars($scriptUrl, ENT_QUOTES, 'UTF-8') . '"></script>' . "\n";

        $user = Typecho_Widget::widget('Widget_User');
        if ($user->hasLogin()) {
            return;
        }

        $options = Typecho_Widget::widget('Widget_Options');
        $authUrl = $options->index . '/action/passkey-auth';
        $requestUri = $_SERVER['REQUEST_URI'] ?? '';
        if (strpos($requestUri, 'login.php') === false) {
            return;
        }

        $encodedAuthUrl = json_encode($authUrl, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT);
        $loginButton = json_encode(self::translate('login_button'), JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT);
        echo '<script>(function($){$(function(){var form=$("form[name=login]");if(!form.length||!window.PasskeyAuth)return;var button=$("<button type=\"button\" class=\"btn btn-l w-100\"></button>").text(' . $loginButton . ');button.on("click",function(){window.PasskeyAuth.login(' . $encodedAuthUrl . ');});form.find("button[type=submit]").last().after(button);});})(jQuery);</script>' . "\n";
    }

    /**
     * 获取插件目录
     * @return string
     */
    public static function getPluginUrl()
    {
        return __TYPECHO_PLUGIN_DIR__ . '/Passkey';
    }

    /**
     * 获取数据表名
     * @return string
     */
    public static function getTableName()
    {
        return Typecho_Db::get()->getPrefix() . self::TABLE_NAME;
    }
}
