<?php
/**
 * Passkey 认证 Action
 */
if (!defined('__TYPECHO_ROOT_DIR__')) exit;

class Passkey_Auth extends Typecho_Widget implements Widget_Interface_Do
{
    private $db;
    private $user;
    private $passkeysTable;

    public function __construct($request, $response, $params = null)
    {
        parent::__construct($request, $response, $params);
        $this->db = Typecho_Db::get();
        $this->user = $this->widget('Widget_User');
        $this->passkeysTable = Passkey_Plugin::getTableName();
    }

    public function action()
    {
        Passkey_Plugin::ensureSchema();

        if (!$this->request->isPost()) {
            $this->response->throwJson(['error' => Passkey_Plugin::translate('post_only')]);
        }

        $body = file_get_contents('php://input');
        $data = json_decode($body, true);
        if (!$data) {
            $this->response->throwJson(['error' => Passkey_Plugin::translate('invalid_request')]);
        }

        $action = $data['action'] ?? '';
        
        if ($action === 'get_challenge') {
            $this->getChallenge();
        } elseif ($action === 'authenticate' || $action === 'auth') {
            $this->authenticate($data);
        } else {
            $this->response->throwJson(['error' => Passkey_Plugin::translate('unknown_action')]);
        }
    }

    private function getChallenge()
    {
        // 获取所有已注册的凭证 ID
        $credentials = $this->db->fetchAll(
            $this->db->select('credential_id')->from($this->passkeysTable)
        );
        
        $challenge = Passkey_Utils_WebAuthn::generateAuthenticationChallenge($credentials);
        $challenge['challenge'] = Passkey_Utils_WebAuthn::createChallenge('authenticate');
        $this->response->throwJson(['publicKey' => $challenge]);
    }

    private function authenticate($data)
    {
        try {
            $cred = $data['credential'] ?? null;
            if (empty($cred['id']) || empty($cred['rawId'])
                || empty($cred['response']['clientJSON']) || empty($cred['response']['authData'])
                || empty($cred['response']['sig'])) {
                throw new Exception(Passkey_Plugin::translate('missing_credential'));
            }

            $credentialIdRaw = Passkey_Utils_WebAuthn::base64UrlDecode($cred['rawId']);
            if (!hash_equals($cred['id'], Passkey_Utils_WebAuthn::base64UrlEncode($credentialIdRaw))) {
                throw new Exception(Passkey_Plugin::translate('credential_mismatch'));
            }
            $credentialId = $cred['id'];

            $clientDataJson = Passkey_Utils_WebAuthn::base64UrlDecode($cred['response']['clientJSON']);
            Passkey_Utils_WebAuthn::consumeClientChallenge('authenticate', $clientDataJson, 'webauthn.get');
            
            // 从数据库获取凭证
            $row = $this->db->fetchRow(
                $this->db->select()->from($this->passkeysTable)
                    ->where('credential_id = ?', $credentialId)
                    ->limit(1)
            );
            
            if (!$row) {
                throw new Exception(Passkey_Plugin::translate('credential_not_found'));
            }
            
            // 构建签名验证数据
            $authData = Passkey_Utils_WebAuthn::base64UrlDecode($cred['response']['authData']);
            Passkey_Utils_WebAuthn::verifyAuthenticatorData($authData);
            $signatureBase = $authData . Passkey_Utils_WebAuthn::hash($clientDataJson);
            $signature = Passkey_Utils_WebAuthn::base64UrlDecode($cred['response']['sig']);
            
            $publicKey = $row['public_key'];
            if (!$publicKey) throw new Exception(Passkey_Plugin::translate('invalid_public_key'));
            
            if (!Passkey_Utils_WebAuthn::verifySignature($publicKey, $signatureBase, $signature)) {
                throw new Exception(Passkey_Plugin::translate('signature_invalid'));
            }
            
            // 检查计数器（防止重放攻击）
            $counter = Passkey_Utils_WebAuthn::readCounter($authData);
            if (($counter > 0 || (int)$row['counter'] > 0) && $counter <= (int)$row['counter']) {
                throw new Exception(Passkey_Plugin::translate('replay_detected'));
            }
            
            // 更新计数器和使用时间
            $this->db->query(
                $this->db->update($this->passkeysTable)
                    ->rows(['counter' => $counter, 'last_used_at' => Typecho_Date::gmtTime()])
                    ->where('id = ?', $row['id'])
            );
            
            // 获取用户信息并登录
            $userRow = $this->db->fetchRow(
                $this->db->select()->from('table.users')
                    ->where('uid = ?', $row['uid'])
                    ->limit(1)
            );
            
            if (!$userRow) throw new Exception(Passkey_Plugin::translate('user_not_found'));
            
            // 登录用户
            $this->user->simpleLogin($userRow, false);
            
            $this->response->throwJson(['success' => true]);
            
        } catch (Throwable $e) {
            $this->response->throwJson(['error' => $e->getMessage()]);
        }
    }
}