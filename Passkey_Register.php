<?php
/**
 * Passkey 注册 Action
 */
if (!defined('__TYPECHO_ROOT_DIR__')) exit;

class Passkey_Register extends Typecho_Widget implements Widget_Interface_Do
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

        if (!$this->user->hasLogin()) {
            $this->response->throwJson(['error' => Passkey_Plugin::translate('login_required')]);
        }

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
            $this->getChallenge($data);
        } elseif ($action === 'register') {
            $this->register($data);
        } else {
            $this->response->throwJson(['error' => Passkey_Plugin::translate('unknown_action')]);
        }
    }

    private function getChallenge($data)
    {
        $user = $this->user->row;
        $challenge = Passkey_Utils_WebAuthn::generateRegistrationChallenge(
            $user['uid'],
            $user['name'],
            $user['screenName'] ?: $user['name']
        );

        $challenge['challenge'] = Passkey_Utils_WebAuthn::createChallenge('register');
        $credentials = $this->db->fetchAll(
            $this->db->select('credential_id')->from($this->passkeysTable)
                ->where('uid = ?', $user['uid'])
        );
        $challenge['excludeCredentials'] = [];
        foreach ($credentials as $credential) {
            $challenge['excludeCredentials'][] = [
                'type' => 'public-key',
                'id' => $credential['credential_id']
            ];
        }
        
        $this->response->throwJson(['publicKey' => $challenge]);
    }

    private function register($data)
    {
        try {
            $cred = $data['credential'] ?? null;
            if (empty($cred['id']) || empty($cred['rawId'])
                || empty($cred['response']['clientJSON']) || empty($cred['response']['attObj'])) {
                throw new Exception(Passkey_Plugin::translate('missing_credential'));
            }

            $clientDataJson = Passkey_Utils_WebAuthn::base64UrlDecode($cred['response']['clientJSON']);
            Passkey_Utils_WebAuthn::consumeClientChallenge('register', $clientDataJson, 'webauthn.create');
            $registration = Passkey_Utils_WebAuthn::parseAttestationObject($cred['response']['attObj']);
            $credentialId = $registration['credentialId'];
            if (!hash_equals($credentialId, Passkey_Utils_WebAuthn::base64UrlDecode($cred['rawId']))) {
                throw new Exception(Passkey_Plugin::translate('credential_mismatch'));
            }

            $credentialIdB64 = Passkey_Utils_WebAuthn::base64UrlEncode($credentialId);
            $exist = $this->db->fetchRow(
                $this->db->select('id')->from($this->passkeysTable)
                    ->where('credential_id = ?', $credentialIdB64)
                    ->limit(1)
            );
            if ($exist) throw new Exception(Passkey_Plugin::translate('already_registered'));

            $name = trim((string)($data['name'] ?? 'Passkey'));
            if ($name === '' || strlen($name) > 255) {
                throw new Exception(Passkey_Plugin::translate('invalid_passkey_name'));
            }

            $this->db->query(
                $this->db->insert($this->passkeysTable)->rows([
                    'uid' => (int)$this->user->uid,
                    'credential_id' => $credentialIdB64,
                    'public_key' => $registration['publicKey'],
                    'name' => $name,
                    'counter' => $registration['counter'],
                    'created_at' => Typecho_Date::gmtTime(),
                    'last_used_at' => null
                ])
            );
            
            $this->response->throwJson(['success' => true]);
            
        } catch (Throwable $e) {
            $this->response->throwJson(['error' => $e->getMessage()]);
        }
    }
}