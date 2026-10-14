<?php
/**
 * Passkey 删除 Action
 */
if (!defined('__TYPECHO_ROOT_DIR__')) exit;

class Passkey_Delete extends Typecho_Widget implements Widget_Interface_Do
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
        if (!$this->user->hasLogin()) {
            $this->response->throwJson(['error' => Passkey_Plugin::translate('login_required')]);
        }

        if (!$this->request->isPost()) {
            $this->response->throwJson(['error' => Passkey_Plugin::translate('post_only')]);
        }

        $body = file_get_contents('php://input');
        $data = json_decode($body, true);
        if (!$data || empty($data['id'])) {
            $this->response->throwJson(['error' => Passkey_Plugin::translate('invalid_request')]);
        }

        // 删除 Passkey
        $rows = $this->db->query(
            $this->db->delete($this->passkeysTable)
                ->where('id = ?', $data['id'])
                ->where('uid = ?', $this->user->row['uid'])
        );

        if ($rows > 0) {
            $this->response->throwJson(['success' => true]);
        } else {
            $this->response->throwJson(['error' => Passkey_Plugin::translate('delete_failed')]);
        }
    }
}