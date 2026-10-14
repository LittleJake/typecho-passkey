<?php
/**
 * Passkey 重命名 Action
 */
if (!defined('__TYPECHO_ROOT_DIR__')) exit;

class Passkey_Rename extends Typecho_Widget implements Widget_Interface_Do
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
        if (!$data || empty($data['id']) || !isset($data['name'])) {
            $this->response->throwJson(['error' => Passkey_Plugin::translate('invalid_request')]);
        }

        $id = (int)$data['id'];
        $name = trim($data['name']);
        
        if (strlen($name) < 1 || strlen($name) > 50) {
            $this->response->throwJson(['error' => Passkey_Plugin::translate('invalid_rename_length')]);
        }

        $rows = $this->db->query(
            $this->db->update($this->passkeysTable)
                ->rows(['name' => $name])
                ->where('id = ?', $id)
                ->where('uid = ?', $this->user->row['uid'])
        );

        if ($rows > 0) {
            $this->response->throwJson(['success' => true]);
        } else {
            $this->response->throwJson(['error' => Passkey_Plugin::translate('rename_failed')]);
        }
    }
}