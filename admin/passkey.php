<?php
/**
 * Passkey 管理页面
 */
if (!defined('__TYPECHO_ADMIN__')) exit;

Passkey_Plugin::ensureActions();
Passkey_Plugin::ensureSchema();

$userWidget = Typecho_Widget::widget('Widget_User');
if (!$userWidget->pass('administrator')) {
    $response->redirect($options->index);
}

$db = Typecho_Db::get();
$table = Passkey_Plugin::getTableName();
$messages = Passkey_Plugin::getMessages();
$currentUserUid = (int)$userWidget->uid;

// 获取当前用户的 Passkeys
$passkeys = $db->fetchAll(
    $db->select()->where('uid = ?', $currentUserUid)
        ->from($table)->order('created_at', Typecho_Db::SORT_DESC)
);
$storedUserIds = [];
if (empty($passkeys)) {
    $storedRows = $db->fetchAll($db->select('uid')->from($table));
    $storedUserIds = array_values(array_unique(array_map('intval', array_column($storedRows, 'uid'))));
}

// 获取用户信息映射
include __TYPECHO_ROOT_DIR__ . '/admin/header.php';
$passkeyCssPath = '../assets/css/passkey.css';
$passkeyCssUrl = Passkey_Plugin::getPluginUrl() . '/assets/css/passkey.css';
if (is_file($passkeyCssPath)) {
    $passkeyCssUrl .= '?v=' . filemtime($passkeyCssPath);
}
?>
<link rel="stylesheet" href="<?php echo htmlspecialchars($passkeyCssUrl, ENT_QUOTES, 'UTF-8'); ?>">
<div class="main">
    <div class="body container passkey-page">
        <div class="typecho-page-title">
            <h2><?php echo htmlspecialchars($messages['manage_title'], ENT_QUOTES, 'UTF-8'); ?></h2>
        </div>
        <div class="row typecho-page-tabs">
            <div class="col-mb-12">
                <section class="passkey-register" aria-labelledby="passkey-register-title">
                    <div class="passkey-register-copy">
                        <span class="passkey-eyebrow"><?php echo htmlspecialchars($messages['account_security'], ENT_QUOTES, 'UTF-8'); ?></span>
                        <h3 id="passkey-register-title"><?php echo htmlspecialchars($messages['register_title'], ENT_QUOTES, 'UTF-8'); ?></h3>
                        <p><?php echo htmlspecialchars($messages['register_description'], ENT_QUOTES, 'UTF-8'); ?></p>
                    </div>
                    <div class="passkey-register-controls">
                        <label class="screen-reader-text" for="passkey-name"><?php echo htmlspecialchars($messages['name_label'], ENT_QUOTES, 'UTF-8'); ?></label>
                        <input id="passkey-name" class="text" type="text" maxlength="255" required
                            placeholder="<?php echo htmlspecialchars($messages['name_placeholder'], ENT_QUOTES, 'UTF-8'); ?>" value="Passkey <?php echo date('Y'); ?>">
                        <button type="button" class="btn btn-s primary" onclick="registerNewPasskey()"><?php echo htmlspecialchars($messages['register_button'], ENT_QUOTES, 'UTF-8'); ?></button>
                    </div>
                </section>
                <div class="passkey-list-heading">
                    <div>
                        <h3><?php echo htmlspecialchars($messages['list_title'], ENT_QUOTES, 'UTF-8'); ?></h3>
                        <p><?php echo htmlspecialchars($messages['list_description'], ENT_QUOTES, 'UTF-8'); ?></p>
                    </div>
                </div>
                <div class="typecho-table-wrap">
                    <table class="typecho-list-table">
                        <thead>
                            <tr>
                                <th width="5%"><?php echo htmlspecialchars($messages['column_id'], ENT_QUOTES, 'UTF-8'); ?></th>
                                <th width="20%"><?php echo htmlspecialchars($messages['column_name'], ENT_QUOTES, 'UTF-8'); ?></th>
                                <th width="25%"><?php echo htmlspecialchars($messages['column_credential'], ENT_QUOTES, 'UTF-8'); ?></th>
                                <th width="15%"><?php echo htmlspecialchars($messages['column_created'], ENT_QUOTES, 'UTF-8'); ?></th>
                                <th width="15%"><?php echo htmlspecialchars($messages['column_last_used'], ENT_QUOTES, 'UTF-8'); ?></th>
                                <th width="20%"><?php echo htmlspecialchars($messages['column_actions'], ENT_QUOTES, 'UTF-8'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($passkeys)): ?>
                            <tr><td colspan="6" class="empty"><?php echo htmlspecialchars($messages['empty_list'], ENT_QUOTES, 'UTF-8'); ?></td></tr>
                                <?php if (!empty($storedUserIds)): ?>
                                <tr><td colspan="6" class="message warning"><?php echo htmlspecialchars(sprintf($messages['database_warning'], $currentUserUid, count($storedRows), implode(', ', $storedUserIds)), ENT_QUOTES, 'UTF-8'); ?></td></tr>
                                <?php endif; ?>
                            <?php else: ?>
                                <?php foreach ($passkeys as $pk): ?>
                                <tr id="passkey-<?php echo (int)$pk['id']; ?>">
                                    <td><?php echo (int)$pk['id']; ?></td>
                                    <td><?php echo htmlspecialchars($pk['name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><code><?php echo htmlspecialchars(substr($pk['credential_id'], 0, 20), ENT_QUOTES, 'UTF-8'); ?>...</code></td>
                                    <td><?php echo date('Y-m-d H:i:s', $pk['created_at']); ?></td>
                                    <td><?php echo $pk['last_used_at'] ? date('Y-m-d H:i:s', $pk['last_used_at']) : htmlspecialchars($messages['never_used'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td>
                                        <a href="#" class="passkey-rename-link" data-passkey-id="<?php echo (int)$pk['id']; ?>" data-passkey-name="<?php echo htmlspecialchars($pk['name'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($messages['rename'], ENT_QUOTES, 'UTF-8'); ?></a> | 
                                        <a href="#" onclick="delPasskey(<?php echo (int)$pk['id']; ?>);return false;" class="text-danger"><?php echo htmlspecialchars($messages['delete'], ENT_QUOTES, 'UTF-8'); ?></a>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>
<script>
var registerUrl = <?php echo json_encode($options->index . '/action/passkey-register', JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>;
var deleteUrl = <?php echo json_encode($options->index . '/action/passkey-delete', JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>;
var renameUrl = <?php echo json_encode($options->index . '/action/passkey-rename', JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>;
var passkeyMessages = <?php echo json_encode($messages, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>;

function passkeyText(key) {
    return passkeyMessages[key] || key;
}

function registerNewPasskey() {
    var nameInput = document.getElementById('passkey-name');
    var name = nameInput.value.trim();
    if (!name) {
        nameInput.setCustomValidity(passkeyText('empty_name'));
        nameInput.reportValidity();
        return;
    }
    nameInput.setCustomValidity('');
    if (window.PasskeyAuth) {
        window.PasskeyAuth.register(registerUrl, name);
    } else {
        alert(passkeyText('module_missing'));
    }
}

function delPasskey(id) {
    if (!confirm(passkeyText('confirm_delete'))) return;
    fetch(deleteUrl, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({id: id})
    })
    .then(function(r){return r.json();})
    .then(function(res){
        if(res.success) location.reload();
        else alert(res.error || passkeyText('delete_failed'));
    });
}

document.addEventListener('click', function(event) {
    var target = event.target.closest('.passkey-rename-link');
    if (!target) return;
    event.preventDefault();
    renamePasskey(Number(target.dataset.passkeyId), target.dataset.passkeyName || '');
});

function renamePasskey(id, name) {
    var currentName = (typeof name === 'string') ? name : '';
    var newName = prompt(passkeyText('rename_prompt'), currentName);
    if (newName === null) return;

    newName = newName.trim();
    if (!newName) {
        alert(passkeyText('empty_name'));
        return;
    }
    if (newName.length > 50) {
        alert(passkeyText('invalid_rename_length'));
        return;
    }

    fetch(renameUrl, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({id: id, name: newName})
    })
    .then(function(r){return r.json();})
    .then(function(res){
        if(res.success) location.reload();
        else alert(res.error || passkeyText('rename_failed'));
    });
}
</script>
<?php include __TYPECHO_ROOT_DIR__ . '/admin/footer.php'; ?>