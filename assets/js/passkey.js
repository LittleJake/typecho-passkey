(function (global) {
	'use strict';

	function text(key, fallback) {
		var messages = global.PasskeyI18n || {};
		return messages[key] || fallback || key;
	}

	function encodeBase64Url(buffer) {
		var bytes = new Uint8Array(buffer);
		var binary = '';
		for (var index = 0; index < bytes.length; index++) {
			binary += String.fromCharCode(bytes[index]);
		}
		return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
	}

	function decodeBase64Url(value) {
		value = value.replace(/-/g, '+').replace(/_/g, '/');
		while (value.length % 4) value += '=';
		return Uint8Array.from(atob(value), function (character) {
			return character.charCodeAt(0);
		}).buffer;
	}

	function postJson(url, data) {
		return fetch(url, {
			method: 'POST',
			headers: {'Content-Type': 'application/json'},
			body: JSON.stringify(data)
		}).then(function (response) {
			return response.text().then(function (body) {
				var result;
				try {
					result = JSON.parse(body);
				} catch (error) {
					throw new Error(text('http_error', 'HTTP {status}，服务器未返回 JSON：')
						.replace('{status}', response.status) + body.slice(0, 180));
				}
				if (!response.ok) {
					throw new Error(result.error || ('HTTP ' + response.status));
				}
				return result;
			});
		}).then(function (result) {
			if (!result || result.error) {
				throw new Error(result && result.error ? result.error : text('invalid_response', '服务器响应无效'));
			}
			return result;
		});
	}

	function assertSupport() {
		if (!global.PublicKeyCredential) {
			throw new Error(text('unsupported', '浏览器不支持 Passkey'));
		}
	}

	var passkeyAuth = {
		login: function (url) {
			try {
				assertSupport();
			} catch (error) {
				alert(error.message);
				return;
			}

			postJson(url, {action: 'get_challenge'})
				.then(function (result) {
					var publicKey = result.publicKey;
					publicKey.challenge = decodeBase64Url(publicKey.challenge);
					(publicKey.allowCredentials || []).forEach(function (credential) {
						credential.id = decodeBase64Url(credential.id);
					});
					return navigator.credentials.get({publicKey: publicKey});
				})
				.then(function (assertion) {
					if (!assertion) return null;
					return postJson(url, {
						action: 'authenticate',
						credential: {
							id: assertion.id,
							rawId: encodeBase64Url(assertion.rawId),
							type: assertion.type,
							response: {
								authData: encodeBase64Url(assertion.response.authenticatorData),
								clientJSON: encodeBase64Url(assertion.response.clientDataJSON),
								sig: encodeBase64Url(assertion.response.signature),
								userHandle: assertion.response.userHandle
									? encodeBase64Url(assertion.response.userHandle)
									: null
							}
						}
					});
				})
				.then(function (result) {
					if (result && result.success) location.reload();
					else if (result) throw new Error(result.error || text('login_failed', '登录失败'));
				})
				.catch(function (error) {
					if (error && error.name === 'NotAllowedError') {
						alert('Passkey 登录未完成：请求被取消、超时，或当前凭证提供器没有此域名对应的 Passkey。请在浏览器弹窗中选择为当前域名注册的 Passkey 后重试。');
						return;
					}
					alert(text('login_failed', '登录失败') + ': ' + error.message);
				});
		},
		register: function (url, name) {
			try {
				assertSupport();
			} catch (error) {
				alert(error.message);
				return;
			}

			postJson(url, {action: 'get_challenge', name: name})
				.then(function (result) {
					var publicKey = result.publicKey;
					publicKey.challenge = decodeBase64Url(publicKey.challenge);
					publicKey.user.id = decodeBase64Url(publicKey.user.id);
					(publicKey.excludeCredentials || []).forEach(function (credential) {
						credential.id = decodeBase64Url(credential.id);
					});
					return navigator.credentials.create({publicKey: publicKey});
				})
				.then(function (credential) {
					if (!credential) return null;
					return postJson(url, {
						action: 'register',
						name: name,
						credential: {
							id: credential.id,
							rawId: encodeBase64Url(credential.rawId),
							type: credential.type,
							response: {
								attObj: encodeBase64Url(credential.response.attestationObject),
								clientJSON: encodeBase64Url(credential.response.clientDataJSON)
							}
						}
					});
				})
				.then(function (result) {
					if (result && result.success) location.reload();
					else if (result) throw new Error(result.error || text('register_failed', '注册失败'));
				})
				.catch(function (error) {
					if (error && error.name === 'NotAllowedError') {
						alert(text('register_cancelled', 'Passkey 注册未完成：请求被取消或超时。请在浏览器弹窗中完成验证，或改用可用的安全密钥后重试。'));
						return;
					}
					alert(text('register_failed', '注册失败') + ': ' + (error.name ? error.name + ': ' : '') + error.message);
				});
		}
	};

	global.PasskeyAuth = passkeyAuth;
})(window);