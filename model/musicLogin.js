import crypto from 'crypto';
import fetch from 'node-fetch';

/**
 * 点歌 ck 扫码登录
 *
 * QQ音乐：手机QQ扫码 → ptlogin 授权 → graph.qq.com OAuth 拿 code → QQ音乐 QQConnectLogin 换 musickey
 * 网易云音乐：网易云音乐 App 扫码 → weapi 轮询 → Set-Cookie 里的 MUSIC_U
 *
 * 每个登录对象提供：
 *   create()      → { image: base64 PNG（不带 data: 前缀）, url, state }
 *   check(state)  → { status, msg?, cookies? }
 *     status: waiting 等待扫码 | scanned 已扫码待确认 | expired 已过期 | refused 已拒绝 | done 成功 | error 出错
 */

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

/** 从 Response 里取出所有 Set-Cookie，返回 name=value 数组（兼容 node-fetch 与原生 fetch） */
export function getSetCookies(response) {
	let list = [];
	try {
		if (typeof response.headers.getSetCookie == 'function') {
			list = response.headers.getSetCookie();
		} else if (typeof response.headers.raw == 'function') {
			list = response.headers.raw()['set-cookie'] || [];
		} else {
			let value = response.headers.get('set-cookie');
			if (value) list = value.split(/,(?=\s*[^;,=\s]+=)/);
		}
	} catch (err) { }
	return list.map(c => c.split(';')[0].trim()).filter(c => c.includes('='));
}

/** name=value 数组合并为 Map，后面的覆盖前面的，空值不覆盖已有值 */
function cookiesToMap(list, map = new Map()) {
	for (let item of list) {
		let index = item.indexOf('=');
		let key = item.substring(0, index).trim();
		let value = item.substring(index + 1).trim();
		if (!key) continue;
		if (value || !map.has(key)) map.set(key, value);
	}
	return map;
}

/** ptlogin 的 hash33：ptqrtoken 用 0 作初值，g_tk / bkn 用 5381 作初值 */
export function hash33(str, hash = 0) {
	for (let i = 0; i < str.length; i++) {
		hash += (hash << 5) + str.charCodeAt(i);
	}
	return hash & 0x7fffffff;
}

// ==================== QQ音乐 ====================

const QQ_APPID = '716027609';
const QQ_DAID = '383';
const QQMUSIC_APPID = '100497308';

export const qqmusicLogin = {
	name: 'QQ音乐',
	app: '手机QQ',
	appShort: 'QQ',

	async create() {
		let url = `https://ssl.ptlogin2.qq.com/ptqrshow?appid=${QQ_APPID}&e=2&l=M&s=6&d=72&v=4&t=${Math.random()}&daid=${QQ_DAID}&pt_3rd_aid=${QQMUSIC_APPID}`;
		let response = await fetch(url, { headers: { 'User-Agent': UA, Referer: 'https://xui.ptlogin2.qq.com/' } });
		let qrsig = cookiesToMap(getSetCookies(response)).get('qrsig');
		if (!response.ok || !qrsig) throw new Error(`获取QQ登录二维码失败（HTTP ${response.status}）`);
		let image = Buffer.from(await response.arrayBuffer()).toString('base64');
		return { image, url: '', state: { qrsig } };
	},

	async check(state) {
		let params = new URLSearchParams({
			u1: 'https://graph.qq.com/oauth2.0/login_jump',
			ptqrtoken: String(hash33(state.qrsig)),
			ptredirect: '0', h: '1', t: '1', g: '1', from_ui: '1', ptlang: '2052',
			action: `0-0-${Date.now()}`,
			js_ver: '20102616', js_type: '1', pt_uistyle: '40',
			aid: QQ_APPID, daid: QQ_DAID, pt_3rd_aid: QQMUSIC_APPID, has_onekey: '1'
		});
		let response = await fetch(`https://ssl.ptlogin2.qq.com/ptqrlogin?${params}`, {
			headers: { 'User-Agent': UA, Referer: 'https://xui.ptlogin2.qq.com/', Cookie: `qrsig=${state.qrsig}` }
		});
		let text = await response.text();
		let match = /ptuiCB\((.*)\)/.exec(text);
		if (!match) return { status: 'error', msg: `二维码状态返回异常：${text.slice(0, 100)}` };
		let args = [...match[1].matchAll(/'([^']*)'/g)].map(m => m[1]);
		switch (args[0]) {
			case '66': return { status: 'waiting' };
			case '67': return { status: 'scanned' };
			case '65': return { status: 'expired' };
			case '68': return { status: 'refused' };
			case '0': break;
			default: return { status: 'error', msg: args[4] || `未知状态 ${args[0]}` };
		}

		// 扫码成功：访问 check_sig 拿 p_skey 等登录态
		let cookies = cookiesToMap(getSetCookies(response));
		let sigResponse = await fetch(args[2], { redirect: 'manual', headers: { 'User-Agent': UA, Referer: 'https://xui.ptlogin2.qq.com/' } });
		cookiesToMap(getSetCookies(sigResponse), cookies);
		let p_skey = cookies.get('p_skey');
		if (!p_skey) return { status: 'error', msg: 'QQ登录成功，但未获取到 p_skey' };

		// QQ互联授权 QQ音乐，拿到 code
		let cookieHeader = [...cookies].filter(([, v]) => v).map(([k, v]) => `${k}=${v}`).join('; ');
		let authResponse = await fetch('https://graph.qq.com/oauth2.0/authorize', {
			method: 'POST',
			redirect: 'manual',
			headers: { 'User-Agent': UA, 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookieHeader },
			body: new URLSearchParams({
				response_type: 'code',
				client_id: QQMUSIC_APPID,
				redirect_uri: 'https://y.qq.com/portal/wx_redirect.html?login_type=1&surl=https://y.qq.com/',
				scope: 'get_user_info,get_app_friends',
				state: 'state',
				switch: '',
				from_ptlogin: '1',
				src: '1',
				update_auth: '1',
				openapi: '1010_1030',
				g_tk: String(hash33(p_skey, 5381)),
				auth_time: String(Date.now()),
				ui: crypto.randomUUID()
			}).toString()
		});
		let location = authResponse.headers.get('location') || '';
		let code = /[?&]code=([^&]+)/.exec(location)?.[1];
		if (!code) return { status: 'error', msg: 'QQ互联授权失败，未获取到 code' };

		// 用 code 登录 QQ音乐
		let loginResponse = await fetch('https://u.y.qq.com/cgi-bin/musicu.fcg', {
			method: 'POST',
			headers: { 'User-Agent': UA, 'Content-Type': 'application/json', Referer: 'https://y.qq.com/' },
			body: JSON.stringify({
				comm: { g_tk: 5381, platform: 'yqq', ct: 24, cv: 0 },
				req: { module: 'QQConnectLogin.LoginServer', method: 'QQLogin', param: { code } }
			})
		});
		let res = await loginResponse.json();
		let data = res?.req?.data;
		if (res?.req?.code != 0 || !data?.musickey) {
			return { status: 'error', msg: `QQ音乐登录失败（code: ${res?.req?.code}）` };
		}
		let ck = cookiesToMap(getSetCookies(loginResponse));
		ck.set('uin', String(data.str_musicid || data.musicid || ck.get('uin') || '0'));
		ck.set('psrf_qqopenid', data.openid);
		ck.set('psrf_qqunionid', data.unionid);
		ck.set('psrf_qqrefresh_token', data.refresh_token);
		ck.set('psrf_qqaccess_token', data.access_token);
		ck.set('psrf_access_token_expiresAt', data.expired_at);
		ck.set('qqmusic_key', data.musickey);
		ck.set('qm_keyst', data.musickey);
		ck.set('psrf_musickey_createtime', data.musickeyCreateTime);
		ck.set('euin', data.encryptUin);
		ck.set('login_type', 1);
		ck.set('tmeLoginType', 2);
		return { status: 'done', cookies: ck };
	}
};

// ==================== 网易云音乐 ====================

const WEAPI_IV = Buffer.from('0102030405060708');
const WEAPI_PRESET_KEY = Buffer.from('0CoJUm6Qyw8W8jud');
const WEAPI_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgtQn2JZ34ZC28NWYpAUd98iZ37BUrX/aKzmFbt7clFSs6sXqHauqKWqdtLkF2KexO40H1YTX8z2lSgBBOAxLsvaklV8k4cBFK9snQXE9/DDaFt6Rr7iVZMldczhC0JNgTz+SHXT6CBHuX3e9SdB1Ua44oncaTWz7OBGLbCiK45wIDAQAB\n-----END PUBLIC KEY-----';
const BASE62 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

function aesEncrypt(data, key) {
	let cipher = crypto.createCipheriv('aes-128-cbc', key, WEAPI_IV);
	return Buffer.concat([cipher.update(data), cipher.final()]);
}

/** 网易云 weapi 参数加密 */
export function weapi(object) {
	let text = JSON.stringify(object);
	let secretKey = Buffer.from(Array.from(crypto.randomBytes(16), b => BASE62.charCodeAt(b % 62)));
	let params = aesEncrypt(aesEncrypt(text, WEAPI_PRESET_KEY).toString('base64'), secretKey).toString('base64');
	let reversed = Buffer.from(secretKey).reverse();
	let encSecKey = crypto.publicEncrypt(
		{ key: WEAPI_PUBLIC_KEY, padding: crypto.constants.RSA_NO_PADDING },
		Buffer.concat([Buffer.alloc(128 - reversed.length), reversed])
	).toString('hex');
	return { params, encSecKey };
}

async function netease_weapi(path, data) {
	let response = await fetch(`https://music.163.com/weapi${path}`, {
		method: 'POST',
		headers: {
			'User-Agent': UA,
			'Content-Type': 'application/x-www-form-urlencoded',
			Referer: 'https://music.163.com/',
			Cookie: 'os=pc; appver=2.10.13; __remember_me=true'
		},
		body: new URLSearchParams(weapi({ ...data, csrf_token: '' })).toString()
	});
	return { response, res: await response.json() };
}

/** 二维码图片需要本地生成（不把登录 key 发给第三方），依赖 qrcode 包 */
async function makeQRCode(text) {
	let QRCode;
	try {
		QRCode = (await import('qrcode')).default;
	} catch (err) {
		throw new Error('缺少依赖 qrcode，请在 Yunzai 根目录执行：pnpm install qrcode -w');
	}
	let buffer = await QRCode.toBuffer(text, { width: 640, margin: 1 });
	return buffer.toString('base64');
}

export const neteaseLogin = {
	name: '网易云音乐',
	app: '网易云音乐 App',
	appShort: '网易云',

	async create() {
		let { res } = await netease_weapi('/login/qrcode/unikey', { type: 1 });
		if (res?.code != 200 || !res.unikey) throw new Error(`获取网易云登录二维码失败（code: ${res?.code}）`);
		let url = `https://music.163.com/login?codekey=${res.unikey}`;
		return { image: await makeQRCode(url), url, state: { unikey: res.unikey } };
	},

	async check(state) {
		let { response, res } = await netease_weapi('/login/qrcode/client/login', { key: state.unikey, type: 1 });
		switch (Number(res?.code)) {
			case 801: return { status: 'waiting' };
			case 802: return { status: 'scanned' };
			case 800: return { status: 'expired' };
			case 803: break;
			default: return { status: 'error', msg: res?.message || `未知状态 ${res?.code}` };
		}
		let music_u = cookiesToMap(getSetCookies(response)).get('MUSIC_U');
		if (!music_u) return { status: 'error', msg: '网易云登录成功，但未获取到 MUSIC_U' };
		return { status: 'done', cookies: `MUSIC_U=${music_u};` };
	}
};
