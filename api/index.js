import { kv } from '@vercel/kv';

// 声明使用 Vercel Edge 边缘计算环境
export const config = {
    runtime: 'edge',
};

// 建议在 Vercel 环境变量中设置 PROXY_USER 和 PROXY_PASS
const CONFIG = {
    USER: process.env.PROXY_USER || "admin",
    PASS: process.env.PROXY_PASS || "admin",
    TITLE: "私有安全网关 (Vercel 版)",
    AUTH_COOKIE: "p_token_final",
    AUTH_VALUE: "v_ultimate_safe"
};

export default async function handler(request) {
    const url = new URL(request.url);

    // --- 1. 拦截无效请求 ---
    if (url.pathname === '/favicon.ico' || url.pathname === '/robots.txt') {
        return new Response(null, { status: 204 });
    }

    const cookieHeader = request.headers.get("Cookie") || "";

    // --- 2. 登录处理接口 ---
    if (url.pathname === "/--login--" && request.method === "POST") {
        try {
            const body = await request.json();
            if (body.u === CONFIG.USER && body.p === CONFIG.PASS) {
                return new Response("OK", {
                    headers: { 
                        "Set-Cookie": `${CONFIG.AUTH_COOKIE}=${CONFIG.AUTH_VALUE}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`,
                        "Cache-Control": "no-store, no-cache, must-revalidate"
                    }
                });
            }
            return new Response("Fail", { status: 401 });
        } catch (e) {
            return new Response("Error", { status: 400 });
        }
    }

    // --- 3. 权限校验 ---
    const isAuthed = cookieHeader.includes(`${CONFIG.AUTH_COOKIE}=${CONFIG.AUTH_VALUE}`);
    if (!isAuthed) {
        return new Response(getLoginUI(), { 
            headers: { 
                "Content-Type": "text/html;charset=UTF-8",
                "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate"
            } 
        });
    }

    // --- 4. 后台书签存储 (适配 Vercel KV) ---
    if (url.pathname === "/--links--" && request.method === "POST") {
        const body = await request.text();
        try {
            await kv.set("user_links", body);
        } catch(e) { console.error("KV 写入失败", e); }
        return new Response("Saved", { headers: { "Cache-Control": "no-store" } });
    }

    // --- 5. 首页直出渲染 ---
    if (url.pathname === "/" && url.search === "") {
        let linksData = "[]";
        try { 
            // Vercel KV 默认返回解析后的对象，如果是对象则转回字符串
            const data = await kv.get("user_links");
            if (data) linksData = typeof data === 'string' ? data : JSON.stringify(data);
        } catch(e) {}
        return new Response(getIndexUI(linksData), { 
            headers: { "Content-Type": "text/html;charset=UTF-8", "Cache-Control": "no-store, no-cache, must-revalidate" } 
        });
    }

    // --- 6. 代理请求路由与智能补全 ---
    let targetStr = url.pathname.slice(1) + url.search;
    let finalUrl;

    if (targetStr.startsWith('http://') || targetStr.startsWith('https://')) {
        finalUrl = targetStr;
    } else {
        const firstSegment = targetStr.split('/')[0].split('?')[0];
        const isDomain = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d+)?$/.test(firstSegment) || 
                         /^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(firstSegment) || 
                         /^localhost(:\d+)?$/.test(firstSegment);
        
        if (isDomain) {
            finalUrl = 'https://' + targetStr;
        } else {
            const referer = request.headers.get('Referer');
            if (referer) {
                try {
                    const refUrl = new URL(referer);
                    const match = refUrl.pathname.match(/^\/(https?:\/\/[^\/]+)/);
                    if (match) {
                        const correctAbsPath = match[1] + '/' + targetStr;
                        return Response.redirect(`https://${url.host}/${correctAbsPath}`, 302);
                    }
                } catch(e) {}
            }
            return new Response("⚠️ 代理请求解析失败：缺少目标域名", { status: 400 });
        }
    }
    
    try {
        const targetUrl = new URL(finalUrl);
        const cleanHeaders = new Headers();
        
        const whitelist = ['user-agent', 'accept', 'accept-language', 'content-type', 'cookie', 'range', 'dnt', 'upgrade-insecure-requests'];
        for (let [k, v] of request.headers.entries()) {
            let key = k.toLowerCase();
            // 放行白名单和所有的 Sec- 头，拦截 Vercel 注入的特殊头
            if ((whitelist.includes(key) || key.startsWith('sec-')) && !key.startsWith('x-vercel-')) {
                if (key === 'cookie' && v) {
                    const filtered = v.split(';').filter(c => !c.trim().startsWith(CONFIG.AUTH_COOKIE)).join(';');
                    if (filtered) cleanHeaders.set(k, filtered);
                } else {
                    cleanHeaders.set(k, v);
                }
            }
        }

        cleanHeaders.set("Origin", targetUrl.origin);
        cleanHeaders.set("Referer", targetUrl.href);
        cleanHeaders.set("Sec-Fetch-Site", "same-origin"); 
        
        // Vercel 环境下读取真实 IP
        const clientIP = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip');
        if (clientIP) {
            cleanHeaders.set('X-Forwarded-For', clientIP);
            cleanHeaders.set('X-Real-IP', clientIP);
        }

        const response = await fetch(targetUrl.href, {
            method: request.method,
            headers: cleanHeaders,
            body: (request.method !== "GET" && request.method !== "HEAD") ? request.body : null,
            redirect: "manual"
        });

        // 重定向跟随
        if ([301, 302, 303, 307, 308].includes(response.status)) {
            const loc = response.headers.get("Location");
            if (loc) {
                const absLoc = new URL(loc, targetUrl.href).href;
                return Response.redirect(`https://${url.host}/${absLoc}`, response.status);
            }
        }

        let resHeaders = new Headers(response.headers);
        const contentType = response.headers.get("content-type") || "";
        
        resHeaders.set("Access-Control-Allow-Origin", "*");
        resHeaders.delete("content-security-policy");
        resHeaders.delete("content-security-policy-report-only");
        resHeaders.delete("x-frame-options");
        resHeaders.delete("cross-origin-embedder-policy"); 
        resHeaders.delete("cross-origin-opener-policy");

        if (typeof response.headers.getSetCookie === 'function') {
            resHeaders.delete("set-cookie");
            for (const c of response.headers.getSetCookie()) {
                let rewritten = c.replace(/Domain=[^;]+/ig, '').replace(/SameSite=Strict/ig, 'SameSite=Lax');
                resHeaders.append("set-cookie", rewritten);
            }
        }

        if (request.method === "GET" && contentType.match(/(image|css|javascript|font)/i)) {
            resHeaders.set("Cache-Control", "public, max-age=2592000");
        }

        // Vercel 环境下使用正则替换 HTMLRewriter 的逻辑
        if (contentType.includes("text/html")) {
            let bodyText = await response.text();
            const proxyBase = `https://${url.host}/`;
            
            // 注入 AJAX / Fetch 劫持脚本
            const scriptToInject = `
            <script>
            (function() {
                const proxyBase = window.location.origin + "/";
                const targetOrigin = "${targetUrl.origin}";
                const wrap = (u) => {
                    if (!u || typeof u !== 'string' || u.startsWith('data:') || u.startsWith('javascript:') || u.startsWith('#')) return u;
                    try {
                        const abs = new URL(u, targetOrigin).href;
                        if (!abs.startsWith(proxyBase)) return proxyBase + abs;
                    } catch(e) {}
                    return u;
                };
                window.fetch = (i, init) => window.fetch(wrap(i), init);
                const _open = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function() {
                    arguments[1] = wrap(arguments[1]);
                    return _open.apply(this, arguments);
                };
            })();
            </script>`;

            // 暴力注入 head
            bodyText = bodyText.replace(/<head[^>]*>/i, `$&${scriptToInject}`);

            // 正则改写 a, form, link, img, script 标签
            bodyText = bodyText.replace(/<(a|form|link|img|script)\s+([^>]*?)(href|action|src)\s*=\s*(['"])(.*?)\4([^>]*?)>/gi, (match, tag, before, attr, quote, val, after) => {
                if (val && !val.startsWith("data:") && !val.startsWith("javascript:") && !val.startsWith("#")) {
                    try {
                        const newUrl = proxyBase + new URL(val, targetUrl.href).href;
                        // 组装新标签并移除安全校验
                        let newTag = `<${tag} ${before}${attr}=${quote}${newUrl}${quote}${after}>`;
                        newTag = newTag.replace(/integrity\s*=\s*['"][^'"]*['"]/gi, '');
                        newTag = newTag.replace(/nonce\s*=\s*['"][^'"]*['"]/gi, '');
                        return newTag;
                    } catch (e) {}
                }
                return match;
            });

            return new Response(bodyText, { status: response.status, headers: resHeaders });
        }

        return new Response(response.body, { status: response.status, headers: resHeaders });

    } catch (e) {
        return new Response("⚠️ 代理请求失败: " + e.message, { status: 500 });
    }
}

// ================= UI 组件保持原样 =================
function getIndexUI(linksData) {
    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <title>私有安全网关</title>
    <style>
        :root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --accent: #38bdf8; --danger: #ef4444; }
        body { background: var(--bg); color: var(--text); font-family: system-ui, sans-serif; display: flex; flex-direction: column; align-items: center; min-height: 100vh; margin: 0; padding-top: 5vh;}
        .container { width: 90%; max-width: 650px; text-align: center;}
        .search-card { background: var(--card); padding: 2.5rem; border-radius: 1.5rem; box-shadow: 0 20px 50px rgba(0,0,0,0.3); margin-bottom: 2rem; }
        h1 { font-size: 1.8rem; margin-bottom: 1.5rem; color: var(--accent); }
        .input-box { width: 100%; padding: 14px 25px; border-radius: 50px; border: 1px solid #334155; background: #0f172a; color: #fff; font-size: 1rem; outline: none; box-sizing: border-box; margin-bottom: 1.5rem;}
        .btn-grid { display: flex; justify-content: center;}
        button { width: 100%; max-width: 250px; padding: 14px 10px; border-radius: 30px; border: none; cursor: pointer; font-weight: 700; font-size: 1rem; transition: 0.2s; background: var(--accent); color: #0f172a;}
        button:hover { opacity: 0.9; transform: translateY(-2px); box-shadow: 0 5px 15px rgba(56,189,248,0.3);}
        .nav-section { width: 100%; text-align: left;}
        .nav-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; padding: 0 10px; border-left: 4px solid var(--accent); }
        .nav-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 12px; }
        .nav-item { position: relative; background: var(--card); padding: 15px; border-radius: 12px; text-align: center; cursor: pointer; border: 1px solid transparent; transition: 0.3s;}
        .nav-item:hover { border-color: var(--accent); background: #2d3a4f;}
        .nav-item .delete-btn { position: absolute; top: 5px; right: 5px; color: var(--danger); font-size: 14px; width: 22px; height: 22px; display: none; background: rgba(0,0,0,0.5); border-radius: 50%; line-height: 20px;}
        .nav-item:hover .delete-btn { display: block;}
        .footer { font-size: 0.75rem; color: #64748b; margin-top: 4rem; text-align: center;}
        #status { font-size: 0.8rem; color: var(--accent); margin-left: 10px; display: none;}
    </style>
</head>
<body>
    <div class="container">
        <div class="search-card">
            <h1>🌐 私有安全网关</h1>
            <input type="text" id="q" class="input-box" placeholder="输入目标 URL 或域名..." autofocus>
            <div class="btn-grid">
                <button onclick="go()">🚀 直 接 访 问</button>
            </div>
        </div>
        <div class="nav-section">
            <div class="nav-header">
                <h3 style="margin:0">🔖 个人书签中心 <span id="status">同步成功</span></h3>
                <span style="font-size:0.8rem; color:var(--accent); cursor:pointer" onclick="addLink()">+ 永久添加</span>
            </div>
            <div id="navGrid" class="nav-grid"></div>
        </div>
    </div>
    <div class="footer">Vercel KV 云端同步已激活 • 边缘节点防阻断重构版</div>
    <script>
        function go() {
            let v = document.getElementById('q').value.trim();
            if(!v) return;
            if(v.toLowerCase() === 'google') v = 'google.com';
            if(v.toLowerCase() === 'github') v = 'github.com';
            let u = v.startsWith('http') ? v : 'https://' + v;
            location.href = "/" + u;
        }
        document.getElementById('q').onkeypress=e=>{ if(e.key==='Enter') go() };

        let links = ${linksData};
        async function saveLinks() {
            showStatus('正在保存云端...');
            try {
                await fetch('/--links--', { method: 'POST', body: JSON.stringify(links) });
                showStatus('云端已更新', 2000);
            } catch(e) { showStatus('保存失败', 3000); }
        }

        function renderLinks() {
            const grid = document.getElementById('navGrid');
            grid.innerHTML = links.length ? '' : '<div style="grid-column:1/-1;text-align:center;color:#64748b;padding:20px;">点击“+ 永久添加”开始建立云端书签</div>';
            links.forEach((item, i) => {
                const div = document.createElement('div');
                div.className = 'nav-item';
                div.onclick = () => location.href = "/" + item.url;
                div.innerHTML = \`<div>\${item.name}</div><div class="delete-btn" onclick="event.stopPropagation(); deleteLink(\${i})">×</div>\`;
                grid.appendChild(div);
            });
        }

        function addLink() {
            const name = prompt("网站名称:");
            let url = prompt("网址 (如 google.com):");
            if(name && url) {
                if(!url.startsWith('http')) url = 'https://' + url;
                links.push({ name, url });
                renderLinks();
                saveLinks();
            }
        }

        function deleteLink(i) {
            if(confirm('删除此云端书签?')) {
                links.splice(i, 1);
                renderLinks();
                saveLinks();
            }
        }

        function showStatus(msg, ms) {
            const s = document.getElementById('status');
            s.innerText = msg; s.style.display = 'inline';
            if(ms) setTimeout(() => s.style.display = 'none', ms);
        }
        
        renderLinks();
    </script>
</body>
</html>`;
}

function getLoginUI() {
    return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录</title>
    <style>
        body{background:#0f172a;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;margin:0} 
        .card{background:#1e293b;padding:2.5rem;border-radius:1.5rem;text-align:center;width:90%;max-width:320px;box-sizing:border-box;box-shadow:0 10px 30px rgba(0,0,0,0.5)} 
        input{width:100%;padding:14px;margin:10px 0;background:#0f172a;border:1px solid #334155;color:#fff;border-radius:30px;text-align:center;box-sizing:border-box;outline:none;font-size:16px} 
        button{width:100%;padding:14px;margin-top:15px;background:#38bdf8;border:none;border-radius:30px;cursor:pointer;font-weight:700;color:#0f172a;font-size:16px;transition:0.2s} 
        button:hover{opacity:0.9;transform:translateY(-1px)}
    </style>
</head>
<body>
    <div class="card">
        <h2 style="margin-top:0;margin-bottom:20px;color:#38bdf8">🔒 身份验证</h2>
        <input id="u" placeholder="请输入用户名" autocomplete="off">
        <input id="p" type="password" placeholder="请输入密码" onkeypress="if(event.key==='Enter'){ l(); return false; }">
        <button id="btn" onclick="l()">进 入 网 关</button>
    </div>
    <script>
        async function l(){
            const u = document.getElementById('u').value.trim();
            const p = document.getElementById('p').value.trim();
            const btn = document.getElementById('btn');
            
            if(!u || !p) return alert('⚠️ 用户名和密码不能为空');
            
            btn.innerText = '正在验证...';
            try {
                const r = await fetch('/--login--', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({u, p})
                });
                
                if (r.ok) {
                    btn.innerText = '验证成功！';
                    btn.style.background = '#4ade80';
                    setTimeout(() => location.href = '/', 300);
                } else {
                    alert('❌ 账号或密码错误，请重试');
                    btn.innerText = '进 入 网 关';
                }
            } catch (e) {
                alert('⚠️ 无法连接到服务器，请检查网络');
                btn.innerText = '进 入 网 关';
            }
        }
    </script>
</body>
</html>`;
}