#!/usr/bin/env bash
# AuthGate 端到端测试：启动 mocksend 与 Caddy，用 curl 执行验收用例 T01–T24。
#
# 用法：scripts/e2e.sh <caddy 二进制>
# 依赖：go、curl、jq
set -euo pipefail

CADDY=$(realpath "${1:?usage: $0 <caddy-binary>}")
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
BASE_PORT=${E2E_BASE_PORT:-18080}
AUTO=$((BASE_PORT + 1))
WEB=$((BASE_PORT + 2))
API=$((BASE_PORT + 3))
MOCK=$((BASE_PORT + 9))
ADMIN=$((BASE_PORT + 19))
DOMAIN=example.com

ADMIN_KEY=sk-68e8c800aaaaaaaaaaaaaaaa
ALICE_KEY=sk-68e8c800bbbbbbbbbbbbbbbb
BOB_KEY=sk-68e8c800cccccccccccccccc

PASS=0
FAIL=0
CADDY_PID=
MOCK_PID=

cleanup() {
	[ -n "$CADDY_PID" ] && kill "$CADDY_PID" 2>/dev/null || true
	[ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null || true
	wait 2>/dev/null || true
	if [ "$FAIL" -gt 0 ] || [ "${E2E_KEEP:-}" = 1 ]; then
		echo "工作目录保留在 $WORK"
		echo "----- caddy.log (tail) -----"
		tail -n 30 "$WORK/caddy.log" 2>/dev/null || true
	else
		rm -rf "$WORK"
	fi
}
trap cleanup EXIT

# ---------- 环境 ----------

write_caddyfile() { # $1 = 额外的全局选项
	cat >"$WORK/Caddyfile" <<EOF
{
	admin 127.0.0.1:$ADMIN
	auto_https off
	persist_config off
	authgate_file $WORK/users.txt
	authgate_sendcode_url http://127.0.0.1:$MOCK/
	authgate_sendcode_header Authorization "Bearer {env.E2E_MAIL_TOKEN}"
	authgate_admin admin root
	authgate_domain $DOMAIN
	$1
}
http://:$AUTO {
	authgate {
		bypass /healthz /public/*
	}
	respond "user={http.request.header.X-Auth-User} admin={http.request.header.X-Is-Admin} method={http.request.header.X-Auth-Method} authz=[{http.request.header.Authorization}] cookie=[{http.request.header.Cookie}]"
}
http://:$WEB {
	authgate web
	respond "user={http.request.header.X-Auth-User} method={http.request.header.X-Auth-Method}"
}
http://:$API {
	authgate api
	respond "user={http.request.header.X-Auth-User} admin={http.request.header.X-Is-Admin}"
}
EOF
}

wait_port() {
	for _ in $(seq 1 100); do
		if curl -s -o /dev/null "http://127.0.0.1:$1/"; then return 0; fi
		sleep 0.1
	done
	echo "port $1 not ready" >&2
	return 1
}

start_caddy() {
	E2E_MAIL_TOKEN=mail-secret "$CADDY" run --config "$WORK/Caddyfile" --adapter caddyfile >>"$WORK/caddy.log" 2>&1 &
	CADDY_PID=$!
	wait_port "$AUTO"
	wait_port "$WEB"
	wait_port "$API"
}

stop_caddy() {
	kill "$CADDY_PID"
	wait "$CADDY_PID" 2>/dev/null || true
	CADDY_PID=
}

reload_caddy() {
	"$CADDY" reload --config "$WORK/Caddyfile" --adapter caddyfile --address "127.0.0.1:$ADMIN" >>"$WORK/caddy.log" 2>&1
}

# ---------- 请求与断言 ----------

SRC=127.0.0.1 # 源地址；不同用例使用不同 127.0.0.x 以免互相触发 IP 限流

# call METHOD URL [curl 参数...]：设置 STATUS、BODY、HDRS
call() {
	local method=$1 url=$2
	shift 2
	local out
	out=$(curl -sS --interface "$SRC" -X "$method" -D "$WORK/hdr" -o "$WORK/body" -w '%{http_code}' "$@" "$url")
	STATUS=$out
	BODY=$(cat "$WORK/body")
	HDRS=$(tr -d '\r' <"$WORK/hdr")
}

get() { call GET "$@"; }
post() { call POST "$@"; }

CASE=
begin() {
	CASE=$1
	SRC=127.0.0.$2
}

ok() {
	PASS=$((PASS + 1))
	printf '  \033[32mPASS\033[0m %s\n' "$CASE${1:+ — $1}"
}

fail() {
	FAIL=$((FAIL + 1))
	printf '  \033[31mFAIL\033[0m %s — %s\n' "$CASE" "$1"
	printf '       status=%s body=%s\n' "$STATUS" "$(head -c 300 <<<"$BODY")"
}

json() { jq -r "$1" <<<"$BODY" 2>/dev/null || echo "<invalid json>"; }

header() { grep -i "^$1:" <<<"$HDRS" | head -n1 | cut -d' ' -f2- || true; }

# check 描述 条件...
check() {
	local desc=$1
	shift
	if "$@"; then ok "$desc"; else fail "$desc"; fi
}

is() { [ "$1" = "$2" ]; }
has() { [[ "$1" == *"$2"* ]]; }
hasnt() { [[ "$1" != *"$2"* ]]; }

latest_code() { curl -sS "http://127.0.0.1:$MOCK/last?email=$1@$DOMAIN"; }
mock_status() { curl -sS -o /dev/null -X POST "http://127.0.0.1:$MOCK/status?code=$1"; }

cookie_value() { grep -i '^set-cookie: authgate_token=' <<<"$HDRS" | head -n1 | sed -E 's/^[^=]+=([^;]*).*/\1/I'; }

# login USER：完成验证码登录，输出 token
login() {
	post "http://127.0.0.1:$AUTO/authgate/code/send" -d "user=$1" >/dev/null
	[ "$STATUS" = 200 ] || { echo "login: code/send $STATUS $BODY" >&2; return 1; }
	post "http://127.0.0.1:$AUTO/authgate/code/valid" -d "user=$1" -d "code=$(latest_code "$1")"
	[ "$STATUS" = 200 ] || { echo "login: code/valid $STATUS $BODY" >&2; return 1; }
	cookie_value
}

# ---------- 启动 ----------

echo "==> 构建 mocksend"
(cd "$ROOT" && go build -o "$WORK/mocksend" ./scripts/mocksend)
"$WORK/mocksend" -addr "127.0.0.1:$MOCK" >"$WORK/mock.log" 2>&1 &
MOCK_PID=$!

printf '# e2e users\n%s:admin\n%s:alice\n%s:bob\n' "$ADMIN_KEY" "$ALICE_KEY" "$BOB_KEY" >"$WORK/users.txt"
chmod 600 "$WORK/users.txt"
write_caddyfile ""
echo "==> 启动 Caddy ($("$CADDY" version | cut -d' ' -f1))"
start_caddy
"$CADDY" list-modules | grep -qx 'http.handlers.authgate' || { echo "authgate module missing"; exit 1; }

A="http://127.0.0.1:$AUTO"
W="http://127.0.0.1:$WEB"
P="http://127.0.0.1:$API"
BEARER_ADMIN=(-H "Authorization: Bearer $ADMIN_KEY")
BEARER_ALICE=(-H "Authorization: Bearer $ALICE_KEY")

echo "==> 验收用例"

begin T01 11
get "$A/dashboard" -H 'Accept: text/html,application/xhtml+xml'
check "浏览器未登录 → 401 + 登录页" is "$STATUS" 401
check "Content-Type 为 HTML" has "$(header Content-Type)" "text/html"
check "CSP 与 no-store" has "$(header Content-Security-Policy)$(header Cache-Control)" "frame-ancestors 'none'no-store"
check "登录页包含域名与验证码输入框" has "$BODY" "\"$DOMAIN\""
check "验证码框属性" has "$BODY" 'autocomplete="one-time-code"'

begin T02 12
get "$A/"
check "curl 无凭证 → 401 JSON" is "$STATUS:$(json .error)" "401:unauthorized"
check "WWW-Authenticate" is "$(header WWW-Authenticate)" 'Bearer realm="authgate"'

begin T08 13
post "$A/authgate/code/send" -d "user=Alice@$DOMAIN"
check "code/send 200" is "$STATUS:$(json .user):$(json .email):$(json .expires_in):$(json .resend_after)" "200:alice:alice@$DOMAIN:300:30"
check "发码服务收到 sendcode_header" grep -q 'auth="Bearer mail-secret"' "$WORK/mock.log"
CODE=$(latest_code alice)
post "$A/authgate/code/valid" -d user=alice -d "code=$CODE"
ALICE_TOKEN=$(cookie_value)
SETCK=$(header Set-Cookie)
check "code/valid 200" is "$STATUS:$(json .user):$(json .is_admin):$(json .expires_in)" "200:alice:false:3600"
check "Cookie 属性 HttpOnly/SameSite=Lax/Path=/" bash -c '[[ "$1" == *HttpOnly* && "$1" == *SameSite=Lax* && "$1" == *"Path=/"* && "$1" == *Max-Age=3600* ]]' _ "$SETCK"
get "$A/" -H 'Accept: text/html' -b "authgate_token=$ALICE_TOKEN"
check "带 Cookie 刷新后正常访问" is "$STATUS" 200
check "后端收到 web 身份" has "$BODY" "user=alice admin=false method=web"

begin T03 14
get "$P/" -b "authgate_token=$ALICE_TOKEN"
check "api 站点仅带 Cookie → 401 JSON" is "$STATUS:$(json .error)" "401:unauthorized"

begin T04 15
for site in "$A" "$W" "$P"; do
	get "$site/" "${BEARER_ALICE[@]}"
	check "Bearer 访问 $site" bash -c '[[ $1 == 200 && $2 == *user=alice* ]]' _ "$STATUS" "$BODY"
done
get "$P/" "${BEARER_ADMIN[@]}"
check "管理员 X-Is-Admin=true" has "$BODY" "user=admin admin=true"

begin T05 16
get "$W/" -H 'Authorization: Bearer sk-not-a-valid-key' -b "authgate_token=$ALICE_TOKEN" -H 'Accept: text/html'
check "无效 Bearer + 有效 Cookie → 401 JSON" is "$STATUS:$(json .error)" "401:unauthorized"

begin T06 17
get "$A/healthz" -H 'X-Auth-User: admin' -H 'X-Is-Admin: true' -H 'X-Auth-Method: api'
check "bypass 路径不认证" is "$STATUS" 200
check "伪造 header 被删除" has "$BODY" "user= admin= method= "

begin T07 18
get "$A/" "${BEARER_ALICE[@]}"
check "后端不含 Authorization" has "$BODY" "authz=[]"
get "$A/" -b "x=1; authgate_token=$ALICE_TOKEN"
check "后端不含 AuthGate Cookie" has "$BODY" "cookie=[x=1]"

begin T09 19
post "$A/authgate/code/send" -d user=alice
check "30s 内重复发码 → 429 too_frequent" is "$STATUS:$(json .error)" "429:too_frequent"
check "retry_after 与 Retry-After" bash -c '[[ $1 -ge 1 && $1 -le 30 && $2 == "$1" ]]' _ "$(json .retry_after)" "$(header Retry-After)"

begin T10 20
mock_status 500
post "$A/authgate/code/send" -d user=bob
check "发码服务 500 → 502 send_failed" is "$STATUS:$(json .error):$(json .upstream_status)" "502:send_failed:500"
mock_status 200
post "$A/authgate/code/send" -d user=bob
check "失败不进入冷却，可立即重发" is "$STATUS" 200

begin T11 21
CODE=$(latest_code bob)
WRONG=000000
[ "$CODE" = "$WRONG" ] && WRONG=111111
for i in 1 2 3 4; do
	post "$A/authgate/code/valid" -d user=bob -d "code=$WRONG"
	check "第 $i 次错误 → 400，剩余 $((5 - i))" is "$STATUS:$(json .error):$(json .remaining_attempts)" "400:invalid_code:$((5 - i))"
done
post "$A/authgate/code/valid" -d user=bob -d "code=$WRONG"
check "第 5 次 → 429 too_many_attempts" is "$STATUS:$(json .error)" "429:too_many_attempts"
post "$A/authgate/code/valid" -d user=bob -d "code=$CODE"
check "之后正确码 → 410" is "$STATUS:$(json .error)" "410:code_expired"

begin T13 22
TOKEN_ROOT=$(login root) || true
check "仅在管理员列表中的用户可登录" test -n "$TOKEN_ROOT"
post "$A/authgate/code/valid" -d user=root -d "code=$(latest_code root)"
check "同一验证码第二次 → 410" is "$STATUS:$(json .error)" "410:code_expired"

begin T14 23
get "$A/authgate/user/list" "${BEARER_ALICE[@]}"
check "普通用户 user/list → 403" is "$STATUS:$(json .error)" "403:forbidden"
get "$A/authgate/user/list" "${BEARER_ADMIN[@]}"
check "管理员 user/list" is "$STATUS:$(json '[.users[].user]|join(",")')" "200:admin,alice,bob,root"

begin T15 24
ADMIN_TOKEN=$(login admin) || true
get "$A/authgate/user/delete?user=bob" -b "authgate_token=$ADMIN_TOKEN" -H "Origin: $A"
check "管理员 Cookie + GET user/delete → 403 csrf_rejected" is "$STATUS:$(json .error)" "403:csrf_rejected"
post "$A/authgate/key/add" -b "authgate_token=$ADMIN_TOKEN" -H "Origin: http://evil.example"
check "跨域 Origin → 403" is "$STATUS:$(json .error)" "403:csrf_rejected"
post "$A/authgate/key/add" -b "authgate_token=$ADMIN_TOKEN" -H "Origin: $A"
check "同源 POST → 201" is "$STATUS" 201

begin T16 25
get "$P/authgate/user/add?user=alice" "${BEARER_ADMIN[@]}"
check "user/add 已存在 → 200 created:false" is "$STATUS:$(json .created):$(json .key)" "200:false:$ALICE_KEY"
get "$P/authgate/user/add?user=carol" "${BEARER_ADMIN[@]}"
CAROL_KEY=$(json .key)
check "user/add 新用户 → 201" is "$STATUS:$(json .created)" "201:true"
check "新 key 格式" bash -c '[[ $1 =~ ^sk-[0-9a-f]{24}$ ]]' _ "$CAROL_KEY"
check "用户文件保留注释" grep -q '^# e2e users$' "$WORK/users.txt"

begin T17 26
get "$P/authgate/user/add?user=erin" "${BEARER_ADMIN[@]}"
ERIN_KEY=$(json .key)
ERIN_TOKEN=$(login erin) || true
get "$P/authgate/me" -b "authgate_token=$ERIN_TOKEN"
check "删除前 Cookie 有效" is "$STATUS:$(json .user):$(json .method)" "200:erin:web"
get "$P/authgate/user/delete?user=erin" "${BEARER_ADMIN[@]}"
check "user/delete → 200" is "$STATUS:$(json .deleted):$(json .keys_removed)" "200:true:1"
get "$P/authgate/me" -b "authgate_token=$ERIN_TOKEN"
check "删除后 Cookie → 401" is "$STATUS" 401
get "$P/" -H "Authorization: Bearer $ERIN_KEY"
check "删除后 key → 401" is "$STATUS" 401
get "$P/authgate/user/delete?user=bob" "${BEARER_ADMIN[@]}"
check "删除 bob → 200" is "$STATUS" 200
get "$P/" -H "Authorization: Bearer $BOB_KEY"
check "bob 的 key → 401" is "$STATUS" 401

begin T18 27
get "$P/authgate/user/delete?user=root" "${BEARER_ADMIN[@]}"
check "删除配置中的管理员 → 409 user_is_admin" is "$STATUS:$(json .error)" "409:user_is_admin"
get "$P/authgate/user/delete?user=admin" "${BEARER_ADMIN[@]}"
check "删除自己 → 409 cannot_delete_self" is "$STATUS:$(json .error)" "409:cannot_delete_self"

begin T19 28
get "$P/authgate/key/delete?key=$CAROL_KEY" -H "Authorization: Bearer $CAROL_KEY"
check "普通用户删除最后一个 key → 409 last_key" is "$STATUS:$(json .error)" "409:last_key"
get "$P/authgate/key/add" -H "Authorization: Bearer $CAROL_KEY"
NEW_KEY=$(json .key)
check "key/add → 201" is "$STATUS" 201
get "$P/authgate/key/list" -H "Authorization: Bearer $NEW_KEY"
check "key/list 返回两个 key" is "$STATUS:$(json '.keys|length')" "200:2"
get "$P/authgate/key/delete?key=$CAROL_KEY" -H "Authorization: Bearer $NEW_KEY"
check "非最后一个 key 可删除" is "$STATUS:$(json .deleted)" "200:true"

begin T20 29
DAVE_KEY=sk-68e8c800dddddddddddddddd
echo "$DAVE_KEY:dave" >>"$WORK/users.txt"
ok_reload=
for _ in $(seq 1 30); do
	get "$P/" -H "Authorization: Bearer $DAVE_KEY"
	if [ "$STATUS" = 200 ]; then ok_reload=1; break; fi
	sleep 0.2
done
check "手工编辑用户文件 5 秒内生效" test -n "$ok_reload"

begin T21 30
post "$A/authgate/code/send" -d user=dave
check "reload 前发送验证码" is "$STATUS" 200
DAVE_CODE=$(latest_code dave)
write_caddyfile "authgate_code_ttl 2s"
reload_caddy
post "$A/authgate/code/send" -d user=dave
check "reload 后冷却状态保留" is "$STATUS:$(json .error)" "429:too_frequent"
post "$A/authgate/code/valid" -d user=dave -d "code=$DAVE_CODE"
check "reload 前的验证码 reload 后仍可验证" is "$STATUS" 200

begin T12 31
post "$A/authgate/code/send" -d user=carol
check "新配置 code_ttl=2s 生效" is "$STATUS:$(json .expires_in)" "200:2"
sleep 2.5
post "$A/authgate/code/valid" -d user=carol -d "code=$(latest_code carol)"
check "验证码过期 → 410" is "$STATUS:$(json .error)" "410:code_expired"

begin T22 32
stop_caddy
check "未配置 secret 时生成 <file>.secret (0600)" test "$(stat -c %a "$WORK/users.txt.secret")" = 600
start_caddy
get "$W/" -b "authgate_token=$ALICE_TOKEN"
check "重启后原 token 仍有效" is "$STATUS:$BODY" "200:user=alice method=web"

begin T23 33
PAYLOAD=$(cut -d. -f2 <<<"$ALICE_TOKEN" | tr '_-' '/+')
while [ $(( ${#PAYLOAD} % 4 )) -ne 0 ]; do PAYLOAD="$PAYLOAD="; done
FORGED_PAYLOAD=$(base64 -d <<<"$PAYLOAD" | sed 's/"u":"alice"/"u":"admin"/' | base64 -w0 | tr '/+' '_-' | tr -d '=')
FORGED="v1.$FORGED_PAYLOAD.$(cut -d. -f3 <<<"$ALICE_TOKEN")"
get "$P/authgate/me" -b "authgate_token=$FORGED"
check "篡改 token 用户名 → 401" is "$STATUS" 401
get "$W/" -b "authgate_token=$FORGED"
check "web 站点同样拒绝" is "$STATUS" 401

begin T24 34
get "$A/" -H 'Accept: application/json'
check "认证先于 respond 执行" bash -c '[[ $1 == 401 && $2 != *user=* ]]' _ "$STATUS" "$BODY"

begin "logout" 35
get "$A/authgate/logout" -H 'Accept: text/html' -b "authgate_token=$ALICE_TOKEN"
check "GET + html → 302 /" is "$STATUS:$(header Location)" "302:/"
check "清除 Cookie" has "$(header Set-Cookie)" "Max-Age=0"
post "$A/authgate/logout"
check "POST → 200 JSON" is "$STATUS:$(json .logout)" "200:true"

begin "bad-bearer-limit" 36
for i in $(seq 1 60); do get "$P/" -H "Authorization: Bearer sk-bad-$i-xxxxxxxx"; done
get "$P/" "${BEARER_ALICE[@]}"
check "无效 Bearer 超过 60 次/分钟 → 429" is "$STATUS:$(json .error)" "429:rate_limited"

begin "code-send-limit" 37
for i in $(seq 1 10); do post "$A/authgate/code/send" -d user=nobody; done
post "$A/authgate/code/send" -d user=nobody
check "code/send 超过 10 次/分钟 → 429" is "$STATUS:$(json .error)" "429:rate_limited"

echo
echo "通过 $PASS，失败 $FAIL"
[ "$FAIL" -eq 0 ]
