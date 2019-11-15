local limit_req = require "resty.limit.req"
local limit_conn = require "resty.limit.conn"
local rule = require("authlua.rule")
local shared_data = ngx.shared.shared_data;
local rule_status = shared_data:get("rule_status");

local function get_client_ip()
    local headers = ngx.req.get_headers()
    local ip = headers["X-REAL-IP"] or headers["X_FORWARDED_FOR"] or ngx.var.remote_addr or "0.0.0.0"
    return ip
end
local function get_client_uri()
    local headers = ngx.req.get_headers()
    local url = headers["X-Forwarded-For-REWRITE-URL"] or ngx.ctx.url or headers["X-Forwarded-For-URL"] or ngx.var.document_uri
    return url
end

local function close_db(db)
    if not db then
        return
    end

    db:close()

end

local mysql = require("resty.mysql")
local cjson = require "cjson"
local jwt = require "resty.jwt"
local redisConfig = require "authlua.redis_config"
local jwtConfig = require "authlua.jwt_config"
local redis = require("authlua.redis_iresty")
local jwt_shared_data = ngx.shared.invalid_token_store;
local opts = { timeout = redisConfig.getTimeOut(), ip = redisConfig.getSessionIp(), port = redisConfig.getSessionPort(), pwd = redisConfig.getSessionPwd() };
local red = redis:new(opts);
local receive_headers = ngx.req.get_headers();
local jwt_token = receive_headers["Authorization"];
if jwt_token and string.len(jwt_token) > 20 then
    local jwt_obj = jwt:verify(jwtConfig.getSecret(), string.sub(jwt_token, 8))
    local payload = jwt_obj.payload;
    -- 验证token、如果token过期，verified也是false
    if not jwt_obj["verified"] then
        ngx.status = ngx.HTTP_UNAUTHORIZED

        -- 验证有效期
        local t = os.time();

        local exp = payload.exp;

        --过期
        if t > exp then
            ngx.status = ngx.HTTP_UNAUTHORIZED

            if payload.tokenType == 1 then
                ngx.log(ngx.ERR, "准备返回10005.jwt_token：", jwt_token, "url:", get_client_uri());
                ngx.print("{\"code\":10005,\"message\":\"access token过期\",\"body\":{}}");
            else
                ngx.print("{\"code\":10006,\"message\":\"您的登录已过期，请重新登录\",\"body\":{}}");
            end

            return ngx.exit(ngx.status);
        end

        ngx.print("{\"code\":10006,\"message\":\"登录信息无效，请重新登录\",\"body\":{}}");
        return ngx.exit(ngx.status);
    end

    -- 验证是否被踢出
    local id = payload.id;
    -- ngx.log(ngx.ERR,"有到这里"..redisConfig.getSessionIp())
    local iskill = jwt_shared_data:get(id);
    if iskill then

        local db, err = mysql:new()
        if not db then
            ngx.log(ngx.ERR, "连接mysql失败 : ", err)

        end

        db:set_timeout(2000)

        local props = {
            host = jwtConfig.getHost(),
            port = jwtConfig.getPort(),
            database = jwtConfig.getDatabase(),
            user = jwtConfig.getUser(),
            password = jwtConfig.getPassword()
        }

        local res, err, errno, sqlstate = db:connect(props)

        if not res then
            ngx.log(ngx.ERR, "创建mysql连接失败,", "connect to mysql error : ", err, " , errno : ", errno, " , sqlstate : ", sqlstate)
            close_db(db)
        end

        local select_sql = "select kill_msg from t_kick_token where token_id = '" .. id .. "'"
        res, err, errno, sqlstate = db:query(select_sql)
        if not res then
            ngx.log(ngx.ERR, "select error : ", err, " , errno : ", errno, " , sqlstate : ", sqlstate)
            close_db(db)

        else

            for i, row in ipairs(res) do

                ngx.print("{\"code\":10007,\"message\":\"" .. row.kill_msg .. "\",\"body\":{}}");
                close_db(db)
                return ngx.exit(ngx.HTTP_OK);

            end

        end

        close_db(db)
    end

    ngx.var.verified = 1
    ngx.var.payload = cjson.encode(payload)

    -- 设置cookie
    local sessionId = tostring(ngx.var.cookie_JSESSIONID);
    if not sessionId or sessionId == 'null' then
        local cookies = ngx.heaer["Set-Cookie"] or {}
        if type(cookies) == "string" then
            cookies = {cookies}
        end
        table.insert(cookies, "JSESSIONID="..payload.sessionId)
        ngx.header["Set-Cookie"] = cookies
    end

end


-- 获取协议号。用于日志打印
local request_method = ngx.var.request_method;
local receive_headers = ngx.req.get_headers();
local args = nil;
if "GET" == request_method then
    args = ngx.req.get_uri_args()
elseif "POST" == request_method then
    ngx.req.read_body();
    args = ngx.req.get_post_args()
end
local json = require(require("ffi").os == "Windows" and "dkjson" or "cjson.safe")
local reqcode = 0;
local body = nil;
-- 防止无参数报错
if args then
    if args["reqcode"] then
        reqcode = args["reqcode"];
        ngx.var.reqcode = reqcode;
    end
end

ngx.log(ngx.INFO, "当前请求协议", reqcode);

if reqcode == 0 or reqcode == nil then
    --未得到协议号
    ngx.var.reqcode = 0;
end

if rule_status ~= nil then
    -- 不为空，则要判断是否手动关闭了。默认是开启的.
    if 0 == rule_status then
        ngx.log(ngx.INFO, "降级限流规则被关闭了....");
        return ;
    end
end

ngx.log(ngx.INFO, "进入限流逻辑咯....");
local ip = get_client_ip();
ngx.log(ngx.INFO, "用户IP:" .. ip);
local url = get_client_uri();
ngx.log(ngx.INFO, "用户URL:" .. url);

-- 规则0：判断IP白名单
local res = shared_data:get("ipwhite" .. ip);
if res then
    ngx.log(ngx.INFO, "IP在白名单，不进行规则判断" .. ip)
    return ;
end

-- 规则1：判断IP黑名单
local res = shared_data:get("ipblack" .. ip);
if res then
    ngx.log(ngx.INFO, "IP在黑名单，被拒绝" .. ip)
    return ngx.exit(ngx.HTTP_FORBIDDEN);
end

-- 规则2：IP连接数是否超出上限
-- limit_conn.new("limit_conn_store", 200, 100, 0.5) 表示 200内正常，可突发到300.超过300拒绝。100是桶    
local clim, err = limit_conn.new("limit_conn_store", shared_data:get("ip_conn_num"), 5, 0.5)
if not clim then
    ngx.log(ngx.ERR,
            "failed to instantiate a resty.limit.conn object: ", err)
    return ngx.exit(500)
end

-- the following call must be per-request.
-- here we use the remote (IP) address as the limiting key
local key = ip
local delay, err = clim:incoming(key, true)
if not delay then
    if err == "rejected" then
        ngx.log(ngx.INFO, "被IP并发连接数限制了..." .. ip);
        ngx.log(ngx.WARN, "被IP并发连接数限制了..." .. ip);
        ngx.log(ngx.CRIT, "被IP并发连接数限制了...ip=" .. ip);
        ngx.print("{\"returncode\":\"503\",\"message\":\"系统繁忙，请稍候再试！(503,1)\",\"body\":\"\"}");
        return ngx.exit(ngx.HTTP_OK);
    end
    ngx.log(ngx.ERR, "failed to limit req: ", err)
    return ngx.exit(500)
end

if clim:is_committed() then
    local ctx = ngx.ctx
    ctx.limit_conn = clim
    ctx.limit_conn_key = key
    ctx.limit_conn_delay = delay
end

-- the 2nd return value holds the current concurrency level
-- for the specified key.
local conn = err

if delay >= 0.001 then
    -- the request exceeding the 200 connections ratio but below
    -- 300 connections, so
    -- we intentionally delay it here a bit to conform to the
    -- 200 connection limit.
    -- ngx.log(ngx.WARN, "delaying")
    ngx.sleep(delay)
end

-- 规则3：IP请求频率是否超出上限

local rate = shared_data:get("ip_req_rate") --固定平均速率
local burst = 10 --桶容量
local error_status = 503
local nodelay = true --是否需要不延迟处理， 不延迟为令牌算法。

local lim, err = limit_req.new("limit_req_store", rate, burst)
if not lim then
    --没定义共享字典
    ngx.log(ngx.ERR,
            "failed to instantiate a resty.limit.req object: ", err)
    return ngx.exit(500)
end

local key = ip --IP维度限流
--请求流入，如果你的请求需要被延迟则返回delay>0
local delay, err = lim:incoming(key, true)

if not delay then
    if err == "rejected" then
        ngx.log(ngx.INFO, "被IP请求频率限制了..." .. ip);
        ngx.log(ngx.WARN, "被IP请求频率限制了..." .. ip);
        ngx.log(ngx.CRIT, "被IP请求频率限制了...ip=" .. ip);
        ngx.print("{\"returncode\":\"503\",\"message\":\"您的请求过于频繁，请稍候再试！(503,2)\",\"body\":\"\"}");
        return ngx.exit(ngx.HTTP_OK);
    end
    ngx.log(ngx.ERR, "failed to limit req: ", err)
    return ngx.exit(500)
end

if delay > 0 then
    --根据需要决定延迟或者不延迟处理
    if nodelay then
        --直接突发处理
    else
        ngx.sleep(delay) --延迟处理
    end
end

-- 规则4：判断URL是否降级
local res = shared_data:get("offline_req_alertmsg_" .. url);
if res then
    ngx.log(ngx.INFO, "地址", url, "被降级,返回内容是:", res);

    -- 判断是否重定向
    if string.find(res, "redirect") == 1 then

        return ngx.redirect('/downgrade?msg=' .. string.sub(res, 10, -1), 302);
    end

    ngx.print(res);
    return ngx.exit(ngx.HTTP_OK);
end

-- 规则5：判断URL是否限流
local url_req_rate = shared_data:get("limit_req_rate_" .. url);
if url_req_rate then
    local limit_req_alertmsg = shared_data:get("limit_req_alertmsg_" .. url);
    local lim, err = limit_req.new("limit_req_store", url_req_rate, burst)
    if not lim then
        --没定义共享字典
        ngx.log(ngx.ERR,
                "failed to instantiate a resty.limit.req object: ", err)
        return ngx.exit(500)
    end

    local key = url --URL维度限流
    --请求流入，如果你的请求需要被延迟则返回delay>0
    local delay, err = lim:incoming(key, true)

    if not delay then
        if err == "rejected" then
            --上限处理

            ngx.log(ngx.CRIT, limit_req_alertmsg .. " url=" .. url);

            -- 判断是否重定向
            if string.find(limit_req_alertmsg, "redirect") == 1 then
                return ngx.redirect('/downgrade?msg=' .. string.sub(limit_req_alertmsg, 10, -1), 302);
            end

            ngx.print(limit_req_alertmsg);

            return ngx.exit(ngx.HTTP_OK);
        end
        ngx.log(ngx.ERR, "failed to limit req: ", err)
        return ngx.exit(500)
    end

    if delay > 0 then
        --根据需要决定延迟或者不延迟处理
        if nodelay then
            --直接突发处理
        else
            ngx.sleep(delay) --延迟处理
        end
    end

end

-- 协议规则开始
if reqcode == 0 or reqcode == nil then
    --未得到协议号
    ngx.var.reqcode = 0;
    return ;
end

-- 规则6: 判断协议是否降级
local res = shared_data:get("offline_req_alertmsg_" .. reqcode);
if res then
    ngx.log(ngx.INFO, "协议", reqcode, "被降级,返回内容是:", res);
    ngx.print(res);
    return ngx.exit(ngx.HTTP_OK);
end

-- 规则7：判断协议是否限流
local reqcode_req_rate = shared_data:get("limit_req_rate_" .. reqcode);
if reqcode_req_rate then
    local limit_req_alertmsg = shared_data:get("limit_req_alertmsg_" .. reqcode);
    local lim, err = limit_req.new("limit_req_store", reqcode_req_rate, burst)
    if not lim then
        --没定义共享字典
        ngx.log(ngx.ERR,
                "failed to instantiate a resty.limit.req object: ", err)
        return ngx.exit(500)
    end

    local key = reqcode --reqcode维度限流
    --请求流入，如果你的请求需要被延迟则返回delay>0
    local delay, err = lim:incoming(key, true)

    if not delay then
        if err == "rejected" then
            --上限处理
            ngx.print(limit_req_alertmsg);
            ngx.log(ngx.CRIT, limit_req_alertmsg .. " reqcode=" .. reqcode);
            return ngx.exit(ngx.HTTP_OK);
        end
        ngx.log(ngx.ERR, "failed to limit req: ", err)
        return ngx.exit(500)
    end

    if delay > 0 then
        --根据需要决定延迟或者不延迟处理
        if nodelay then
            --直接突发处理
        else
            ngx.sleep(delay) --延迟处理
        end
    end

end

function hashConvert(v)
    local ch = 0
    local val = 0

    if (v) then
        for i = 1, #v do
            ch = v:byte(i)
            if (ch >= 65 and ch <= 90) then
                ch = ch + 32
            end
            val = val * 0.7 + ch  --0.7是加权
        end
    end
    val = val .. ''
    val = val:gsub("+", "")
    val = val:gsub("%.", "")

    return string.format('%s', val)
end

-- 规则8:判断URL用户是否针对用户降级
local sessionId = tostring(ngx.var.cookie_JSESSIONID);

-- ngx.log(ngx.INFO,"进入判断是否针对用户降级",sessionId);

local failUserNum = shared_data:get("failUserNum");
if sessionId and sessionId ~= 'null' and failUserNum and failUserNum > 0 then
    local offline_url_user_msg = shared_data:get("offline_url_msg_" .. url);
    -- ngx.log(ngx.INFO,"本次session的code是:",hashConvert(sessionId));
    if offline_url_user_msg and hashConvert(sessionId) % failUserNum == 0 then
        --  ngx.log(ngx.INFO,"sessionId:",sessionId,"url:",url,"被降级,返回内容是:", res);
        ngx.print(offline_url_user_msg);
        return ngx.exit(ngx.HTTP_OK);
    end

end