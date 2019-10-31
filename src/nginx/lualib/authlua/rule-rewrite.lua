-- ngx.log(ngx.INFO,"进入跳转逻辑");

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
if  args then
        if args["reqcode"] then
          reqcode = args["reqcode"];
    ngx.var.reqcode = reqcode;
        end
end

-- ngx.log(ngx.INFO,"当前请求协议",reqcode);

if reqcode == 0 or reqcode == nil then --未得到协议号
 ngx.var.reqcode = 0;
end



-- ngx.log(ngx.INFO,"我要强制跳转...args", json.encode(args));

-- 规则对1094协议等协议进行分流到红点服务
 if reqcode == '1094' or reqcode == '1026' or reqcode == '1027' or reqcode == '1169' or reqcode == '1207' then
   -- ngx.log(ngx.INFO,"我要强制跳转...args", json.encode(args));
   if "GET" == request_method then
       return ngx.exec('/RedDot/message',args);
   elseif "POST" == request_method then
       return ngx.exec('/RedDot/message');
   end
 end