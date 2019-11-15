-- reids连接配置
local ip = "";  --连接IP
local pwd = "";    --密码
local port = 6379;
local timeout = 1;    --超时时间，单位秒


local session_ip = "";
local session_pwd = "";
local session_port = 6379;



local _M = {_VERSION = "0.1"}

function _M.getIp()
  return ip
end


function _M.getPwd()
  return pwd
end

function _M.getPort()
  return port
end

function _M.getTimeOut()
  return timeout
end


function _M.getSessionIp()
  return session_ip
end


function _M.getSessionPwd()
  return session_pwd
end

function _M.getSessionPort()
  return session_port
end



return _M