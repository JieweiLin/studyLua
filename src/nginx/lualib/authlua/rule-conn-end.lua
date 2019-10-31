local ctx = ngx.ctx
local lim = ctx.limit_conn
local limit_conn = require "resty.limit.conn"
local shared_data  = ngx.shared.shared_data;
local function get_client_ip()
    local headers=ngx.req.get_headers()
    local ip=headers["X-REAL-IP"] or headers["X_FORWARDED_FOR"] or ngx.var.remote_addr or "0.0.0.0"
    return ip
end
local ip = get_client_ip();



if lim then
        -- if you are using an upstream module in the content phase,
        -- then you probably want to use $upstream_response_time
        -- instead of ($request_time - ctx.limit_conn_delay) below.
        local latency = tonumber(ngx.var.request_time) - ctx.limit_conn_delay
        local key = ctx.limit_conn_key
        assert(key)
        local conn, err = lim:leaving(key, latency)
        if not conn then
            ngx.log(ngx.ERR,
                    "failed to record the connection leaving ",
                    "request: ", err)
            return
         else
         
     
            
        end

else

     local ip_conn_num = shared_data:get("ip_conn_num");
	if not ip_conn_num then
           
            return
        
        end

        
      local clim, err = limit_conn.new("limit_conn_store", shared_data:get("ip_conn_num"), 5, 0.5)
      local latency = tonumber(ngx.var.upstream_response_time)
       local key = ip 
       local conn, err = clim:leaving(key, latency)
        if not conn then
           
            return
        
        else
            
          
            
        end
        
end