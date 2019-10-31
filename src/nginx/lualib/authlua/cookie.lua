 local token = ngx.md5("love"..ngx.localtime());
 
 ngx.header["Set-Cookie"] = {"token="..token};
 