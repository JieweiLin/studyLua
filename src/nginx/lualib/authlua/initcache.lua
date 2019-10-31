local shared_data  = ngx.shared.shared_data;
shared_data :set("hasinit", false); --让内存重新初始化
ngx.print("ok");