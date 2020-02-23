# my_lua_waf

## 部署
```shell
sudo mkdir -p /usr/local/openresty/nginx/waf
cd /usr/local/openresty/nginx/waf
sudo git clone https://github.com/kuberxy/my_lua_waf.git .

sudo mkdir -p /usr/local/openresty/nginx/waf/logs
sudo chmod 777 /usr/local/openresty/nginx/waf/logs
```

## 配置
### nginx
```shell
sudo vim  /usr/local/openresty/nginx/conf/nginx.conf
```
配置如下：
```nginx
worker_processes  1;
error_log logs/error.log;

events {
    worker_connections 1024;
}

http {
    lua_package_path '/usr/local/openresty/nginx/waf/?.lua;;';
    lua_shared_dict cc_counter_store 10m;
    init_by_lua_file  waf/init.lua;
    access_by_lua_file waf/waf.lua;

    server {
        listen    80;

        location / {
            content_by_lua_block {
                ngx.say('hello, world')
            }
        }

    }
}
```

## 测试
```shell
curl 127.0.0.1
curl 192.168.1.250/123/
curl 192.168.1.250/.svn/
curl 192.168.1.250 -A "sqlmap"
curl 192.168.1.250 -b "a=select * from"
curl "192.168.1.250/1.thml?a=select * from"
curl 192.168.1.250 -d "a=select * from"
```