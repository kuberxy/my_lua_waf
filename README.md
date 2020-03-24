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
### openresty
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
    lua_shared_dict limit_rate_store 100m;
    lua_shared_dict my_locks 100k;
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



### waf

配置文件的路径为/usr/local/openresty/nginx/waf/config.lua，它其实是一个lua文件，用于定义一些全局的配置项（变量）。配置项的含义如下：

| 配置项                      | 数据类型 | 含义                                                         |
| --------------------------- | -------- | ------------------------------------------------------------ |
| enable_waf                  | string   | 是否启用WAF。on为启动，off为关闭，默认为on。                 |
| rule_dir                    | string   | 规则文件的路径。默认为“/usr/local/openresty/nginx/waf/rules”。 |
| dry_mode                    | string   | 是否开启演习模式，即不拦截请求。on为启动，off为关闭，默认为on。 |
| enable_attack_log           | string   | 是否记录攻击日志。on为启用，off为关闭，默认为on。            |
| log_dir                     | string   | 攻击日志的路径。默认为“/usr/local/openresty/nginx/waf/logs”  |
| enable_white_ip_filter      | string   | 是否启用IP白名单。on为启动，off为关闭，默认为on。            |
| enable_white_url_filter     | string   | 是否启用url白名单。on为启动，off为关闭，默认为on。           |
| enable_black_ip_filter      | string   | 是否启用IP黑名单。on为启动，off为关闭，默认为on。            |
| enable_black_url_filter     | string   | 是否启用url黑名单。on为启动，off为关闭，默认为on。           |
| enable_user_agent_filter    | string   | 是否启用user_agent黑名单。on为启动，off为关闭，默认为on。    |
| enable_cookie_attack_filter | string   | 是否启用cookie黑名单。on为启动，off为关闭，默认为on。        |
| enable_get_args_filter      | string   | 是否启用get参数黑名单。on为启动，off为关闭，默认为on。       |
| enable_post_args_filter     | string   | 是否启用post参数黑名单。on为启动，off为关闭，默认为on。      |
| black_file_suffix           | string   | 恶意文件的后缀。默认为{"php","jsp"}。                        |
| enable_req_rate_limiter     | string   | 是否启用速率控制。on为启动，off为关闭，默认为on。            |




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