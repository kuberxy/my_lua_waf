require 'config'

local tools = require('tools')
local rulefinder = ngx.re.find

local _M = {}

-- filter client ip whether in ip white list
function _M.white_ip_filter()
    if enable_waf == 'on' and enable_white_ip_filter == 'on' then
        local client_ip = tools.get_client_ip()
        local ip_white_list = tools.get_rule('white_ip.rule')  -- return a table

        if next(ip_white_list) then
            for _,rule_ip in ipairs(ip_white_list) do
                if client_ip == rule_ip then
                    if enable_attack_log == 'on' then
                        tools.log(client_ip,'white_ip',ngx.var.request_uri,client_ip)
                    end
                    return true
                end
            end
        end
    end
end

-- filter client url whether in url white list
function _M.white_url_filter()
    if enable_waf == 'on' and enable_white_url_filter == 'on' then
        local client_request_uri = ngx.var.request_uri
        local url_white_list  = tools.get_rule('white_url.rule')
        if next(url_white_list) then
            for _,rule_uri in ipairs(url_white_list) do
                if rulefinder(client_request_uri,rule_uri,'isjo') then
                    if enable_attack_log == 'on' then
                        tools.log(tools.get_client_ip(),'white_url',ngx.var.request_uri,client_request_uri)
                    end
                    return true
                end
            end
        end
    end
end

-- filter client ip whether in ip black list
function _M.black_ip_filter()
    if enable_waf == 'on' and enable_black_ip_filter == 'on' then
        local client_ip = tools.get_client_ip()
        local ip_black_list = tools.get_rule('black_ip.rule')

        if next(ip_black_list) then
            for _,rule_ip in ipairs(ip_black_list) do
                if client_ip == rule_ip then
                    if enable_attack_log == 'on' then
                        tools.log(client_ip,'black_ip',ngx.var.request_uri,client_ip)
                    end
                    if log_mode ~= "on" then
                        ngx.exit(403)
                        return true
                    end
                end
            end
        end
    end
end

-- filter client url whether in url black list
function _M.black_url_filter()
    if enable_waf == 'on' and enable_black_url_filter == 'on' then
        local client_request_uri = ngx.var.request_uri
        local url_black_list = tools.get_rule('black_url.rule')
        if next(url_black_list) then
            for _,rule_uri in ipairs(url_black_list) do
                if rulefinder(client_request_uri,rule_uri,'isjo') then
                    if enable_attack_log == 'on' then
                        tools.log(tools.get_client_ip(),'black_url',ngx.var.request_uri,client_request_uri)
                    end
                    if log_mode ~= "on" then
                        ngx.exit(403)
                        return true
                    end
                end
            end
        end
    end
end

-- filter client user_agent whether in user_agent black list
function _M.user_agent_filter()
    if enable_waf == 'on' and enable_user_agent_filter == 'on' then
        local client_user_agent = ngx.var.http_user_agent
        if client_user_agent then
            local user_agent_list = tools.get_rule('user_agent.rule')
            if next(user_agent_list) then
                for _,rule_user_agent in ipairs(user_agent_list) do
                    if rulefinder(client_user_agent,rule_user_agent,'isjo') then
                        if enable_attack_log == 'on' then
                            tools.log(tools.get_client_ip(),'user_agent',ngx.var.request_uri,client_user_agent)
                        end
                        if log_mode ~= "on" then
                            ngx.exit(403)
                            return true
                        end
                    end
                end
            end
        end
    end
end

-- filter client cookie whether in cookie black list
function _M.cookie_filter()
    if enable_waf == 'on' and enable_cookie_attack_filter == "on" then
        local client_cookie = ngx.var.http_cookie
        if client_cookie then
            local cookie_rule_list = tools.get_rule('cookie.rule')
            if next(cookie_rule_list) then
                local rulefinder = ngx.re.find
                for _,rule_cookie in ipairs(cookie_rule_list) do
                    if rulefinder(client_cookie,rule_cookie,'isjo') then
                        if enable_attack_log == 'on' then
                            tools.log(tools.get_client_ip(),'cookie',ngx.var.request_uri,client_cookie)
                        end
                        if log_mode ~= "on" then
                            ngx.exit(403)
                            return true
                        end
                    end
                end
            end
        end
    end
end

-- filter client get request args whether in get_args black list
function _M.get_args_filter()
    if enable_waf == 'on' and enable_get_args_filter == 'on' then
        local ngxmatch = ngx.re.find
        local client_get_args_table = ngx.req.get_uri_args()
        if next(client_get_args_table) then
            local get_args_table = tools.get_rule('get_args.rule')
            if next(get_args_table) then
                for key,val in pairs(client_get_args_table) do
                    if type(val) == 'table' then
                        client_get_args = table.concat(val, " ")
                    else
                        client_get_args = tostring(val)
                    end
                    if client_get_args and client_get_args ~= "" then
                        for _,rule_get_args in ipairs(get_args_table) do
                            if rulefinder(ngx.unescape_uri(client_get_args),rule_get_args,"isjo") then
                                if enable_attack_log == 'on' then
                                    tools.log(tools.get_client_ip(),'get_args',ngx.var.request_uri,client_get_args)
                                end
                                if log_mode ~= "on" then
                                    ngx.exit(403)
                                    return true
                                end
                            end
                        end
                    end
                end
            end
        end
    end
end

-- filter client post request args whether in post_args black list
function _M.post_args_filter()
    if enable_waf == 'on' and enable_post_args_filter == 'on' and ngx.req.get_method() == "POST" then
        -- 在客户端请求头中，content-type参数的值包含‘boundary’
        if tools.get_boundary() then
            -- 获取客户端的socket连接
            local tcpsock, err = ngx.req.socket()
            if not tcpsock then
                return
            end
            tcpsock:settimeout(0)

            -- 设置在读取客户端socket时，每次读取的数据大小，即窗口大小
            local chunk_size = 4096
            local client_content_length = tonumber(ngx.req.get_headers()['content-length']) or 0
            if client_content_length < chunk_size then
                chunk_size = client_content_length
            end

            -- 从0开始读取客户端socket，并将读取到的数据存入到为当前请求创建的请求主体中
            ngx.req.init_body(128 * 1024)
            local head = 0
            while head < client_content_length do
                local data, err, partial = tcpsock:receive(chunk_size)
                data = data or partial
                -- 没有读到数据直接返回
                if not data then
                    return
                end
                -- 将读取到的数据写入到当前请求的请求主体中
                ngx.req.append_body(data)

                -- 直接过滤读取到的数据
                if tools.filter_request_body(data) then
                    return true
                end

                -- 走到这里说明，直接过滤没有找到非法数据。因此，进行更进一步的过滤
                local file_suffix = rulefinder(data,[[Content-Disposition: form-data;(.+)filename="(.+)\\.(.*)"]],'ijo')
                if file_suffix then
                    tools.filter_file_suffix(file_suffix[3])
                    return true
                else
                    if rulefinder(data,"Content-Disposition:",'isjo') then
                        if tools.filter_request_body(data) then
                            return true
                        end
                    end
                end

                -- 指针移动到下一个窗口的开始，并设置下一个窗口
                head = head + #data
                local free_data_length = client_content_length - head
                if free_data_length < chunk_size then
                    chunk_size = free_data_length
                end
            end

            -- 当前请求的请求主体，写入数据完毕
            ngx.req.finish_body()
        else
            ngx.req.read_body()
            local client_post_args = ngx.req.get_post_args()
            if not client_post_args then
                return
            end

            for k,v in pairs(client_post_args) do
                if type(v) == "table" then
                    data = table.concat(v, ", ")
                else
                    data = v
                end

                if data then
                    if tools.filter_request_body(data) or tools.filter_request_body(k) then
                        return true
                    end
                end
            end
        end
    end
end

-- filter client request whether is cc attack
function _M.cc_attack_filter()
    if enable_waf == 'on' and enable_cc_attack_filter == "on" then
        local client_ip = tools.get_client_ip()
        local cc_key =  client_ip .. ngx.var.uri
        local cc_count = tonumber(string.match(cc_rate,'(.*)/'))
        local cc_seconds = tonumber(string.match(cc_rate,'/(.*)'))

        local cc_counter = ngx.shared.cc_counter_store
        local current_rate,_ = cc_counter:get(cc_key)
        if current_rate then
            if current_rate > cc_count then
                if enable_attack_log == 'on' then
                    tools.log(client_ip,'cc',ngx.var.request_uri,current_rate..'/'..cc_seconds)
                end
                if log_mode ~= "on" then
                    ngx.exit(403)
                    return true
                end
            else
                cc_counter:incr(cc_key,1)
            end
        else
            cc_counter:set(cc_key,1,cc_seconds)
        end
    end
end

return _M