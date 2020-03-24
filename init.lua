require 'config'

local tools = require('tools')
local rulefinder = ngx.re.find

local _M = {}

-- filter client ip whether in ip white list
function _M.white_ip_filter()
    if enable_waf == 'off' or enable_white_ip_filter == 'off' then
        return
    end

    local client_ip = ngx.var.remote_addr
    if not client_ip then
        return
    end

    local white_ip_rules = tools.get_rule('white_ip.rule')  -- return a table
    if not next(white_ip_rules) then
        return
    end

    for _,rule_ip in ipairs(white_ip_rules) do
        if client_ip == rule_ip then
            if enable_attack_log == 'on' then
                tools.log(client_ip,'white_ip',ngx.var.request_uri,client_ip)
            end
            return true
        end
    end
end

-- filter client url whether in url white list
function _M.white_url_filter()
    if enable_waf == 'off' or enable_white_url_filter == 'off' then
        return
    end

    local client_request_uri = ngx.var.request_uri
    if not client_request_uri then
        return
    end

    local white_url_rules = tools.get_rule('white_url.rule')
    if not next(white_url_rules) then
        return
    end

    for _,rule_uri in ipairs(white_url_rules) do
        if rulefinder(client_request_uri,rule_uri,'isjo') then
            if enable_attack_log == 'on' then
                tools.log(ngx.var.remote_addr,'white_url',client_request_uri,client_request_uri)
            end
            return true
        end
    end
end

-- filter client ip whether in ip black list
function _M.black_ip_filter()
    if enable_waf == 'off' or enable_black_ip_filter == 'off' then
        return
    end

    local client_ip = ngx.var.remote_addr
    if not client_ip then
        return
    end

    local black_ip_rules = tools.get_rule('black_ip.rule')
    if not next(black_ip_rules) then
        return
    end

    for _,rule_ip in ipairs(black_ip_rules) do
        if client_ip == rule_ip then
            if enable_attack_log == 'on' then
                tools.log(client_ip,'black_ip',ngx.var.request_uri,client_ip)
            end
            if dry_mode ~= "on" then
                ngx.exit(403)
                return true
            end
        end
    end
end

-- filter client url whether in url black list
function _M.black_url_filter()
    if enable_waf == 'off' or enable_black_url_filter == 'off' then
        return
    end

    local client_request_uri = ngx.var.request_uri
    if not client_request_uri then
        return
    end

    local black_url_rules = tools.get_rule('black_url.rule')
    if not next(black_url_rules) then
        return
    end

    for _,rule_uri in ipairs(black_url_rules) do
        if rulefinder(client_request_uri,rule_uri,'isjo') then
            if enable_attack_log == 'on' then
                tools.log(ngx.var.remote_addr,'black_url',client_request_uri,client_request_uri)
            end
            if dry_mode ~= "on" then
                ngx.exit(403)
                return true
            end
        end
    end
end

-- filter client user_agent whether in user_agent black list
function _M.user_agent_filter()
    if enable_waf == 'off' or enable_user_agent_filter == 'off' then
        return
    end

    local client_user_agent = ngx.var.http_user_agent
    if not client_user_agent then
        return
    end

    local user_agent_rules = tools.get_rule('user_agent.rule')
    if not next(user_agent_rules) then
        return
    end

    for _,rule_user_agent in ipairs(user_agent_rules) do
        if rulefinder(client_user_agent,rule_user_agent,'isjo') then
            if enable_attack_log == 'on' then
                tools.log(ngx.var.remote_addr,'user_agent',ngx.var.request_uri,client_user_agent)
            end
            if dry_mode ~= "on" then
                ngx.exit(403)
                return true
            end
        end
    end
end

-- filter client cookie whether in cookie black list
function _M.cookie_filter()
    if enable_waf == 'off' or enable_cookie_attack_filter == "off" then
        return
    end

    local client_cookie = ngx.var.http_cookie
    if not client_cookie then
        return
    end

    local cookie_rules = tools.get_rule('cookie.rule')
    if not next(cookie_rules) then
        return
    end

    for _,rule_cookie in ipairs(cookie_rules) do
        if rulefinder(client_cookie,rule_cookie,'isjo') then
            if enable_attack_log == 'on' then
                tools.log(ngx.var.remote_addr,'cookie',ngx.var.request_uri,client_cookie)
            end
            if dry_mode ~= "on" then
                ngx.exit(403)
                return true
            end
        end
    end
end

-- filter client get request args whether in get_args black list
function _M.get_args_filter()
    if enable_waf == 'off' or enable_get_args_filter == 'off' then
        return
    end

    local client_get_args_table = ngx.req.get_uri_args()
    if not next(client_get_args_table) then
        return
    end

    local get_args_rules = tools.get_rule('get_args.rule')
    if not next(get_args_rules) then
        return
    end

    for key,val in pairs(client_get_args_table) do
        if type(val) == 'table' then
            local t = {}
            for k,v in pairs(val) do
                if t == true then
                    v = ""
                end
                table.insert(t,v)
            end
            client_get_args = table.concat(t, " ")
        else
            client_get_args = tostring(val)
        end

        if not client_get_args or client_get_args == "" then
            return
        end

        for _,rule_get_args in ipairs(get_args_rules) do
            if rulefinder(ngx.unescape_uri(client_get_args),rule_get_args,"isjo") then
                if enable_attack_log == 'on' then
                    tools.log(ngx.var.remote_addr,'get_args',ngx.var.request_uri,client_get_args)
                end
                if dry_mode ~= "on" then
                    ngx.exit(403)
                    return true
                end
            end
        end
    end
end

-- filter client post request args whether in post_args black list
function _M.post_args_filter()
    if enable_waf == 'off' or enable_post_args_filter == 'off' then
        return
    end

    if ngx.req.get_method() ~= "POST" then
        return
    end

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

        -- 从0开始读取客户端socket，并用读取到的数据构造一个新的请求主体
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
                 if tools.filter_file_suffix(file_suffix[3]) then
                    return true
                end
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

        -- 新请求主体构造完毕
        ngx.req.finish_body()
    else
        ngx.req.read_body()
        local client_post_args = ngx.req.get_post_args()
        if not client_post_args then
            return
        end

        for key,val in pairs(client_post_args) do
            if type(val) == "table" then
                if type(val[1]) == "boolean" then
                    return
                end
                data = table.concat(val, ", ")
            else
                data = val
            end

            if not data then
                return
            end

            if tools.filter_request_body(data) or tools.filter_request_body(key) then
                return true
            end
        end
    end
end

return _M