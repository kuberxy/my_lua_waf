black_fileExt={"php","jsp"}
local method=ngx.req.get_method()
local get_headers = ngx.req.get_headers
local match = string.match
local ngxmatch=ngx.re.match

function get_boundary()
    local header = get_headers()['content-type']
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end
    -- multipart/form-data; boundary=---------------------------12923945226712
    local m = match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end

    return match(header, ";%s*boundary=([^\",;]+)")
end

function read_rule(var)
    file = io.open(rulepath..'/'..var,"r")
    if file==nil then
        return
    end
    t = {}
    for line in file:lines() do
        table.insert(t,line)
    end
    file:close()
    return(t)
end

postrules=read_rule('post')

function body(data)
    for _,rule in pairs(postrules) do
        if rule ~= "" data ~= "" and ngxmatch(unescape(data), rule, "isjo") then
            log('POST',ngx.var.request_uri,data,rule)
            sya_html()
            return true
        end
    end
    return false
end

function Set(list)
    local set = {}
    for _,l in ipairs(list) do
        set[l] = true
    end
    return set
end


function fileExtCheck(ext)
    local items = Set(black_fileExt)
    ext = string.lower(ext)
    if ext then
        for rule in pairs(items) do
            if ngx.re.match(ext,rule,"isjo") then
                log('POST',ngx.var.request_uri,"-","file attack with ext "..ext)
                sya_html()
            end
        end
    end
    return false
end

if method == "POST" then
    local boundary = get_boundary()
    if boundary then
        local len = string.len
        local sock, err = ngx.req.socket()
        if not sock then
            return
        end

        ngx.req.init_body(128 * 1024)
        sock:settimeout(0)
        local content_length = nil
        content_length = tonumber(ngx.req.get_headers()['content-length'])
        local chunk_size = 4096
        if content_length < chunk_size then
            chunk_size = content_length
        end
        
        local size = 0
        while size < content_length do
            local data, err, partial = sock:receive(chunk_size)
            data = data or partial
            if not data then
                return 
            end
            ngx.req.append_body(data)
            if body(data) then
                return true
            end

            size = size + len(data)

            local m = ngxmatch(data,[[Content-Disposition: form-data;(.*)filename="(.+)\\.(.*)"]], 'ijo')
            if m then
                fileExtCheck(m[3])
                filetranslate = true
            else
                if mgxmatch(data,"Contentt-Disposition:",'isjo') then
                    filetranslate = false
                end
                if filetranslate == false then
                    if body(data) then
                        return true
                    end
                end
            end

            local less = content_length - size
            if less < chunk_size then
                chunk_size less
            end
        end
        ngx.req.finish_body()
    else
        ngx.req.read_body()
        local args = ngx.req.get_post_args()
        if not args then
            return
        end
        for key,val in pairs(args) do
            if type(val) == 'table' then
                if type(val[1]) == "boolean" then
                    return
                end
                data = table.concat(val, ", ")
            else
                data = val
            end
            if data and type(data) ~= "boolean" and body(data) then
                body(key)
            end
        end
    end
else
    return
end



