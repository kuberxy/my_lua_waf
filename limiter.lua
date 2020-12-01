require 'config'

local limit_rate = require("resty.limit.rate")

local _M = {}

function _M.req_rate_limiter()
    if enable_req_rate_limiter ~= 'on' then
        return
    end

    -- global 40r/s 12000r/5m
    local lim_global,err = limit_rate.new("limit_rate_store", 100, 12000, 4, nil, {
        lock_enable = true,
        locks_shdict_name = "my_locks",
    })
    if not lim_global then
        ngx.log(ngx.ERR, "global bucket init failed: ", err)
        return ngx.exit(500)
    end
    
    -- single 10r/s 6000r/5m
    local lim_single,err = limit_rate.new("limit_rate_store", 200, 6000, 2, 100, {
        locks_shdict_name = "my_locks",
    })
    if not lim_single then
        ngx.log(ngx.ERR, "single bucket init failed: ", err)
        return ngx.exit(500)
    end
    
    -- take token from global bucket
    local t, err = lim_global:take_available("__global__", 1)
    if not t then
        ngx.log(ngx.ERR, "failed to take global: ", err)
        return ngx.exit(500)
    end
    
    -- take token from single bucket
    local key = ngx.var.binary_remote_addr or "__single__"
    local delay, err = lim_single:take(key,1,true)

    -- if global and single bucket full?
    if t == 1 then
        if not delay then
            if err == "rejected" then
                ngx.exit(403)
            end
            ngx.log(ngx.ERR, "failed to take single: ", err)
            return ngx.exit(500)
        end
    
        if delay >= 0.001 then
            ngx.sleep(delay)
        end
    else  -- global bucket full
        if not delay then
            if err == "rejected" then
                ngx.log(ngx.ERR, "limiter rejected: ", ngx.var.remote_addr)
                ngx.exit(403)
            end
            ngx.log(ngx.ERR, "failed to take single: ", err)
            return ngx.exit(500)
        end
        
        if delay >= 0.001 then
            ngx.log(ngx.ERR, "limiter rejected: ", ngx.var.remote_addr)
            return ngx.exit(403)
        end
    end
end

return _M
