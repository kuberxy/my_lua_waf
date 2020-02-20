-- enable waf and filter rules path
enable_waf = 'on'
rule_dir = "./rules"

-- record attack log and attack log path
enable_attack_log = 'on'
log_dir = './logs'

-- enable white_ip filter
enable_white_ip_filter = 'on'

-- enable white_url filter
enable_white_url_filter = 'on'

-- enable black_ip filter
enable_black_ip_filter = 'on'

-- enable black_url filter
enable_black_url_filter = 'on'

-- enable user_agent filter
enable_user_agent_filter = 'on'

-- enable cookie_attack filter
enable_cookie_attack_filter = "on"

-- enable get_args filter
enable_get_args_filter == 'on'

-- enable post_args filter
enable_post_args_filter == 'on'
balck_file_suffix = {"php","jsp"}

-- enable cc_attack filter and cc rate(the xxx of xxx seconds) 
enable_cc_attack_filter = "on"
cc_rate = "100/60"