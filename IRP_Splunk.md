# Incident Response Plan: Splunk Detection Playbook

## 1. Splunk Index Discovery and Configuration

...existing code...

## 2. Splunk Detection Queries

### PHP Reverse Shell Detection

```spl
index=main sourcetype=tcpdump arp
| stats count by src_mac
| where count > 50
| sort - count
```

```spl
index=main tcp_flags="S"
| stats dc(dest_port) as unique_ports by src_ip
| where unique_ports > 100
```

```spl
index=main method="POST" uri_path="*upload*"
| rex field=form_data "filename=\"(?<filename>[^\"]+)\""
| where match(filename, "\.php$")
```

```spl
index=main
| transaction src_ip dest_ip dest_port
| where dest_port IN (4444, 1234, 8080) AND duration > 60
```

### SQL Injection Detection

```spl
index=main (uri_path="/rest/user/login" OR uri_path="/rest/products/search" OR uri_path="/rest/track-order/*")
| rex field=uri_query "(?<sqli_indicators>('|\"|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|--|\*|;))"
| where isnotnull(sqli_indicators)
| stats count by src_ip sqli_indicators uri_path
```

```spl
index=main uri_path="/rest/user/login" method="POST"
| rex field=form_data "email=(?<email_input>[^&]+)"
| where match(email_input, "('|--|UNION|SELECT)")
| stats count by src_ip email_input
```

```spl
index=main
| where match(useragent, "(?i)sqlmap") OR match(uri_query, "testpayload")
| stats count by src_ip useragent
```

```spl
index=main
| where match(uri_query, "(?i)(sqlite_master|information_schema|sys\.tables|SHOW\s+TABLES)")
| stats count by src_ip uri_path uri_query
```

```spl
index=main status>=400
| where match(response_body, "(?i)(sql|database|syntax|mysql|sqlite|oracle)")
| stats count by src_ip status response_body
```

### XSS Detection

```spl
index=main
| rex field=uri_query "(?<xss_indicators>(<script>|javascript:|onerror|onload|alert\(|document\.cookie))"
| where isnotnull(xss_indicators)
| stats count by src_ip xss_indicators uri_path
```

```spl
index=main
| where match(uri_query, "(?i)(document\.cookie|document\.location|window\.location)")
| stats count by src_ip uri_path form_data
```

```spl
index=main method="GET"
| where match(uri_query, "(?i)(<script>|javascript:|onerror)")
| where match(response_body, uri_query)
| stats count by src_ip uri_query
```

```spl
index=main method="POST"
| rex field=form_data "(?<xss_payload>(<script>|javascript:|onerror)[^&]*)"
| where isnotnull(xss_payload)
| stats count by src_ip xss_payload uri_path
```

```spl
index=main
| where match(uri_query, "(?i)(document\.write|innerHTML|location\.hash|location\.search)")
| stats count by src_ip uri_query
```

### IDOR Detection

```spl
index=main
| rex field=uri_query "(?<object_refs>(id=|user=|file=|account=)(?<ref_value>\d+))"
| where isnotnull(object_refs)
| eventstats dc(ref_value) as unique_refs by src_ip uri_path
| where unique_refs > 10
| stats count by src_ip uri_path object_refs
```

```spl
index=main status=200
| where match(uri_path, "(?i)(admin|profile|account|user)")
| where match(uri_query, "(id=|user=)")
| stats dc(uri_query) as unique_access by src_ip
| where unique_access > 5
```

```spl
index=main
| where match(uri_query, "(?i)(\.\.\/|\.\.%2F|\.\.%5C)")
| stats count by src_ip uri_query uri_path
```

```spl
index=main
| where match(uri_path, "(?i)(admin|manager|root)")
| where NOT match(user_role, "(?i)(admin|administrator)")
| stats count by src_ip user_id uri_path
```

### Phishing Detection

```spl
index=main
| where match(host, "(?i)(security|verify|update|account|confirm)")
| where NOT match(host, "(legitimate-domain\.com|trusted-site\.org)")
| stats count by src_ip host uri_path
```

```spl
index=main method="POST"
| where match(form_data, "(?i)(password|username|login|email)")
| where NOT match(host, "(legitimate-login-domains)")
| stats count by src_ip host form_data
```

```spl
index=main
| where match(referer, "(?i)(email|mail|webmail)")
| where match(host, "(?i)(security|verify|update|account)")
| stats count by src_ip referer host
```

### SYN Flood DDoS Detection

```spl
index=main tcp_flags="S"
| bucket _time span=1s
| stats count as syn_count by _time dest_ip
| where syn_count > 100
| sort -syn_count
```

```spl
index=main tcp_flags="S" dest_ip="10.30.0.235"
| stats count by src_ip
| where count > 50
| sort -count
```

```spl
index=main tcp_flags="S" dest_ip="10.30.0.235"
| join src_ip dest_ip dest_port [search index=main tcp_flags="SA" OR tcp_flags="R"]
| where isnull(tcp_flags_join)
| stats count as incomplete_handshakes by src_ip
```

```spl
index=main tcp_flags="S" dest_ip="10.30.0.235"
| stats dc(src_ip) as unique_sources, count as total_syns by dest_port
| where unique_sources > 100 AND total_syns > 1000
```

```spl
index=main tcp_flags="S" dest_ip="10.30.0.235"
| bucket _time span=1m
| stats count as syn_rate by _time
| where syn_rate > baseline_rate * 10
```

### Brute Force Detection

```spl
index=main uri_path="*login*" method="POST"
| stats count as attempts by src_ip
| where attempts > 20
| sort -attempts
```

```spl
index=main dest_port=22 tcp_flags="S"
| bucket _time span=1m
| stats count as attempts by _time src_ip dest_ip
| where attempts > 10
```

```spl
index=main uri_path="*login*" (status=401 OR status=403)
| stats count as failed_attempts by src_ip
| where failed_attempts > 15
```

```spl
index=main uri_path="*login*" method="POST"
| rex field=form_data "username=(?<username>[^&]+)"
| stats dc(username) as unique_users, count as attempts by src_ip
| where unique_users > 5 AND attempts > 20
```

```spl
index=main uri_path="*login*" method="POST"
| stats count as attempts, dc(user_agent) as unique_agents by src_ip
| where attempts > 50 AND unique_agents = 1
```

```spl
index=auth event_type="account_locked"
| stats count as lockouts by username
| where lockouts > 3
```

### Session Hijacking Detection

```spl
index=main
| rex field=cookie "(?<session_token>(PHPSESSID|JSESSIONID|sessionid)=[^;]+)"
| where isnotnull(session_token)
| stats dc(src_ip) as unique_ips, values(src_ip) as source_ips by session_token
| where unique_ips > 1
| sort -unique_ips
```

```spl
index=main
| rex field=cookie "sessionid=(?<session_token>[^;]+)"
| where isnotnull(session_token)
| stats values(src_ip) as source_ips, values(user_agent) as user_agents by session_token
| where mvcount(source_ips) > 1 OR mvcount(user_agents) > 1
```

```spl
index=main
| rex field=cookie "(?<session_token>(PHPSESSID|JSESSIONID)=[^;]+)"
| where isnotnull(session_token)
| iplocation src_ip
| stats dc(Country) as unique_countries by session_token user_id
| where unique_countries > 1
```

```spl
index=main uri_path="*login*"
| rex field=response_headers "Set-Cookie: (?<new_session>[^;]+)"
| rex field=cookie "(?<old_session>[^;]+)"
| where new_session = old_session
| stats count by src_ip session_id
```

```spl
index=main
| rex field=cookie "(?<session_token>sessionid=[^;]+)"
| where isnotnull(session_token)
| bucket _time span=1m
| stats dc(src_ip) as concurrent_ips by _time session_token
| where concurrent_ips > 1
```

## 3. Splunk Dashboards and Alerts

...all Splunk dashboard XML and alert configuration sections...
