---
layout: default
title: Home
---

{% for post in site.posts %}
## [{{ post.title }}]({{ post.url }})
<!-- date time  -->
*{{ post.date | date: "%B %-d, %Y %I:%M %p" }}*
{{ post.excerpt }}
{% endfor %}
