---
layout: page
title: Tags
hidden: true
---

<span class="discreet">Sort by <a href="/">date</a></span>
<br>

{% for tag in site.tags  %}
  <h3 id="{{ tag[0] }}-ref">{{ tag[0] }}</h3>
  <ul>
  {% assign post_list = tag[1] %}
  {% for post in post_list %}
    <li><a href="{{ post.url }}">{{ post.title }}</a></li>
  {% endfor %}
  </ul>
{% endfor %}

<br>
<p class="rss-subscribe">subscribe <a href="{{ "/feed.xml" | relative_url }}">via RSS</a></p>
