---
layout: page
title: s4vinotes
---

<section>
   <h3>This years posts 2023 , posts de este año 2023 </h3>
   <ul>
      {% assign sorted_posts = site.posts2 | sort: 'title' %}
      {% for post in sorted_posts %}
        <li>
          <a href="{{ post.url | prepend: site.baseurl | replace: '//', '/' }}">{{ post.title }}
          </a>
        </li>
    {% endfor %}
    </ul>
</section>
