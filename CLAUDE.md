# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Personal blog (https://twizzyindy.github.io) built with Jekyll 4.4 and the stock `minima` theme, hosted on GitHub Pages. There is no custom layout or CSS; the only local override is `_includes/google-analytics.html`.

## Commands

- Install: `bundle install`
- Serve locally with live reload of content: `bundle exec jekyll serve` (`_config.yml` changes require a restart)
- Build: `bundle exec jekyll build`
- Google Analytics only renders when `JEKYLL_ENV=production`.
- On this Windows machine Ruby is installed via scoop and is not on the Bash tool's PATH; run `export PATH="/c/Users/twizz/scoop/apps/ruby/current/bin:$PATH"` first.
- Sass deprecation warnings (`@import`, `lighten()`, etc.) come from minima 2.5.x itself (2.5.2 is the latest and has the same issue). They are muted by `sass.silence_deprecations` in `_config.yml`; the real fix would be migrating the theme's SCSS locally or leaving minima.

There are no tests or linters.

## Content conventions

- Posts live in `_posts/` as `YYYY-MM-DD-slug.md` with front matter: `layout: post`, `title`, `date` (with `+0630` timezone), `categories`, `tags`.
- Posts are written in both English and Burmese as separate files: the English one is `*-en.md`, the Burmese one is `*-mm.md` (title suffixed ` (MM)`, tag `mm` added). Keep the pair in sync when editing one.
- Post images go in `assets/imgs/<post-slug-folder>/` (e.g. `assets/imgs/learning-from-exynos`).
- Top-level pages (`index.md`, `about.markdown`, `404.html`) use the theme's layouts; site metadata (title, social usernames, `google_analytics` ID) is in `_config.yml`.
