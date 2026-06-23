/**
 * Sets up Justified Gallery.
 */
if (!!$.prototype.justifiedGallery) {
  var options = {
    rowHeight: 140,
    margins: 4,
    lastRow: "justify"
  };
  $(".article-gallery").justifiedGallery(options);
}

$(document).ready(function() {

  /**
   * Shows the responsive navigation menu on mobile.
   */
  $("#header > #nav > ul > .icon").click(function() {
    $("#header > #nav > ul").toggleClass("responsive");
  });


  /**
   * Controls the different versions of  the menu in blog post articles 
   * for Desktop, tablet and mobile.
   */
  if ($(".post").length) {
    var menu = $("#menu");
    var nav = $("#menu > #nav");
    var menuIcon = $("#menu-icon, #menu-icon-tablet");

    /**
     * Display the menu on hi-res laptops and desktops.
     */
    if ($(document).width() >= 1440) {
      menu.show();
      menuIcon.addClass("active");
    }

    /**
     * Display the menu if the menu icon is clicked.
     */
    menuIcon.click(function() {
      if (menu.is(":hidden")) {
        menu.show();
        menuIcon.addClass("active");
      } else {
        menu.hide();
        menuIcon.removeClass("active");
      }
      return false;
    });

    /**
     * Add a scroll listener to the menu to hide/show the navigation links.
     */
    if (menu.length) {
      $(window).on("scroll", function() {
        var topDistance = menu.offset().top;

        // hide only the navigation links on desktop
        if (!nav.is(":visible") && topDistance < 50) {
          nav.show();
        } else if (nav.is(":visible") && topDistance > 100) {
          nav.hide();
        }

        // on tablet, hide the navigation icon as well and show a "scroll to top
        // icon" instead
        if ( ! $( "#menu-icon" ).is(":visible") && topDistance < 50 ) {
          $("#menu-icon-tablet").show();
          $("#top-icon-tablet").hide();
        } else if (! $( "#menu-icon" ).is(":visible") && topDistance > 100) {
          $("#menu-icon-tablet").hide();
          $("#top-icon-tablet").show();
        }
      });
    }

    /**
     * Show mobile navigation menu after scrolling upwards,
     * hide it again after scrolling downwards.
     */
    if ($( "#footer-post").length) {
      var lastScrollTop = 0;
      $(window).on("scroll", function() {
        var topDistance = $(window).scrollTop();

        if (topDistance > lastScrollTop){
          // downscroll -> show menu
          $("#footer-post").hide();
        } else {
          // upscroll -> hide menu
          $("#footer-post").show();
        }
        lastScrollTop = topDistance;

        // close all submenu"s on scroll
        $("#nav-footer").hide();
        $("#toc-footer").hide();
        $("#share-footer").hide();

        // show a "navigation" icon when close to the top of the page, 
        // otherwise show a "scroll to the top" icon
        if (topDistance < 50) {
          $("#actions-footer > #top").hide();
        } else if (topDistance > 100) {
          $("#actions-footer > #top").show();
        }
      });
    }
  }

  setupPhpSrcContributionStats();
});

function setupPhpSrcContributionStats() {
  var root = document.getElementById("php-src-contribution-stats");
  if (!root || !window.fetch) {
    return;
  }

  var owner = root.getAttribute("data-owner") || "php";
  var repo = root.getAttribute("data-repo") || "php-src";
  var author = root.getAttribute("data-author") || "LamentXU123";
  var cacheMinutes = Number(root.getAttribute("data-cache-minutes") || 15);
  var cacheKey = ["php-src-stats", owner, repo, author].join(":");
  var status = root.querySelector('[data-stat="status"]');

  function setStatus(message) {
    if (status) {
      status.textContent = message;
    }
  }

  function setValue(name, value) {
    var node = root.querySelector('[data-stat="' + name + '"]');
    if (node) {
      node.textContent = Number(value).toLocaleString();
    }
  }

  function render(stats, stale) {
    setValue("additions", stats.additions);
    setValue("deletions", stats.deletions);
    setValue("prs", stats.prs);
    var updatedAt = stats.updatedAt ? new Date(stats.updatedAt) : new Date();
    var prefix = stale ? "GitHub 暂时不可用，显示缓存统计" : "实时统计";
    setStatus(prefix + "，更新于 " + updatedAt.toLocaleString());
  }

  function readCache() {
    try {
      var cached = JSON.parse(localStorage.getItem(cacheKey) || "null");
      if (!cached || !cached.updatedAt) {
        return null;
      }
      return cached;
    } catch (error) {
      return null;
    }
  }

  function writeCache(stats) {
    try {
      localStorage.setItem(cacheKey, JSON.stringify(stats));
    } catch (error) {
      // Ignore unavailable or full localStorage.
    }
  }

  function getLinkHeaderUrl(headers, rel) {
    var link = headers.get("Link");
    if (!link) {
      return null;
    }
    var parts = link.split(",");
    for (var i = 0; i < parts.length; i++) {
      var section = parts[i].split(";");
      if (section.length < 2 || section[1].indexOf('rel="' + rel + '"') === -1) {
        continue;
      }
      return section[0].trim().replace(/^<|>$/g, "");
    }
    return null;
  }

  function fetchJson(url) {
    return fetch(url, {
      headers: {
        Accept: "application/vnd.github+json"
      }
    }).then(function(response) {
      if (!response.ok) {
        throw new Error("GitHub API " + response.status);
      }
      return response;
    });
  }

  function fetchMergedPulls() {
    var query = [
      "repo:" + owner + "/" + repo,
      "author:" + author,
      "is:pr",
      "is:merged"
    ].join(" ");
    var url = "https://api.github.com/search/issues?q=" + encodeURIComponent(query) + "&per_page=100";
    var pulls = [];

    function next(pageUrl) {
      return fetchJson(pageUrl).then(function(response) {
        var nextUrl = getLinkHeaderUrl(response.headers, "next");
        return response.json().then(function(data) {
          pulls = pulls.concat(data.items || []);
          if (nextUrl) {
            return next(nextUrl);
          }
          return pulls;
        });
      });
    }

    return next(url);
  }

  function fetchPullStats(pull) {
    return fetchJson(pull.pull_request.url).then(function(response) {
      return response.json();
    }).then(function(data) {
      return {
        additions: data.additions || 0,
        deletions: data.deletions || 0
      };
    });
  }

  function fetchAllPullStats(pulls) {
    var totals = {
      additions: 0,
      deletions: 0,
      prs: pulls.length,
      updatedAt: new Date().toISOString()
    };
    var index = 0;
    var workers = [];
    var workerCount = Math.min(6, pulls.length || 1);

    function worker() {
      if (index >= pulls.length) {
        return Promise.resolve();
      }
      var pull = pulls[index++];
      return fetchPullStats(pull).then(function(stats) {
        totals.additions += stats.additions;
        totals.deletions += stats.deletions;
        setStatus("正在统计 GitHub PR " + index + " / " + pulls.length + "...");
        return worker();
      });
    }

    for (var i = 0; i < workerCount; i++) {
      workers.push(worker());
    }

    return Promise.all(workers).then(function() {
      return totals;
    });
  }

  var cached = readCache();
  var now = Date.now();
  if (cached) {
    render(cached, false);
    if (now - new Date(cached.updatedAt).getTime() < cacheMinutes * 60 * 1000) {
      return;
    }
    setStatus("正在刷新 GitHub 实时统计...");
  }

  fetchMergedPulls()
    .then(fetchAllPullStats)
    .then(function(stats) {
      writeCache(stats);
      render(stats, false);
    })
    .catch(function(error) {
      if (cached) {
        render(cached, true);
      } else {
        setStatus("GitHub 统计加载失败：" + error.message);
      }
    });
}
