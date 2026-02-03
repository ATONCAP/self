/**
 * NewsService.js - News and intelligence gathering for executive assistant
 *
 * Handles news fetching, caching, alerts, and briefing generation
 * Uses Portugal timezone (WET/WEST) for all date calculations
 */

// Portugal timezone
const TIMEZONE = 'Europe/Lisbon';

// Default alerts to seed on initialization
const DEFAULT_ALERTS = [
  { keyword: 'AlphaTON', category: 'company', frequency: 'realtime' },
  { keyword: 'TON blockchain', category: 'industry', frequency: 'daily' },
  { keyword: 'Telegram crypto', category: 'industry', frequency: 'daily' },
  { keyword: 'AI regulation', category: 'regulatory', frequency: 'daily' },
  { keyword: 'cryptocurrency SEC', category: 'regulatory', frequency: 'realtime' },
  { keyword: 'blockchain', category: 'technology', frequency: 'weekly' }
];

// Category emoji mapping
const CATEGORY_EMOJIS = {
  company: '🏢',
  industry: '📈',
  competitor: '🎯',
  regulatory: '⚖️',
  technology: '💻',
  general: '📰'
};

/**
 * Get current date in Portugal timezone
 * @returns {Date}
 */
function getPortugalNow() {
  const now = new Date();
  const ptString = now.toLocaleString('en-US', { timeZone: TIMEZONE });
  return new Date(ptString);
}

/**
 * Format a date for SQLite storage (ISO format)
 * @param {Date|string} date
 * @returns {string|null}
 */
function formatDateForDb(date) {
  if (!date) return null;
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toISOString();
}

/**
 * Format a date for human-readable display
 * @param {Date|string} date
 * @returns {string}
 */
function formatDateForDisplay(date) {
  if (!date) return 'Unknown';
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleString('en-US', {
    timeZone: TIMEZONE,
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

// ============================================================================
// Database Initialization
// ============================================================================

/**
 * Initialize database tables for news and alerts
 * @param {Database} db - better-sqlite3 database instance
 */
function initTables(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS news_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT,
      title TEXT NOT NULL,
      url TEXT,
      summary TEXT,
      relevance_score REAL DEFAULT 0,
      category TEXT,
      published_at DATETIME,
      read BOOLEAN DEFAULT 0,
      starred BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS news_alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      keyword TEXT NOT NULL,
      source_filter TEXT,
      category TEXT,
      frequency TEXT DEFAULT 'daily',
      last_checked DATETIME,
      enabled BOOLEAN DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_news_items_url ON news_items(url);
    CREATE INDEX IF NOT EXISTS idx_news_items_category ON news_items(category);
    CREATE INDEX IF NOT EXISTS idx_news_items_read ON news_items(read);
    CREATE INDEX IF NOT EXISTS idx_news_items_starred ON news_items(starred);
    CREATE INDEX IF NOT EXISTS idx_news_items_created_at ON news_items(created_at);
    CREATE INDEX IF NOT EXISTS idx_news_items_published_at ON news_items(published_at);
    CREATE INDEX IF NOT EXISTS idx_news_alerts_enabled ON news_alerts(enabled);
    CREATE INDEX IF NOT EXISTS idx_news_alerts_frequency ON news_alerts(frequency);
  `);

  // Seed default alerts if none exist
  const alertCount = db.prepare('SELECT COUNT(*) as count FROM news_alerts').get();
  if (alertCount.count === 0) {
    const insertAlert = db.prepare(`
      INSERT INTO news_alerts (keyword, category, frequency)
      VALUES (?, ?, ?)
    `);

    for (const alert of DEFAULT_ALERTS) {
      try {
        insertAlert.run(alert.keyword, alert.category, alert.frequency);
      } catch (err) {
        console.error(`Failed to seed alert: ${alert.keyword}`, err.message);
      }
    }
    console.log(`Seeded ${DEFAULT_ALERTS.length} default news alerts`);
  }
}

// ============================================================================
// News Fetching
// ============================================================================

/**
 * Fetch news from NewsAPI or return mock data
 * @param {string[]} keywords - Keywords to search for
 * @param {string} [apiKey] - NewsAPI key (or use NEWS_API_KEY env var)
 * @returns {Promise<Object[]>} Array of news items
 */
async function fetchNews(keywords, apiKey) {
  const key = apiKey || process.env.NEWS_API_KEY;

  if (!key) {
    console.log('No NewsAPI key provided, returning mock data');
    return generateMockNews(keywords);
  }

  const query = encodeURIComponent(keywords.join(' OR '));
  const url = `https://newsapi.org/v2/everything?q=${query}&sortBy=publishedAt&pageSize=50&apiKey=${key}`;

  try {
    const response = await fetch(url);

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(`NewsAPI error: ${response.status} - ${errorData.message || 'Unknown error'}`);
    }

    const data = await response.json();

    if (data.status !== 'ok') {
      throw new Error(`NewsAPI returned status: ${data.status} - ${data.message || 'Unknown error'}`);
    }

    return (data.articles || []).map(article => ({
      source: article.source?.name || 'Unknown',
      title: article.title || 'Untitled',
      url: article.url,
      summary: article.description || article.content?.substring(0, 200) || '',
      publishedAt: article.publishedAt,
      author: article.author
    }));
  } catch (err) {
    console.error('Failed to fetch news from API:', err.message);
    // Return mock data on failure to ensure service continuity
    return generateMockNews(keywords);
  }
}

/**
 * Generate mock news data for testing
 * @param {string[]} keywords - Keywords used for search
 * @returns {Object[]} Mock news items
 */
function generateMockNews(keywords) {
  const mockSources = ['TechCrunch', 'CoinDesk', 'Reuters', 'Bloomberg', 'The Verge'];
  const now = new Date();

  return keywords.slice(0, 5).map((keyword, i) => ({
    source: mockSources[i % mockSources.length],
    title: `Latest developments in ${keyword} industry - Mock Article`,
    url: `https://example.com/news/${keyword.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}`,
    summary: `This is a mock news article about ${keyword}. In production, this would contain real news content from NewsAPI.`,
    publishedAt: new Date(now.getTime() - i * 3600000).toISOString()
  }));
}

// ============================================================================
// News Caching
// ============================================================================

/**
 * Cache news items to database, avoiding duplicates by URL
 * @param {Database} db - better-sqlite3 database instance
 * @param {Object[]} items - News items to cache
 * @returns {Object} Result with counts
 */
function cacheNewsItems(db, items) {
  if (!items || items.length === 0) {
    return { cached: 0, duplicates: 0 };
  }

  const checkUrl = db.prepare('SELECT id FROM news_items WHERE url = ?');
  const insertItem = db.prepare(`
    INSERT INTO news_items (source, title, url, summary, relevance_score, category, published_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  let cached = 0;
  let duplicates = 0;

  const transaction = db.transaction((newsItems) => {
    for (const item of newsItems) {
      // Skip items without URL or check for duplicates
      if (item.url) {
        const existing = checkUrl.get(item.url);
        if (existing) {
          duplicates++;
          continue;
        }
      }

      try {
        insertItem.run(
          item.source || null,
          item.title,
          item.url || null,
          item.summary || null,
          item.relevanceScore || 0,
          item.category || 'general',
          formatDateForDb(item.publishedAt)
        );
        cached++;
      } catch (err) {
        console.error(`Failed to cache news item: ${item.title}`, err.message);
      }
    }
  });

  transaction(items);

  return { cached, duplicates };
}

/**
 * Deduplicate news items by URL
 * @param {Object[]} items - News items to deduplicate
 * @returns {Object[]} Deduplicated items
 */
function deduplicateNews(items) {
  const seen = new Set();
  return items.filter(item => {
    if (!item.url) return true; // Keep items without URL
    if (seen.has(item.url)) return false;
    seen.add(item.url);
    return true;
  });
}

// ============================================================================
// News Retrieval
// ============================================================================

/**
 * Get unread news items
 * @param {Database} db - better-sqlite3 database instance
 * @param {number} [limit=20] - Maximum items to return
 * @returns {Object[]} Unread news items
 */
function getUnreadNews(db, limit = 20) {
  try {
    return db.prepare(`
      SELECT * FROM news_items
      WHERE read = 0
      ORDER BY relevance_score DESC, published_at DESC
      LIMIT ?
    `).all(limit);
  } catch (err) {
    console.error('Failed to get unread news:', err.message);
    return [];
  }
}

/**
 * Get news items by category
 * @param {Database} db - better-sqlite3 database instance
 * @param {string} category - Category to filter by
 * @param {number} [limit=20] - Maximum items to return
 * @returns {Object[]} News items in category
 */
function getNewsByCategory(db, category, limit = 20) {
  try {
    return db.prepare(`
      SELECT * FROM news_items
      WHERE category = ?
      ORDER BY published_at DESC
      LIMIT ?
    `).all(category, limit);
  } catch (err) {
    console.error(`Failed to get news for category ${category}:`, err.message);
    return [];
  }
}

/**
 * Get starred/important news items
 * @param {Database} db - better-sqlite3 database instance
 * @returns {Object[]} Starred news items
 */
function getStarredNews(db) {
  try {
    return db.prepare(`
      SELECT * FROM news_items
      WHERE starred = 1
      ORDER BY published_at DESC
    `).all();
  } catch (err) {
    console.error('Failed to get starred news:', err.message);
    return [];
  }
}

/**
 * Mark a news item as read
 * @param {Database} db - better-sqlite3 database instance
 * @param {number} newsId - News item ID
 * @returns {boolean} Success status
 */
function markAsRead(db, newsId) {
  try {
    const result = db.prepare(`
      UPDATE news_items SET read = 1 WHERE id = ?
    `).run(newsId);
    return result.changes > 0;
  } catch (err) {
    console.error(`Failed to mark news ${newsId} as read:`, err.message);
    return false;
  }
}

/**
 * Toggle star status on a news item
 * @param {Database} db - better-sqlite3 database instance
 * @param {number} newsId - News item ID
 * @returns {Object|null} Updated item or null on failure
 */
function toggleStar(db, newsId) {
  try {
    db.prepare(`
      UPDATE news_items SET starred = NOT starred WHERE id = ?
    `).run(newsId);
    return db.prepare('SELECT * FROM news_items WHERE id = ?').get(newsId);
  } catch (err) {
    console.error(`Failed to toggle star on news ${newsId}:`, err.message);
    return null;
  }
}

/**
 * Search cached news items
 * @param {Database} db - better-sqlite3 database instance
 * @param {string} query - Search query
 * @returns {Object[]} Matching news items
 */
function searchNews(db, query) {
  try {
    const searchTerm = `%${query}%`;
    return db.prepare(`
      SELECT * FROM news_items
      WHERE title LIKE ? OR summary LIKE ? OR source LIKE ?
      ORDER BY relevance_score DESC, published_at DESC
      LIMIT 50
    `).all(searchTerm, searchTerm, searchTerm);
  } catch (err) {
    console.error(`Failed to search news for "${query}":`, err.message);
    return [];
  }
}

/**
 * Get news digest for the last N hours
 * @param {Database} db - better-sqlite3 database instance
 * @param {number} [hours=24] - Number of hours to look back
 * @returns {Object} Digest with categorized news
 */
function getNewsDigest(db, hours = 24) {
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);

  try {
    const items = db.prepare(`
      SELECT * FROM news_items
      WHERE created_at >= ?
      ORDER BY relevance_score DESC, published_at DESC
    `).all(formatDateForDb(since));

    // Group by category
    const byCategory = {};
    for (const item of items) {
      const cat = item.category || 'general';
      if (!byCategory[cat]) byCategory[cat] = [];
      byCategory[cat].push(item);
    }

    return {
      period: `Last ${hours} hours`,
      since: since.toISOString(),
      totalItems: items.length,
      byCategory,
      topStories: items.slice(0, 5),
      unreadCount: items.filter(i => !i.read).length
    };
  } catch (err) {
    console.error('Failed to generate news digest:', err.message);
    return {
      period: `Last ${hours} hours`,
      since: since.toISOString(),
      totalItems: 0,
      byCategory: {},
      topStories: [],
      unreadCount: 0
    };
  }
}

// ============================================================================
// Alert Management
// ============================================================================

/**
 * Add a news alert
 * @param {Database} db - better-sqlite3 database instance
 * @param {Object} alert - Alert configuration
 * @param {string} alert.keyword - Keyword to monitor
 * @param {string[]} [alert.sourceFilter] - Allowed sources (null for all)
 * @param {string} [alert.category] - Alert category
 * @param {string} [alert.frequency='daily'] - Check frequency
 * @returns {Object|null} Created alert or null on failure
 */
function addAlert(db, { keyword, sourceFilter, category, frequency = 'daily' }) {
  if (!keyword || keyword.trim().length === 0) {
    console.error('Cannot add alert: keyword is required');
    return null;
  }

  try {
    const result = db.prepare(`
      INSERT INTO news_alerts (keyword, source_filter, category, frequency)
      VALUES (?, ?, ?, ?)
    `).run(
      keyword.trim(),
      sourceFilter ? JSON.stringify(sourceFilter) : null,
      category || 'general',
      frequency
    );

    return db.prepare('SELECT * FROM news_alerts WHERE id = ?').get(result.lastInsertRowid);
  } catch (err) {
    console.error('Failed to add alert:', err.message);
    return null;
  }
}

/**
 * Get all alerts
 * @param {Database} db - better-sqlite3 database instance
 * @returns {Object[]} All alerts
 */
function getAlerts(db) {
  try {
    const alerts = db.prepare('SELECT * FROM news_alerts ORDER BY created_at DESC').all();
    return alerts.map(alert => ({
      ...alert,
      sourceFilter: alert.source_filter ? JSON.parse(alert.source_filter) : null
    }));
  } catch (err) {
    console.error('Failed to get alerts:', err.message);
    return [];
  }
}

/**
 * Update an alert
 * @param {Database} db - better-sqlite3 database instance
 * @param {number} alertId - Alert ID
 * @param {Object} updates - Fields to update
 * @returns {Object|null} Updated alert or null on failure
 */
function updateAlert(db, alertId, updates) {
  const allowedFields = ['keyword', 'source_filter', 'category', 'frequency', 'enabled'];
  const setClause = [];
  const values = [];

  for (const [key, value] of Object.entries(updates)) {
    const dbKey = key === 'sourceFilter' ? 'source_filter' : key;
    if (allowedFields.includes(dbKey)) {
      setClause.push(`${dbKey} = ?`);
      if (dbKey === 'source_filter' && Array.isArray(value)) {
        values.push(JSON.stringify(value));
      } else {
        values.push(value);
      }
    }
  }

  if (setClause.length === 0) {
    console.error('No valid fields to update');
    return null;
  }

  values.push(alertId);

  try {
    db.prepare(`
      UPDATE news_alerts SET ${setClause.join(', ')} WHERE id = ?
    `).run(...values);

    const alert = db.prepare('SELECT * FROM news_alerts WHERE id = ?').get(alertId);
    if (alert) {
      alert.sourceFilter = alert.source_filter ? JSON.parse(alert.source_filter) : null;
    }
    return alert;
  } catch (err) {
    console.error(`Failed to update alert ${alertId}:`, err.message);
    return null;
  }
}

/**
 * Delete an alert
 * @param {Database} db - better-sqlite3 database instance
 * @param {number} alertId - Alert ID
 * @returns {boolean} Success status
 */
function deleteAlert(db, alertId) {
  try {
    const result = db.prepare('DELETE FROM news_alerts WHERE id = ?').run(alertId);
    return result.changes > 0;
  } catch (err) {
    console.error(`Failed to delete alert ${alertId}:`, err.message);
    return false;
  }
}

/**
 * Check all active alerts and fetch matching news
 * @param {Database} db - better-sqlite3 database instance
 * @param {string} [apiKey] - NewsAPI key
 * @returns {Promise<Object>} Results summary
 */
async function checkAlerts(db, apiKey) {
  const alerts = db.prepare(`
    SELECT * FROM news_alerts WHERE enabled = 1
  `).all();

  if (alerts.length === 0) {
    return { checked: 0, newItems: 0, errors: [] };
  }

  const results = {
    checked: alerts.length,
    newItems: 0,
    errors: []
  };

  const updateLastChecked = db.prepare(`
    UPDATE news_alerts SET last_checked = ? WHERE id = ?
  `);

  for (const alert of alerts) {
    try {
      const items = await fetchNews([alert.keyword], apiKey);

      // Filter by source if specified
      let filteredItems = items;
      if (alert.source_filter) {
        const allowedSources = JSON.parse(alert.source_filter);
        filteredItems = items.filter(item =>
          allowedSources.some(src =>
            item.source?.toLowerCase().includes(src.toLowerCase())
          )
        );
      }

      // Calculate relevance and assign category
      const scoredItems = filteredItems.map(item => ({
        ...item,
        relevanceScore: calculateRelevanceScore(item, [alert.keyword]),
        category: alert.category || 'general'
      }));

      const { cached } = cacheNewsItems(db, scoredItems);
      results.newItems += cached;

      // Update last checked timestamp
      updateLastChecked.run(formatDateForDb(new Date()), alert.id);
    } catch (err) {
      results.errors.push({ alertId: alert.id, keyword: alert.keyword, error: err.message });
    }
  }

  return results;
}

// ============================================================================
// Relevance Scoring
// ============================================================================

/**
 * Calculate relevance score for a news item
 * @param {Object} newsItem - News item to score
 * @param {string[]} keywords - Keywords to match against
 * @returns {number} Score between 0 and 1
 */
function calculateRelevanceScore(newsItem, keywords) {
  if (!keywords || keywords.length === 0) return 0;

  const titleLower = (newsItem.title || '').toLowerCase();
  const summaryLower = (newsItem.summary || '').toLowerCase();
  const sourceLower = (newsItem.source || '').toLowerCase();

  let score = 0;
  let maxPossible = keywords.length * 3; // 3 fields to check

  for (const keyword of keywords) {
    const keywordLower = keyword.toLowerCase();
    const keywordWords = keywordLower.split(/\s+/);

    // Title match (highest weight)
    if (titleLower.includes(keywordLower)) {
      score += 1.0;
    } else if (keywordWords.some(w => titleLower.includes(w))) {
      score += 0.5;
    }

    // Summary match (medium weight)
    if (summaryLower.includes(keywordLower)) {
      score += 0.6;
    } else if (keywordWords.some(w => summaryLower.includes(w))) {
      score += 0.3;
    }

    // Source match (lower weight)
    if (sourceLower.includes(keywordLower)) {
      score += 0.4;
    }
  }

  // Normalize to 0-1 range
  return Math.min(1, score / maxPossible);
}

// ============================================================================
// Briefing Generation
// ============================================================================

/**
 * Generate comprehensive daily news digest
 * @param {Database} db - better-sqlite3 database instance
 * @param {string} [apiKey] - NewsAPI key for fresh fetch
 * @returns {Promise<Object>} Daily digest
 */
async function generateDailyDigest(db, apiKey) {
  // First, check alerts and fetch fresh news
  const alertResults = await checkAlerts(db, apiKey);

  // Get digest for last 24 hours
  const digest = getNewsDigest(db, 24);

  // Add alert check results
  digest.alertResults = alertResults;
  digest.generatedAt = getPortugalNow().toISOString();

  // Generate category summaries
  digest.categorySummaries = {};
  for (const [category, items] of Object.entries(digest.byCategory)) {
    digest.categorySummaries[category] = {
      count: items.length,
      topItem: items[0] ? summarizeNewsItem(items[0]) : null,
      unread: items.filter(i => !i.read).length
    };
  }

  return digest;
}

/**
 * Generate briefing for specific category
 * @param {Database} db - better-sqlite3 database instance
 * @param {string} category - Category to brief on
 * @returns {Object} Category briefing
 */
function generateCategoryBriefing(db, category) {
  const items = getNewsByCategory(db, category, 20);
  const starred = items.filter(i => i.starred);
  const unread = items.filter(i => !i.read);

  return {
    category,
    emoji: getCategoryEmoji(category),
    totalItems: items.length,
    unreadCount: unread.length,
    starredCount: starred.length,
    items: items.slice(0, 10),
    topStories: items.slice(0, 3).map(summarizeNewsItem),
    generatedAt: getPortugalNow().toISOString()
  };
}

/**
 * Generate one-line summary of a news item
 * @param {Object} newsItem - News item to summarize
 * @returns {string} One-line summary
 */
function summarizeNewsItem(newsItem) {
  if (!newsItem) return '';

  const source = newsItem.source ? `[${newsItem.source}]` : '';
  const title = newsItem.title || 'Untitled';
  const truncatedTitle = title.length > 80 ? title.substring(0, 77) + '...' : title;

  return `${source} ${truncatedTitle}`.trim();
}

// ============================================================================
// Display Formatting
// ============================================================================

/**
 * Get emoji for a category
 * @param {string} category - Category name
 * @returns {string} Emoji for category
 */
function getCategoryEmoji(category) {
  return CATEGORY_EMOJIS[category] || CATEGORY_EMOJIS.general;
}

/**
 * Format news items for Telegram HTML display
 * @param {Object[]} items - News items to format
 * @returns {string} HTML formatted string
 */
function formatNewsForDisplay(items) {
  if (!items || items.length === 0) {
    return '<i>No news items to display</i>';
  }

  const lines = items.map((item, index) => {
    const emoji = getCategoryEmoji(item.category);
    const starIcon = item.starred ? '⭐ ' : '';
    const readIcon = item.read ? '' : '🔵 ';
    const title = escapeHtml(item.title || 'Untitled');
    const source = item.source ? `<i>${escapeHtml(item.source)}</i>` : '';
    const date = formatDateForDisplay(item.published_at || item.publishedAt);

    let line = `${index + 1}. ${readIcon}${starIcon}${emoji} <b>${title}</b>`;
    if (source) line += `\n   ${source}`;
    if (item.url) line += `\n   <a href="${item.url}">Read more</a>`;
    line += `\n   <code>${date}</code>`;

    return line;
  });

  return lines.join('\n\n');
}

/**
 * Format digest for Telegram HTML display
 * @param {Object} digest - Digest object
 * @returns {string} HTML formatted string
 */
function formatDigestForDisplay(digest) {
  const lines = [];

  lines.push(`<b>📰 News Digest</b>`);
  lines.push(`<i>${digest.period}</i>\n`);

  lines.push(`📊 <b>Summary:</b>`);
  lines.push(`   • Total items: ${digest.totalItems}`);
  lines.push(`   • Unread: ${digest.unreadCount}\n`);

  // Category breakdown
  if (Object.keys(digest.byCategory).length > 0) {
    lines.push(`<b>By Category:</b>`);
    for (const [category, items] of Object.entries(digest.byCategory)) {
      const emoji = getCategoryEmoji(category);
      const unread = items.filter(i => !i.read).length;
      lines.push(`   ${emoji} ${capitalizeFirst(category)}: ${items.length} (${unread} unread)`);
    }
    lines.push('');
  }

  // Top stories
  if (digest.topStories && digest.topStories.length > 0) {
    lines.push(`<b>🔝 Top Stories:</b>`);
    digest.topStories.forEach((item, i) => {
      const summary = summarizeNewsItem(item);
      lines.push(`   ${i + 1}. ${summary}`);
    });
  }

  return lines.join('\n');
}

/**
 * Escape HTML special characters
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Capitalize first letter of string
 * @param {string} str - String to capitalize
 * @returns {string} Capitalized string
 */
function capitalizeFirst(str) {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1);
}

// ============================================================================
// Module Exports
// ============================================================================

module.exports = {
  // Constants
  DEFAULT_ALERTS,
  CATEGORY_EMOJIS,
  TIMEZONE,

  // Database
  initTables,

  // News fetching
  fetchNews,
  generateMockNews,

  // News caching
  cacheNewsItems,
  deduplicateNews,

  // News retrieval
  getUnreadNews,
  getNewsByCategory,
  getStarredNews,
  markAsRead,
  toggleStar,
  searchNews,
  getNewsDigest,

  // Alerts
  addAlert,
  getAlerts,
  updateAlert,
  deleteAlert,
  checkAlerts,

  // Relevance
  calculateRelevanceScore,

  // Briefings
  generateDailyDigest,
  generateCategoryBriefing,
  summarizeNewsItem,

  // Display
  formatNewsForDisplay,
  formatDigestForDisplay,
  getCategoryEmoji,

  // Utilities
  formatDateForDb,
  formatDateForDisplay,
  escapeHtml,
  getPortugalNow
};
