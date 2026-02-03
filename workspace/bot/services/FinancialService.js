/**
 * FinancialService.js
 *
 * Financial monitoring service for executive dashboard.
 * Handles stock quotes, price alerts, and SEC filing monitoring
 * for ATON (NASDAQ: ATON) and competitor analysis.
 */

const https = require('https');

// Default watched symbols
const DEFAULT_SYMBOLS = ['ATON'];  // AlphaTON Capital
const COMPETITOR_SYMBOLS = ['COIN', 'MARA', 'RIOT', 'MSTR'];  // Crypto-related public companies

// SEC filing type descriptions
const FILING_TYPE_DESCRIPTIONS = {
  '8-K': 'Current Report (Material Event)',
  '10-Q': 'Quarterly Report',
  '10-K': 'Annual Report',
  '4': 'Insider Trading Report',
  'S-1': 'Registration Statement',
  'S-3': 'Shelf Registration',
  'DEF 14A': 'Proxy Statement',
  '13F': 'Institutional Holdings',
  'SC 13D': 'Beneficial Ownership (>5%)',
  'SC 13G': 'Passive Beneficial Ownership',
  '144': 'Notice of Proposed Sale'
};

/**
 * Initialize database tables for financial monitoring
 * @param {Object} db - SQLite database instance
 * @returns {Promise<void>}
 */
async function initTables(db) {
  const tables = [
    `CREATE TABLE IF NOT EXISTS financial_alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      symbol TEXT NOT NULL,
      alert_type TEXT NOT NULL,
      threshold REAL,
      triggered BOOLEAN DEFAULT 0,
      triggered_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS stock_prices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      symbol TEXT NOT NULL,
      price REAL NOT NULL,
      change_percent REAL,
      volume INTEGER,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS sec_filings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      symbol TEXT NOT NULL,
      filing_type TEXT NOT NULL,
      title TEXT,
      url TEXT,
      filed_date DATE,
      notified BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
  ];

  // Create indexes for performance
  const indexes = [
    'CREATE INDEX IF NOT EXISTS idx_alerts_symbol ON financial_alerts(symbol)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_triggered ON financial_alerts(triggered)',
    'CREATE INDEX IF NOT EXISTS idx_prices_symbol ON stock_prices(symbol)',
    'CREATE INDEX IF NOT EXISTS idx_prices_timestamp ON stock_prices(timestamp)',
    'CREATE INDEX IF NOT EXISTS idx_filings_symbol ON sec_filings(symbol)',
    'CREATE INDEX IF NOT EXISTS idx_filings_notified ON sec_filings(notified)'
  ];

  return new Promise((resolve, reject) => {
    db.serialize(() => {
      for (const sql of [...tables, ...indexes]) {
        db.run(sql, (err) => {
          if (err) {
            console.error('Error creating table/index:', err.message);
          }
        });
      }
      resolve();
    });
  });
}

/**
 * Fetch current stock quote from Alpha Vantage API
 * @param {string} symbol - Stock symbol
 * @param {string} [apiKey] - Alpha Vantage API key (optional, uses env var if not provided)
 * @returns {Promise<Object>} Quote data
 */
async function getStockQuote(symbol, apiKey = null) {
  const key = apiKey || process.env.ALPHA_VANTAGE_API_KEY;

  if (!key) {
    // Return cached/mock data if no API key
    return {
      symbol: symbol.toUpperCase(),
      price: null,
      change: null,
      changePercent: null,
      volume: null,
      latestTradingDay: null,
      error: 'No API key configured - using cached data only'
    };
  }

  const url = `https://www.alphavantage.co/query?function=GLOBAL_QUOTE&symbol=${encodeURIComponent(symbol)}&apikey=${key}`;

  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);

          // Check for API errors
          if (parsed.Note) {
            resolve({
              symbol: symbol.toUpperCase(),
              price: null,
              error: 'API rate limit exceeded'
            });
            return;
          }

          if (parsed['Error Message']) {
            resolve({
              symbol: symbol.toUpperCase(),
              price: null,
              error: parsed['Error Message']
            });
            return;
          }

          const quote = parsed['Global Quote'];
          if (!quote || Object.keys(quote).length === 0) {
            resolve({
              symbol: symbol.toUpperCase(),
              price: null,
              error: 'No data available'
            });
            return;
          }

          resolve({
            symbol: quote['01. symbol'],
            price: parseFloat(quote['05. price']),
            change: parseFloat(quote['09. change']),
            changePercent: parseFloat(quote['10. change percent']?.replace('%', '')),
            volume: parseInt(quote['06. volume'], 10),
            latestTradingDay: quote['07. latest trading day'],
            open: parseFloat(quote['02. open']),
            high: parseFloat(quote['03. high']),
            low: parseFloat(quote['04. low']),
            previousClose: parseFloat(quote['08. previous close'])
          });
        } catch (error) {
          reject(new Error(`Failed to parse quote data: ${error.message}`));
        }
      });
    }).on('error', (error) => {
      reject(new Error(`Failed to fetch quote: ${error.message}`));
    });
  });
}

/**
 * Cache a stock price in the database
 * @param {Object} db - SQLite database instance
 * @param {string} symbol - Stock symbol
 * @param {number} price - Current price
 * @param {number} changePercent - Percent change
 * @param {number} volume - Trading volume
 * @returns {Promise<number>} Inserted row ID
 */
function cacheStockPrice(db, symbol, price, changePercent, volume) {
  return new Promise((resolve, reject) => {
    const sql = `INSERT INTO stock_prices (symbol, price, change_percent, volume) VALUES (?, ?, ?, ?)`;
    db.run(sql, [symbol.toUpperCase(), price, changePercent, volume], function(err) {
      if (err) {
        reject(new Error(`Failed to cache stock price: ${err.message}`));
      } else {
        resolve(this.lastID);
      }
    });
  });
}

/**
 * Get the most recent cached price for a symbol
 * @param {Object} db - SQLite database instance
 * @param {string} symbol - Stock symbol
 * @returns {Promise<Object|null>} Latest price data or null
 */
function getLatestPrice(db, symbol) {
  return new Promise((resolve, reject) => {
    const sql = `SELECT * FROM stock_prices WHERE symbol = ? ORDER BY timestamp DESC LIMIT 1`;
    db.get(sql, [symbol.toUpperCase()], (err, row) => {
      if (err) {
        reject(new Error(`Failed to get latest price: ${err.message}`));
      } else {
        resolve(row || null);
      }
    });
  });
}

/**
 * Add a new price or filing alert
 * @param {Object} db - SQLite database instance
 * @param {Object} options - Alert options
 * @param {string} options.symbol - Stock symbol
 * @param {string} options.alertType - Alert type (price_above, price_below, filing, earnings)
 * @param {number} [options.threshold] - Price threshold (for price alerts)
 * @returns {Promise<number>} Inserted alert ID
 */
function addAlert(db, { symbol, alertType, threshold }) {
  return new Promise((resolve, reject) => {
    const validTypes = ['price_above', 'price_below', 'filing', 'earnings'];
    if (!validTypes.includes(alertType)) {
      reject(new Error(`Invalid alert type: ${alertType}. Must be one of: ${validTypes.join(', ')}`));
      return;
    }

    if ((alertType === 'price_above' || alertType === 'price_below') && threshold == null) {
      reject(new Error('Price alerts require a threshold value'));
      return;
    }

    const sql = `INSERT INTO financial_alerts (symbol, alert_type, threshold) VALUES (?, ?, ?)`;
    db.run(sql, [symbol.toUpperCase(), alertType, threshold], function(err) {
      if (err) {
        reject(new Error(`Failed to add alert: ${err.message}`));
      } else {
        resolve(this.lastID);
      }
    });
  });
}

/**
 * Get all alerts for a symbol
 * @param {Object} db - SQLite database instance
 * @param {string} [symbol] - Stock symbol (optional, returns all if not provided)
 * @returns {Promise<Array>} Array of alerts
 */
function getAlerts(db, symbol = null) {
  return new Promise((resolve, reject) => {
    let sql = 'SELECT * FROM financial_alerts WHERE triggered = 0';
    const params = [];

    if (symbol) {
      sql += ' AND symbol = ?';
      params.push(symbol.toUpperCase());
    }

    sql += ' ORDER BY created_at DESC';

    db.all(sql, params, (err, rows) => {
      if (err) {
        reject(new Error(`Failed to get alerts: ${err.message}`));
      } else {
        resolve(rows || []);
      }
    });
  });
}

/**
 * Check if any alerts should fire based on current price
 * @param {Object} db - SQLite database instance
 * @param {string} symbol - Stock symbol
 * @param {number} currentPrice - Current stock price
 * @returns {Promise<Array>} Array of triggered alerts
 */
function checkAlerts(db, symbol, currentPrice) {
  return new Promise((resolve, reject) => {
    const sql = `
      SELECT * FROM financial_alerts
      WHERE symbol = ?
        AND triggered = 0
        AND alert_type IN ('price_above', 'price_below')
    `;

    db.all(sql, [symbol.toUpperCase()], (err, rows) => {
      if (err) {
        reject(new Error(`Failed to check alerts: ${err.message}`));
        return;
      }

      const triggeredAlerts = (rows || []).filter(alert => {
        if (alert.alert_type === 'price_above' && currentPrice >= alert.threshold) {
          return true;
        }
        if (alert.alert_type === 'price_below' && currentPrice <= alert.threshold) {
          return true;
        }
        return false;
      });

      resolve(triggeredAlerts);
    });
  });
}

/**
 * Mark an alert as triggered
 * @param {Object} db - SQLite database instance
 * @param {number} alertId - Alert ID to mark as triggered
 * @returns {Promise<void>}
 */
function markAlertTriggered(db, alertId) {
  return new Promise((resolve, reject) => {
    const sql = `UPDATE financial_alerts SET triggered = 1, triggered_at = CURRENT_TIMESTAMP WHERE id = ?`;
    db.run(sql, [alertId], function(err) {
      if (err) {
        reject(new Error(`Failed to mark alert triggered: ${err.message}`));
      } else if (this.changes === 0) {
        reject(new Error(`Alert not found: ${alertId}`));
      } else {
        resolve();
      }
    });
  });
}

/**
 * Delete an alert
 * @param {Object} db - SQLite database instance
 * @param {number} alertId - Alert ID to delete
 * @returns {Promise<void>}
 */
function deleteAlert(db, alertId) {
  return new Promise((resolve, reject) => {
    const sql = `DELETE FROM financial_alerts WHERE id = ?`;
    db.run(sql, [alertId], function(err) {
      if (err) {
        reject(new Error(`Failed to delete alert: ${err.message}`));
      } else if (this.changes === 0) {
        reject(new Error(`Alert not found: ${alertId}`));
      } else {
        resolve();
      }
    });
  });
}

/**
 * Check for new SEC filings for a symbol
 * Mock implementation - ready for SEC EDGAR API integration
 * @param {string} symbol - Stock symbol
 * @returns {Promise<Array>} Array of filings
 */
async function checkSECFilings(symbol) {
  // TODO: Implement real SEC EDGAR API integration
  // SEC EDGAR API: https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={CIK}&type=&dateb=&owner=include&count=10&output=atom

  // For now, return empty array - production implementation would:
  // 1. Look up CIK from symbol
  // 2. Query SEC EDGAR API
  // 3. Parse and return recent filings

  console.log(`[FinancialService] Checking SEC filings for ${symbol} (mock)`);

  return [];
}

/**
 * Cache SEC filings in the database
 * @param {Object} db - SQLite database instance
 * @param {Array} filings - Array of filing objects
 * @returns {Promise<number>} Number of filings cached
 */
function cacheFilings(db, filings) {
  return new Promise((resolve, reject) => {
    if (!filings || filings.length === 0) {
      resolve(0);
      return;
    }

    let cached = 0;
    const sql = `
      INSERT OR IGNORE INTO sec_filings (symbol, filing_type, title, url, filed_date)
      VALUES (?, ?, ?, ?, ?)
    `;

    db.serialize(() => {
      for (const filing of filings) {
        db.run(sql, [
          filing.symbol?.toUpperCase(),
          filing.filingType,
          filing.title,
          filing.url,
          filing.filedDate
        ], function(err) {
          if (!err && this.changes > 0) {
            cached++;
          }
        });
      }

      // Use a callback to resolve after all inserts
      db.run('SELECT 1', [], () => {
        resolve(cached);
      });
    });
  });
}

/**
 * Get filings that have not been notified
 * @param {Object} db - SQLite database instance
 * @returns {Promise<Array>} Array of unnotified filings
 */
function getUnnotifiedFilings(db) {
  return new Promise((resolve, reject) => {
    const sql = `SELECT * FROM sec_filings WHERE notified = 0 ORDER BY filed_date DESC`;
    db.all(sql, [], (err, rows) => {
      if (err) {
        reject(new Error(`Failed to get unnotified filings: ${err.message}`));
      } else {
        resolve(rows || []);
      }
    });
  });
}

/**
 * Mark a filing as notified
 * @param {Object} db - SQLite database instance
 * @param {number} filingId - Filing ID to mark as notified
 * @returns {Promise<void>}
 */
function markFilingNotified(db, filingId) {
  return new Promise((resolve, reject) => {
    const sql = `UPDATE sec_filings SET notified = 1 WHERE id = ?`;
    db.run(sql, [filingId], function(err) {
      if (err) {
        reject(new Error(`Failed to mark filing notified: ${err.message}`));
      } else if (this.changes === 0) {
        reject(new Error(`Filing not found: ${filingId}`));
      } else {
        resolve();
      }
    });
  });
}

/**
 * Format a price with $ and 2 decimal places
 * @param {number} price - Price to format
 * @returns {string} Formatted price
 */
function formatPrice(price) {
  if (price == null || isNaN(price)) {
    return 'N/A';
  }
  return `$${price.toFixed(2)}`;
}

/**
 * Format percent change with color indicator
 * @param {number} change - Percent change
 * @returns {string} Formatted change with emoji
 */
function formatPercentChange(change) {
  if (change == null || isNaN(change)) {
    return 'N/A';
  }
  const sign = change >= 0 ? '+' : '';
  const emoji = change >= 0 ? '📈' : '📉';
  return `${emoji} ${sign}${change.toFixed(2)}%`;
}

/**
 * Get human-readable description for SEC filing type
 * @param {string} type - Filing type code
 * @returns {string} Description
 */
function getFilingTypeDescription(type) {
  return FILING_TYPE_DESCRIPTIONS[type] || type;
}

/**
 * Format stock quote for Telegram HTML display
 * @param {Object} quote - Quote object from getStockQuote
 * @returns {string} Formatted HTML string
 */
function formatQuoteForDisplay(quote) {
  if (!quote || quote.error) {
    return `<b>${quote?.symbol || 'Unknown'}</b>\n<i>${quote?.error || 'Data unavailable'}</i>`;
  }

  const changeEmoji = quote.changePercent >= 0 ? '📈' : '📉';
  const changeSign = quote.changePercent >= 0 ? '+' : '';

  let html = `<b>${quote.symbol}</b>\n`;
  html += `Price: <b>${formatPrice(quote.price)}</b>\n`;
  html += `Change: ${changeEmoji} ${changeSign}${quote.change?.toFixed(2)} (${changeSign}${quote.changePercent?.toFixed(2)}%)\n`;

  if (quote.volume) {
    html += `Volume: ${quote.volume.toLocaleString()}\n`;
  }

  if (quote.latestTradingDay) {
    html += `<i>As of ${quote.latestTradingDay}</i>`;
  }

  return html;
}

/**
 * Format SEC filings for display
 * @param {Array} filings - Array of filing objects
 * @returns {string} Formatted string
 */
function formatFilingsForDisplay(filings) {
  if (!filings || filings.length === 0) {
    return 'No recent filings';
  }

  return filings.map(filing => {
    const typeDesc = getFilingTypeDescription(filing.filing_type);
    let text = `<b>${filing.symbol}</b> - ${filing.filing_type}\n`;
    text += `${typeDesc}\n`;
    if (filing.title) {
      text += `${filing.title}\n`;
    }
    if (filing.filed_date) {
      text += `Filed: ${filing.filed_date}\n`;
    }
    if (filing.url) {
      text += `<a href="${filing.url}">View Filing</a>`;
    }
    return text;
  }).join('\n\n');
}

/**
 * Generate a market briefing for watched symbols
 * @param {Object} db - SQLite database instance
 * @param {Array} [symbols] - Symbols to include (defaults to DEFAULT_SYMBOLS + COMPETITOR_SYMBOLS)
 * @param {string} [apiKey] - Alpha Vantage API key
 * @returns {Promise<string>} Formatted briefing
 */
async function generateMarketBriefing(db, symbols = null, apiKey = null) {
  const watchList = symbols || [...DEFAULT_SYMBOLS, ...COMPETITOR_SYMBOLS];
  const briefingDate = new Date().toLocaleDateString('en-US', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });

  let briefing = `<b>Market Briefing</b>\n`;
  briefing += `<i>${briefingDate}</i>\n\n`;

  // Primary holdings section
  briefing += `<b>Primary Holdings</b>\n`;
  briefing += `${'─'.repeat(20)}\n`;

  for (const symbol of DEFAULT_SYMBOLS) {
    try {
      let quote = await getStockQuote(symbol, apiKey);

      // If API failed, try to get cached data
      if (quote.error) {
        const cached = await getLatestPrice(db, symbol);
        if (cached) {
          quote = {
            symbol: cached.symbol,
            price: cached.price,
            changePercent: cached.change_percent,
            volume: cached.volume,
            cached: true
          };
        }
      } else {
        // Cache successful quote
        await cacheStockPrice(db, quote.symbol, quote.price, quote.changePercent, quote.volume);
      }

      briefing += formatQuoteForDisplay(quote);
      if (quote.cached) {
        briefing += '\n<i>(Cached data)</i>';
      }
      briefing += '\n\n';

      // Check for alerts
      const triggeredAlerts = await checkAlerts(db, symbol, quote.price);
      if (triggeredAlerts.length > 0) {
        briefing += `⚠️ <b>ALERTS TRIGGERED:</b>\n`;
        for (const alert of triggeredAlerts) {
          briefing += `  • ${alert.alert_type}: ${formatPrice(alert.threshold)}\n`;
          await markAlertTriggered(db, alert.id);
        }
        briefing += '\n';
      }
    } catch (error) {
      briefing += `<b>${symbol}</b>\n<i>Error: ${error.message}</i>\n\n`;
    }
  }

  // Competitor section
  if (COMPETITOR_SYMBOLS.length > 0) {
    briefing += `\n<b>Sector Comparison</b>\n`;
    briefing += `${'─'.repeat(20)}\n`;

    for (const symbol of COMPETITOR_SYMBOLS) {
      try {
        let quote = await getStockQuote(symbol, apiKey);

        if (quote.error) {
          const cached = await getLatestPrice(db, symbol);
          if (cached) {
            quote = {
              symbol: cached.symbol,
              price: cached.price,
              changePercent: cached.change_percent,
              cached: true
            };
          }
        } else {
          await cacheStockPrice(db, quote.symbol, quote.price, quote.changePercent, quote.volume);
        }

        // Compact format for competitors
        if (quote.price) {
          const changeStr = formatPercentChange(quote.changePercent);
          briefing += `${quote.symbol}: ${formatPrice(quote.price)} ${changeStr}`;
          if (quote.cached) {
            briefing += ' (cached)';
          }
          briefing += '\n';
        } else {
          briefing += `${symbol}: Data unavailable\n`;
        }
      } catch (error) {
        briefing += `${symbol}: Error\n`;
      }
    }
  }

  // Check for unnotified SEC filings
  const filings = await getUnnotifiedFilings(db);
  if (filings.length > 0) {
    briefing += `\n\n<b>New SEC Filings</b>\n`;
    briefing += `${'─'.repeat(20)}\n`;
    briefing += formatFilingsForDisplay(filings);
  }

  return briefing;
}

module.exports = {
  // Constants
  DEFAULT_SYMBOLS,
  COMPETITOR_SYMBOLS,
  FILING_TYPE_DESCRIPTIONS,

  // Database initialization
  initTables,

  // Stock quotes
  getStockQuote,
  cacheStockPrice,
  getLatestPrice,

  // Alerts
  addAlert,
  getAlerts,
  checkAlerts,
  markAlertTriggered,
  deleteAlert,

  // SEC filings
  checkSECFilings,
  cacheFilings,
  getUnnotifiedFilings,
  markFilingNotified,

  // Formatting helpers
  formatPrice,
  formatPercentChange,
  getFilingTypeDescription,
  formatQuoteForDisplay,
  formatFilingsForDisplay,

  // Briefing
  generateMarketBriefing
};
