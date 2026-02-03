/**
 * ExpenseService.js - Expense management for executive assistant bot
 *
 * Handles expense tracking, reports, budgets, and analytics
 * Uses Portugal timezone (WET/WEST) for all date calculations
 */

// Portugal timezone
const TIMEZONE = 'Europe/Lisbon';

// Valid expense categories
const VALID_CATEGORIES = ['travel', 'meals', 'supplies', 'software', 'equipment', 'other'];

// Default budget limits per category
const DEFAULT_BUDGETS = [
  { category: 'travel', monthlyLimit: 5000 },
  { category: 'meals', monthlyLimit: 500 },
  { category: 'supplies', monthlyLimit: 200 },
  { category: 'software', monthlyLimit: 1000 },
  { category: 'equipment', monthlyLimit: 2000 },
  { category: 'other', monthlyLimit: 500 }
];

// Currency symbols
const CURRENCY_SYMBOLS = {
  USD: '$',
  EUR: '\u20AC',
  GBP: '\u00A3',
  JPY: '\u00A5',
  CNY: '\u00A5',
  BTC: '\u20BF'
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
 * Format a date for SQLite storage (YYYY-MM-DD)
 * @param {Date|string} date
 * @returns {string}
 */
function formatDateForDb(date) {
  if (!date) return null;
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toISOString().split('T')[0];
}

/**
 * Get start of current month in Portugal timezone
 * @param {Date} date
 * @returns {string} YYYY-MM-DD format
 */
function getStartOfMonthPortugal(date = new Date()) {
  const ptString = date.toLocaleString('en-US', {
    timeZone: TIMEZONE,
    year: 'numeric',
    month: '2-digit'
  });
  const [month, , year] = ptString.split('/');
  return `${year}-${month}-01`;
}

/**
 * Get end of current month in Portugal timezone
 * @param {Date} date
 * @returns {string} YYYY-MM-DD format
 */
function getEndOfMonthPortugal(date = new Date()) {
  const ptString = date.toLocaleString('en-US', {
    timeZone: TIMEZONE,
    year: 'numeric',
    month: '2-digit'
  });
  const [month, , year] = ptString.split('/');
  const lastDay = new Date(parseInt(year), parseInt(month), 0).getDate();
  return `${year}-${month}-${String(lastDay).padStart(2, '0')}`;
}

/**
 * Escape HTML special characters for Telegram
 * @param {string} text
 * @returns {string}
 */
function escapeHtml(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// ============================================================================
// DATABASE INITIALIZATION
// ============================================================================

/**
 * Initialize database tables for expenses, reports, and budgets
 * @param {Database} db - better-sqlite3 database instance
 */
function initTables(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS expenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      amount REAL NOT NULL,
      currency TEXT DEFAULT 'USD',
      category TEXT NOT NULL,
      description TEXT,
      vendor TEXT,
      receipt_path TEXT,
      date DATE NOT NULL,
      report_id INTEGER,
      reimbursed BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (report_id) REFERENCES expense_reports(id)
    );

    CREATE TABLE IF NOT EXISTS expense_reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      period_start DATE NOT NULL,
      period_end DATE NOT NULL,
      total REAL DEFAULT 0,
      currency TEXT DEFAULT 'USD',
      status TEXT DEFAULT 'draft',
      submitted_at DATETIME,
      approved_at DATETIME,
      notes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS expense_budgets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      category TEXT NOT NULL UNIQUE,
      monthly_limit REAL NOT NULL,
      currency TEXT DEFAULT 'USD',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_expenses_date ON expenses(date);
    CREATE INDEX IF NOT EXISTS idx_expenses_category ON expenses(category);
    CREATE INDEX IF NOT EXISTS idx_expenses_report_id ON expenses(report_id);
    CREATE INDEX IF NOT EXISTS idx_expenses_reimbursed ON expenses(reimbursed);
    CREATE INDEX IF NOT EXISTS idx_expense_reports_status ON expense_reports(status);
    CREATE INDEX IF NOT EXISTS idx_expense_budgets_category ON expense_budgets(category);
  `);

  // Initialize default budgets if none exist
  const budgetCount = db.prepare('SELECT COUNT(*) as count FROM expense_budgets').get();
  if (budgetCount.count === 0) {
    const insertBudget = db.prepare(`
      INSERT INTO expense_budgets (category, monthly_limit, currency)
      VALUES (?, ?, 'USD')
    `);

    for (const budget of DEFAULT_BUDGETS) {
      insertBudget.run(budget.category, budget.monthlyLimit);
    }
  }
}

// ============================================================================
// CORE EXPENSE FUNCTIONS
// ============================================================================

/**
 * Add a new expense
 * @param {Database} db
 * @param {Object} params
 * @param {number} params.amount - Expense amount (required)
 * @param {string} [params.currency='USD'] - Currency code
 * @param {string} params.category - Expense category (required)
 * @param {string} [params.description] - Description
 * @param {string} [params.vendor] - Vendor name
 * @param {string} [params.receiptPath] - Path to receipt file
 * @param {Date|string} params.date - Expense date (required)
 * @returns {Object} Created expense with id
 */
function addExpense(db, { amount, currency = 'USD', category, description, vendor, receiptPath, date }) {
  if (amount === undefined || amount === null || isNaN(parseFloat(amount))) {
    throw new Error('Valid expense amount is required');
  }

  if (!category || typeof category !== 'string') {
    throw new Error('Expense category is required');
  }

  const normalizedCategory = category.toLowerCase().trim();
  if (!VALID_CATEGORIES.includes(normalizedCategory)) {
    throw new Error(`Invalid category. Must be one of: ${VALID_CATEGORIES.join(', ')}`);
  }

  if (!date) {
    throw new Error('Expense date is required');
  }

  const stmt = db.prepare(`
    INSERT INTO expenses (amount, currency, category, description, vendor, receipt_path, date)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  const result = stmt.run(
    parseFloat(amount),
    currency.toUpperCase(),
    normalizedCategory,
    description || null,
    vendor || null,
    receiptPath || null,
    formatDateForDb(date)
  );

  return getExpense(db, result.lastInsertRowid);
}

/**
 * Get a single expense by ID
 * @param {Database} db
 * @param {number} expenseId
 * @returns {Object|null} Expense object or null if not found
 */
function getExpense(db, expenseId) {
  const stmt = db.prepare('SELECT * FROM expenses WHERE id = ?');
  return stmt.get(expenseId) || null;
}

/**
 * Get expenses with optional filters
 * @param {Database} db
 * @param {Object} [filters={}]
 * @param {string} [filters.startDate] - Filter by start date
 * @param {string} [filters.endDate] - Filter by end date
 * @param {string} [filters.category] - Filter by category
 * @param {number} [filters.reportId] - Filter by report ID
 * @param {number} [filters.limit=100] - Maximum number of expenses to return
 * @returns {Array} Array of expense objects
 */
function getExpenses(db, { startDate, endDate, category, reportId, limit = 100 } = {}) {
  let query = 'SELECT * FROM expenses WHERE 1=1';
  const params = [];

  if (startDate) {
    query += ' AND date >= ?';
    params.push(formatDateForDb(startDate));
  }

  if (endDate) {
    query += ' AND date <= ?';
    params.push(formatDateForDb(endDate));
  }

  if (category) {
    query += ' AND category = ?';
    params.push(category.toLowerCase());
  }

  if (reportId !== undefined) {
    query += ' AND report_id = ?';
    params.push(reportId);
  }

  query += ' ORDER BY date DESC, created_at DESC';
  query += ' LIMIT ?';
  params.push(limit);

  const stmt = db.prepare(query);
  return stmt.all(...params);
}

/**
 * Get expenses not assigned to any report
 * @param {Database} db
 * @returns {Array} Array of unreported expense objects
 */
function getUnreportedExpenses(db) {
  const stmt = db.prepare(`
    SELECT * FROM expenses
    WHERE report_id IS NULL
    ORDER BY date DESC, created_at DESC
  `);
  return stmt.all();
}

/**
 * Update an expense
 * @param {Database} db
 * @param {number} expenseId
 * @param {Object} updates - Fields to update
 * @returns {Object} Updated expense
 */
function updateExpense(db, expenseId, updates) {
  const expense = getExpense(db, expenseId);
  if (!expense) {
    throw new Error(`Expense with ID ${expenseId} not found`);
  }

  const allowedFields = ['amount', 'currency', 'category', 'description', 'vendor', 'receipt_path', 'date'];
  const updateParts = [];
  const params = [];

  for (const [key, value] of Object.entries(updates)) {
    const dbKey = key === 'receiptPath' ? 'receipt_path' : key;
    if (allowedFields.includes(dbKey)) {
      if (dbKey === 'category') {
        const normalizedCategory = value.toLowerCase().trim();
        if (!VALID_CATEGORIES.includes(normalizedCategory)) {
          throw new Error(`Invalid category. Must be one of: ${VALID_CATEGORIES.join(', ')}`);
        }
        updateParts.push(`${dbKey} = ?`);
        params.push(normalizedCategory);
      } else if (dbKey === 'date') {
        updateParts.push(`${dbKey} = ?`);
        params.push(formatDateForDb(value));
      } else if (dbKey === 'amount') {
        updateParts.push(`${dbKey} = ?`);
        params.push(parseFloat(value));
      } else if (dbKey === 'currency') {
        updateParts.push(`${dbKey} = ?`);
        params.push(value.toUpperCase());
      } else {
        updateParts.push(`${dbKey} = ?`);
        params.push(value);
      }
    }
  }

  if (updateParts.length === 0) {
    return expense;
  }

  params.push(expenseId);
  const stmt = db.prepare(`UPDATE expenses SET ${updateParts.join(', ')} WHERE id = ?`);
  stmt.run(...params);

  // If expense is part of a report, recalculate total
  if (expense.report_id) {
    calculateReportTotal(db, expense.report_id);
  }

  return getExpense(db, expenseId);
}

/**
 * Delete an expense
 * @param {Database} db
 * @param {number} expenseId
 * @returns {boolean} True if expense was deleted
 */
function deleteExpense(db, expenseId) {
  const expense = getExpense(db, expenseId);
  if (!expense) {
    throw new Error(`Expense with ID ${expenseId} not found`);
  }

  const reportId = expense.report_id;

  const stmt = db.prepare('DELETE FROM expenses WHERE id = ?');
  const result = stmt.run(expenseId);

  // If expense was part of a report, recalculate total
  if (reportId) {
    calculateReportTotal(db, reportId);
  }

  return result.changes > 0;
}

/**
 * Assign expense to a report
 * @param {Database} db
 * @param {number} expenseId
 * @param {number} reportId
 * @returns {Object} Updated expense
 */
function assignToReport(db, expenseId, reportId) {
  const expense = getExpense(db, expenseId);
  if (!expense) {
    throw new Error(`Expense with ID ${expenseId} not found`);
  }

  const report = getReport(db, reportId);
  if (!report) {
    throw new Error(`Report with ID ${reportId} not found`);
  }

  const oldReportId = expense.report_id;

  const stmt = db.prepare('UPDATE expenses SET report_id = ? WHERE id = ?');
  stmt.run(reportId, expenseId);

  // Recalculate totals for both old and new reports
  if (oldReportId && oldReportId !== reportId) {
    calculateReportTotal(db, oldReportId);
  }
  calculateReportTotal(db, reportId);

  return getExpense(db, expenseId);
}

/**
 * Mark expense as reimbursed
 * @param {Database} db
 * @param {number} expenseId
 * @returns {Object} Updated expense
 */
function markReimbursed(db, expenseId) {
  const expense = getExpense(db, expenseId);
  if (!expense) {
    throw new Error(`Expense with ID ${expenseId} not found`);
  }

  const stmt = db.prepare('UPDATE expenses SET reimbursed = 1 WHERE id = ?');
  stmt.run(expenseId);

  return getExpense(db, expenseId);
}

// ============================================================================
// REPORT FUNCTIONS
// ============================================================================

/**
 * Create a new expense report
 * @param {Database} db
 * @param {Object} params
 * @param {string} params.title - Report title (required)
 * @param {Date|string} params.periodStart - Period start date (required)
 * @param {Date|string} params.periodEnd - Period end date (required)
 * @param {string} [params.notes] - Additional notes
 * @returns {Object} Created report with id
 */
function createReport(db, { title, periodStart, periodEnd, notes }) {
  if (!title || typeof title !== 'string' || title.trim() === '') {
    throw new Error('Report title is required');
  }

  if (!periodStart) {
    throw new Error('Period start date is required');
  }

  if (!periodEnd) {
    throw new Error('Period end date is required');
  }

  const stmt = db.prepare(`
    INSERT INTO expense_reports (title, period_start, period_end, notes)
    VALUES (?, ?, ?, ?)
  `);

  const result = stmt.run(
    title.trim(),
    formatDateForDb(periodStart),
    formatDateForDb(periodEnd),
    notes || null
  );

  return getReport(db, result.lastInsertRowid);
}

/**
 * Get a report with all its expenses
 * @param {Database} db
 * @param {number} reportId
 * @returns {Object|null} Report object with expenses array, or null if not found
 */
function getReport(db, reportId) {
  const reportStmt = db.prepare('SELECT * FROM expense_reports WHERE id = ?');
  const report = reportStmt.get(reportId);

  if (!report) {
    return null;
  }

  const expensesStmt = db.prepare(`
    SELECT * FROM expenses
    WHERE report_id = ?
    ORDER BY date ASC, created_at ASC
  `);
  report.expenses = expensesStmt.all(reportId);

  return report;
}

/**
 * Get reports by status
 * @param {Database} db
 * @param {string} [status] - Filter by status (draft, submitted, approved, rejected, reimbursed)
 * @returns {Array} Array of report objects
 */
function getReports(db, status) {
  let query = 'SELECT * FROM expense_reports';
  const params = [];

  if (status) {
    query += ' WHERE status = ?';
    params.push(status);
  }

  query += ' ORDER BY created_at DESC';

  const stmt = db.prepare(query);
  return stmt.all(...params);
}

/**
 * Update a report
 * @param {Database} db
 * @param {number} reportId
 * @param {Object} updates - Fields to update
 * @returns {Object} Updated report
 */
function updateReport(db, reportId, updates) {
  const report = getReport(db, reportId);
  if (!report) {
    throw new Error(`Report with ID ${reportId} not found`);
  }

  const allowedFields = ['title', 'period_start', 'period_end', 'notes', 'currency'];
  const updateParts = [];
  const params = [];

  for (const [key, value] of Object.entries(updates)) {
    const dbKey = key === 'periodStart' ? 'period_start' :
                  key === 'periodEnd' ? 'period_end' : key;
    if (allowedFields.includes(dbKey)) {
      if (dbKey === 'period_start' || dbKey === 'period_end') {
        updateParts.push(`${dbKey} = ?`);
        params.push(formatDateForDb(value));
      } else if (dbKey === 'currency') {
        updateParts.push(`${dbKey} = ?`);
        params.push(value.toUpperCase());
      } else {
        updateParts.push(`${dbKey} = ?`);
        params.push(value);
      }
    }
  }

  if (updateParts.length === 0) {
    return report;
  }

  params.push(reportId);
  const stmt = db.prepare(`UPDATE expense_reports SET ${updateParts.join(', ')} WHERE id = ?`);
  stmt.run(...params);

  return getReport(db, reportId);
}

/**
 * Recalculate report total from its expenses
 * @param {Database} db
 * @param {number} reportId
 * @returns {number} New total
 */
function calculateReportTotal(db, reportId) {
  const report = getReport(db, reportId);
  if (!report) {
    throw new Error(`Report with ID ${reportId} not found`);
  }

  const sumStmt = db.prepare(`
    SELECT COALESCE(SUM(amount), 0) as total
    FROM expenses
    WHERE report_id = ?
  `);
  const result = sumStmt.get(reportId);
  const total = result.total;

  const updateStmt = db.prepare('UPDATE expense_reports SET total = ? WHERE id = ?');
  updateStmt.run(total, reportId);

  return total;
}

/**
 * Submit report for approval
 * @param {Database} db
 * @param {number} reportId
 * @returns {Object} Updated report
 */
function submitReport(db, reportId) {
  const report = getReport(db, reportId);
  if (!report) {
    throw new Error(`Report with ID ${reportId} not found`);
  }

  if (report.status !== 'draft') {
    throw new Error(`Cannot submit report with status '${report.status}'. Only draft reports can be submitted.`);
  }

  // Recalculate total before submission
  calculateReportTotal(db, reportId);

  const now = new Date().toISOString();
  const stmt = db.prepare(`
    UPDATE expense_reports
    SET status = 'submitted', submitted_at = ?
    WHERE id = ?
  `);
  stmt.run(now, reportId);

  return getReport(db, reportId);
}

/**
 * Approve a submitted report
 * @param {Database} db
 * @param {number} reportId
 * @returns {Object} Updated report
 */
function approveReport(db, reportId) {
  const report = getReport(db, reportId);
  if (!report) {
    throw new Error(`Report with ID ${reportId} not found`);
  }

  if (report.status !== 'submitted') {
    throw new Error(`Cannot approve report with status '${report.status}'. Only submitted reports can be approved.`);
  }

  const now = new Date().toISOString();
  const stmt = db.prepare(`
    UPDATE expense_reports
    SET status = 'approved', approved_at = ?
    WHERE id = ?
  `);
  stmt.run(now, reportId);

  return getReport(db, reportId);
}

/**
 * Reject a submitted report
 * @param {Database} db
 * @param {number} reportId
 * @param {string} reason - Rejection reason
 * @returns {Object} Updated report
 */
function rejectReport(db, reportId, reason) {
  const report = getReport(db, reportId);
  if (!report) {
    throw new Error(`Report with ID ${reportId} not found`);
  }

  if (report.status !== 'submitted') {
    throw new Error(`Cannot reject report with status '${report.status}'. Only submitted reports can be rejected.`);
  }

  const notes = report.notes
    ? `${report.notes}\n\nRejection reason: ${reason}`
    : `Rejection reason: ${reason}`;

  const stmt = db.prepare(`
    UPDATE expense_reports
    SET status = 'rejected', notes = ?
    WHERE id = ?
  `);
  stmt.run(notes, reportId);

  return getReport(db, reportId);
}

/**
 * Delete a report (unassigns expenses first)
 * @param {Database} db
 * @param {number} reportId
 * @returns {boolean} True if report was deleted
 */
function deleteReport(db, reportId) {
  const report = getReport(db, reportId);
  if (!report) {
    throw new Error(`Report with ID ${reportId} not found`);
  }

  // Unassign all expenses from this report
  const unassignStmt = db.prepare('UPDATE expenses SET report_id = NULL WHERE report_id = ?');
  unassignStmt.run(reportId);

  // Delete the report
  const deleteStmt = db.prepare('DELETE FROM expense_reports WHERE id = ?');
  const result = deleteStmt.run(reportId);

  return result.changes > 0;
}

// ============================================================================
// BUDGET FUNCTIONS
// ============================================================================

/**
 * Set or update budget for a category
 * @param {Database} db
 * @param {string} category - Expense category
 * @param {number} monthlyLimit - Monthly budget limit
 * @param {string} [currency='USD'] - Currency code
 * @returns {Object} Created or updated budget
 */
function setBudget(db, category, monthlyLimit, currency = 'USD') {
  if (!category || typeof category !== 'string') {
    throw new Error('Category is required');
  }

  const normalizedCategory = category.toLowerCase().trim();
  if (!VALID_CATEGORIES.includes(normalizedCategory)) {
    throw new Error(`Invalid category. Must be one of: ${VALID_CATEGORIES.join(', ')}`);
  }

  if (monthlyLimit === undefined || monthlyLimit === null || isNaN(parseFloat(monthlyLimit))) {
    throw new Error('Valid monthly limit is required');
  }

  if (parseFloat(monthlyLimit) < 0) {
    throw new Error('Monthly limit cannot be negative');
  }

  const stmt = db.prepare(`
    INSERT INTO expense_budgets (category, monthly_limit, currency)
    VALUES (?, ?, ?)
    ON CONFLICT(category) DO UPDATE SET
      monthly_limit = excluded.monthly_limit,
      currency = excluded.currency
  `);

  stmt.run(normalizedCategory, parseFloat(monthlyLimit), currency.toUpperCase());

  const getStmt = db.prepare('SELECT * FROM expense_budgets WHERE category = ?');
  return getStmt.get(normalizedCategory);
}

/**
 * Get all budgets
 * @param {Database} db
 * @returns {Array} Array of budget objects
 */
function getBudgets(db) {
  const stmt = db.prepare('SELECT * FROM expense_budgets ORDER BY category');
  return stmt.all();
}

/**
 * Get budget status for a category (current month spending vs budget)
 * @param {Database} db
 * @param {string} category
 * @returns {Object} Budget status with spent, limit, remaining, percentage
 */
function getBudgetStatus(db, category) {
  const normalizedCategory = category.toLowerCase().trim();
  if (!VALID_CATEGORIES.includes(normalizedCategory)) {
    throw new Error(`Invalid category. Must be one of: ${VALID_CATEGORIES.join(', ')}`);
  }

  const budgetStmt = db.prepare('SELECT * FROM expense_budgets WHERE category = ?');
  const budget = budgetStmt.get(normalizedCategory);

  if (!budget) {
    return {
      category: normalizedCategory,
      spent: 0,
      limit: 0,
      remaining: 0,
      percentage: 0,
      currency: 'USD',
      hasbudget: false
    };
  }

  const startOfMonth = getStartOfMonthPortugal();
  const endOfMonth = getEndOfMonthPortugal();

  const spentStmt = db.prepare(`
    SELECT COALESCE(SUM(amount), 0) as spent
    FROM expenses
    WHERE category = ?
      AND date >= ?
      AND date <= ?
  `);
  const result = spentStmt.get(normalizedCategory, startOfMonth, endOfMonth);
  const spent = result.spent;

  const remaining = Math.max(0, budget.monthly_limit - spent);
  const percentage = budget.monthly_limit > 0
    ? Math.round((spent / budget.monthly_limit) * 100)
    : 0;

  return {
    category: normalizedCategory,
    spent,
    limit: budget.monthly_limit,
    remaining,
    percentage,
    currency: budget.currency,
    hasBudget: true
  };
}

/**
 * Get budget status for all categories
 * @param {Database} db
 * @returns {Array} Array of budget status objects
 */
function getAllBudgetStatuses(db) {
  return VALID_CATEGORIES.map(category => getBudgetStatus(db, category));
}

/**
 * Check if budget alert should be triggered (over 80% or 100%)
 * @param {Database} db
 * @param {string} category
 * @returns {Object} Alert status with level (null, 'warning', 'exceeded')
 */
function checkBudgetAlert(db, category) {
  const status = getBudgetStatus(db, category);

  if (!status.hasBudget || status.limit === 0) {
    return {
      ...status,
      alertLevel: null,
      message: null
    };
  }

  let alertLevel = null;
  let message = null;

  if (status.percentage >= 100) {
    alertLevel = 'exceeded';
    message = `Budget exceeded! ${formatCurrency(status.spent, status.currency)} spent of ${formatCurrency(status.limit, status.currency)} limit (${status.percentage}%)`;
  } else if (status.percentage >= 80) {
    alertLevel = 'warning';
    message = `Budget warning: ${formatCurrency(status.spent, status.currency)} spent of ${formatCurrency(status.limit, status.currency)} limit (${status.percentage}%)`;
  }

  return {
    ...status,
    alertLevel,
    message
  };
}

// ============================================================================
// ANALYTICS FUNCTIONS
// ============================================================================

/**
 * Get spending breakdown by category for a date range
 * @param {Database} db
 * @param {Date|string} startDate
 * @param {Date|string} endDate
 * @returns {Array} Array of category spending objects
 */
function getSpendingByCategory(db, startDate, endDate) {
  const stmt = db.prepare(`
    SELECT
      category,
      SUM(amount) as total,
      COUNT(*) as count,
      AVG(amount) as average
    FROM expenses
    WHERE date >= ? AND date <= ?
    GROUP BY category
    ORDER BY total DESC
  `);

  return stmt.all(formatDateForDb(startDate), formatDateForDb(endDate));
}

/**
 * Get monthly spending history
 * @param {Database} db
 * @param {number} [months=6] - Number of months to include
 * @returns {Array} Array of monthly spending objects
 */
function getMonthlySpending(db, months = 6) {
  const now = getPortugalNow();
  const results = [];

  for (let i = 0; i < months; i++) {
    const date = new Date(now);
    date.setMonth(date.getMonth() - i);

    const startOfMonth = getStartOfMonthPortugal(date);
    const endOfMonth = getEndOfMonthPortugal(date);

    const stmt = db.prepare(`
      SELECT
        COALESCE(SUM(amount), 0) as total,
        COUNT(*) as count
      FROM expenses
      WHERE date >= ? AND date <= ?
    `);

    const result = stmt.get(startOfMonth, endOfMonth);

    const monthName = date.toLocaleString('en-US', {
      month: 'short',
      year: 'numeric',
      timeZone: TIMEZONE
    });

    results.push({
      month: monthName,
      startDate: startOfMonth,
      endDate: endOfMonth,
      total: result.total,
      count: result.count
    });
  }

  return results.reverse();
}

/**
 * Get top vendors by total spend
 * @param {Database} db
 * @param {number} [limit=10] - Number of vendors to return
 * @returns {Array} Array of vendor spending objects
 */
function getTopVendors(db, limit = 10) {
  const stmt = db.prepare(`
    SELECT
      vendor,
      SUM(amount) as total,
      COUNT(*) as count,
      AVG(amount) as average
    FROM expenses
    WHERE vendor IS NOT NULL AND vendor != ''
    GROUP BY vendor
    ORDER BY total DESC
    LIMIT ?
  `);

  return stmt.all(limit);
}

// ============================================================================
// DISPLAY FUNCTIONS
// ============================================================================

/**
 * Get emoji for expense category
 * @param {string} category
 * @returns {string} Emoji for the category
 */
function getCategoryEmoji(category) {
  const emojis = {
    travel: '\u{2708}\u{FE0F}',     // Airplane
    meals: '\u{1F37D}\u{FE0F}',     // Fork and knife with plate
    supplies: '\u{1F4E6}',          // Package
    software: '\u{1F4BB}',          // Laptop
    equipment: '\u{1F527}',         // Wrench
    other: '\u{1F4B3}'              // Credit card
  };
  return emojis[category?.toLowerCase()] || emojis.other;
}

/**
 * Format currency amount with symbol
 * @param {number} amount
 * @param {string} [currency='USD']
 * @returns {string} Formatted amount with currency symbol
 */
function formatCurrency(amount, currency = 'USD') {
  const symbol = CURRENCY_SYMBOLS[currency] || currency;
  const formatted = parseFloat(amount).toFixed(2);

  // For currencies that typically put symbol after amount
  if (['EUR'].includes(currency)) {
    return `${formatted}${symbol}`;
  }

  return `${symbol}${formatted}`;
}

/**
 * Format single expense for Telegram HTML display
 * @param {Object} expense
 * @returns {string} HTML-formatted string
 */
function formatExpenseForDisplay(expense) {
  if (!expense) {
    return '<i>Expense not found</i>';
  }

  const emoji = getCategoryEmoji(expense.category);
  const amount = formatCurrency(expense.amount, expense.currency);
  const date = new Date(expense.date).toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric'
  });

  let text = `${emoji} <b>${amount}</b> - ${escapeHtml(expense.category)}\n`;
  text += `\u{1F4C5} ${date}\n`;

  if (expense.description) {
    text += `\u{1F4DD} ${escapeHtml(expense.description)}\n`;
  }

  if (expense.vendor) {
    text += `\u{1F3EA} ${escapeHtml(expense.vendor)}\n`;
  }

  if (expense.receipt_path) {
    text += `\u{1F4CE} Receipt attached\n`;
  }

  if (expense.reimbursed) {
    text += `\u{2705} Reimbursed\n`;
  }

  if (expense.report_id) {
    text += `\u{1F4CB} Report #${expense.report_id}\n`;
  }

  text += `<code>#exp${expense.id}</code>`;

  return text;
}

/**
 * Format expense list for Telegram HTML display
 * @param {Array} expenses
 * @returns {string} HTML-formatted string
 */
function formatExpenseListForDisplay(expenses) {
  if (!expenses || expenses.length === 0) {
    return '<i>No expenses found</i>';
  }

  const total = expenses.reduce((sum, exp) => sum + exp.amount, 0);
  const currency = expenses[0]?.currency || 'USD';

  let text = `<b>\u{1F4B0} ${expenses.length} Expense${expenses.length !== 1 ? 's' : ''}</b>\n`;
  text += `<b>Total: ${formatCurrency(total, currency)}</b>\n\n`;

  const lines = expenses.slice(0, 15).map(expense => {
    const emoji = getCategoryEmoji(expense.category);
    const amount = formatCurrency(expense.amount, expense.currency);
    const date = new Date(expense.date).toLocaleDateString('en-GB', {
      day: 'numeric',
      month: 'short'
    });

    let line = `${emoji} <b>${amount}</b> ${date}`;
    if (expense.vendor) {
      line += ` - ${escapeHtml(expense.vendor)}`;
    } else if (expense.description) {
      const shortDesc = expense.description.length > 30
        ? expense.description.substring(0, 27) + '...'
        : expense.description;
      line += ` - ${escapeHtml(shortDesc)}`;
    }
    line += ` <code>#exp${expense.id}</code>`;

    return line;
  });

  text += lines.join('\n');

  if (expenses.length > 15) {
    text += `\n\n<i>...and ${expenses.length - 15} more</i>`;
  }

  return text;
}

/**
 * Format full report for Telegram HTML display
 * @param {Object} report
 * @returns {string} HTML-formatted string
 */
function formatReportForDisplay(report) {
  if (!report) {
    return '<i>Report not found</i>';
  }

  const statusEmojis = {
    draft: '\u{1F4DD}',         // Memo
    submitted: '\u{1F4E4}',     // Outbox tray
    approved: '\u{2705}',       // Check mark
    rejected: '\u{274C}',       // Cross mark
    reimbursed: '\u{1F4B5}'     // Dollar
  };

  const statusEmoji = statusEmojis[report.status] || '\u{2753}';
  const periodStart = new Date(report.period_start).toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric'
  });
  const periodEnd = new Date(report.period_end).toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric'
  });

  let text = `<b>\u{1F4CB} ${escapeHtml(report.title)}</b>\n\n`;
  text += `${statusEmoji} Status: <b>${report.status}</b>\n`;
  text += `\u{1F4C5} Period: ${periodStart} - ${periodEnd}\n`;
  text += `\u{1F4B0} Total: <b>${formatCurrency(report.total, report.currency)}</b>\n`;

  if (report.submitted_at) {
    const submittedDate = new Date(report.submitted_at).toLocaleDateString('en-GB');
    text += `\u{1F4E4} Submitted: ${submittedDate}\n`;
  }

  if (report.approved_at) {
    const approvedDate = new Date(report.approved_at).toLocaleDateString('en-GB');
    text += `\u{2705} Approved: ${approvedDate}\n`;
  }

  if (report.notes) {
    text += `\n<i>${escapeHtml(report.notes)}</i>\n`;
  }

  text += `\n<code>#report${report.id}</code>\n`;

  // List expenses
  if (report.expenses && report.expenses.length > 0) {
    text += `\n<b>Expenses (${report.expenses.length}):</b>\n`;

    const byCategory = {};
    for (const expense of report.expenses) {
      if (!byCategory[expense.category]) {
        byCategory[expense.category] = { total: 0, count: 0 };
      }
      byCategory[expense.category].total += expense.amount;
      byCategory[expense.category].count += 1;
    }

    for (const [category, data] of Object.entries(byCategory)) {
      const emoji = getCategoryEmoji(category);
      text += `${emoji} ${category}: ${formatCurrency(data.total, report.currency)} (${data.count})\n`;
    }
  }

  return text;
}

/**
 * Format budget status for Telegram HTML display
 * @param {Array} statuses
 * @returns {string} HTML-formatted string
 */
function formatBudgetStatusForDisplay(statuses) {
  if (!statuses || statuses.length === 0) {
    return '<i>No budgets configured</i>';
  }

  let text = '<b>\u{1F4CA} Budget Status</b>\n\n';

  for (const status of statuses) {
    const emoji = getCategoryEmoji(status.category);
    const progressBar = generateProgressBar(status.percentage);

    let alertIcon = '';
    if (status.percentage >= 100) {
      alertIcon = ' \u{1F6A8}';
    } else if (status.percentage >= 80) {
      alertIcon = ' \u{26A0}\u{FE0F}';
    }

    text += `${emoji} <b>${status.category}</b>${alertIcon}\n`;
    text += `${progressBar} ${status.percentage}%\n`;
    text += `Spent: ${formatCurrency(status.spent, status.currency)} / ${formatCurrency(status.limit, status.currency)}\n`;
    text += `Remaining: ${formatCurrency(status.remaining, status.currency)}\n\n`;
  }

  return text;
}

/**
 * Generate a text progress bar
 * @param {number} percentage
 * @returns {string} Progress bar string
 */
function generateProgressBar(percentage) {
  const filled = Math.min(10, Math.round(percentage / 10));
  const empty = 10 - filled;

  let bar = '';
  if (percentage >= 100) {
    bar = '\u{1F7E5}'.repeat(filled) + '\u{2B1C}'.repeat(empty);
  } else if (percentage >= 80) {
    bar = '\u{1F7E7}'.repeat(filled) + '\u{2B1C}'.repeat(empty);
  } else {
    bar = '\u{1F7E9}'.repeat(filled) + '\u{2B1C}'.repeat(empty);
  }

  return bar;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Parse expense from natural language text
 * Supports patterns like:
 * - "$50 lunch at Starbucks"
 * - "25.99 supplies from Amazon"
 * - "taxi $30"
 * - "100 USD software"
 *
 * @param {string} text - Natural language input
 * @returns {Object|null} Parsed expense object or null if parsing failed
 */
function parseExpenseFromText(text) {
  if (!text || typeof text !== 'string') {
    return null;
  }

  let cleanText = text.trim();
  let amount = null;
  let currency = 'USD';
  let category = null;
  let description = null;
  let vendor = null;

  // Extract amount patterns
  const amountPatterns = [
    // "$50.00" or "$50"
    { pattern: /\$(\d+(?:\.\d{2})?)/i, currency: 'USD' },
    // "50 USD" or "50USD"
    { pattern: /(\d+(?:\.\d{2})?)\s*USD/i, currency: 'USD' },
    // "50 EUR" or "50EUR" or "50E" (with euro symbol)
    { pattern: /(\d+(?:\.\d{2})?)\s*(?:EUR|\u20AC)/i, currency: 'EUR' },
    // "\u00A350" or "50 GBP"
    { pattern: /\u00A3(\d+(?:\.\d{2})?)/i, currency: 'GBP' },
    { pattern: /(\d+(?:\.\d{2})?)\s*GBP/i, currency: 'GBP' },
    // Plain number at start or end
    { pattern: /^(\d+(?:\.\d{2})?)\s+/i, currency: 'USD' },
    { pattern: /\s+(\d+(?:\.\d{2})?)$/i, currency: 'USD' }
  ];

  for (const { pattern, currency: curr } of amountPatterns) {
    const match = cleanText.match(pattern);
    if (match) {
      amount = parseFloat(match[1]);
      currency = curr;
      cleanText = cleanText.replace(pattern, ' ').trim();
      break;
    }
  }

  if (amount === null) {
    return null;
  }

  // Extract "at <vendor>" pattern
  const atVendorMatch = cleanText.match(/\s+at\s+(.+?)(?:\s+for\s+|\s*$)/i);
  if (atVendorMatch) {
    vendor = atVendorMatch[1].trim();
    cleanText = cleanText.replace(/\s+at\s+.+?(?:\s+for\s+|\s*$)/i, ' ').trim();
  }

  // Extract "from <vendor>" pattern
  const fromVendorMatch = cleanText.match(/\s+from\s+(.+?)(?:\s+for\s+|\s*$)/i);
  if (fromVendorMatch) {
    vendor = fromVendorMatch[1].trim();
    cleanText = cleanText.replace(/\s+from\s+.+?(?:\s+for\s+|\s*$)/i, ' ').trim();
  }

  // Try to match category from text
  const categoryKeywords = {
    travel: ['travel', 'flight', 'hotel', 'uber', 'lyft', 'taxi', 'train', 'bus', 'rental', 'airbnb', 'booking'],
    meals: ['meal', 'meals', 'lunch', 'dinner', 'breakfast', 'food', 'coffee', 'restaurant', 'cafe', 'snack', 'drinks'],
    supplies: ['supplies', 'supply', 'office', 'paper', 'pens', 'stationery'],
    software: ['software', 'subscription', 'saas', 'app', 'license', 'tool', 'service'],
    equipment: ['equipment', 'hardware', 'computer', 'laptop', 'monitor', 'keyboard', 'mouse', 'phone', 'device']
  };

  const lowerText = cleanText.toLowerCase();
  for (const [cat, keywords] of Object.entries(categoryKeywords)) {
    for (const keyword of keywords) {
      if (lowerText.includes(keyword)) {
        category = cat;
        break;
      }
    }
    if (category) break;
  }

  // Default to 'other' if no category found
  if (!category) {
    category = 'other';
  }

  // Whatever remains is the description
  description = cleanText.trim() || null;

  return {
    amount,
    currency,
    category,
    description,
    vendor,
    date: getPortugalNow()
  };
}

/**
 * Validate category name
 * @param {string} category
 * @returns {boolean} True if valid
 */
function validateCategory(category) {
  if (!category || typeof category !== 'string') {
    return false;
  }
  return VALID_CATEGORIES.includes(category.toLowerCase().trim());
}

/**
 * Get list of valid categories
 * @returns {Array} Array of valid category names
 */
function getDefaultCategories() {
  return [...VALID_CATEGORIES];
}

// ============================================================================
// MODULE EXPORTS
// ============================================================================

module.exports = {
  // Database initialization
  initTables,

  // Core expense functions
  addExpense,
  getExpense,
  getExpenses,
  getUnreportedExpenses,
  updateExpense,
  deleteExpense,
  assignToReport,
  markReimbursed,

  // Report functions
  createReport,
  getReport,
  getReports,
  updateReport,
  calculateReportTotal,
  submitReport,
  approveReport,
  rejectReport,
  deleteReport,

  // Budget functions
  setBudget,
  getBudgets,
  getBudgetStatus,
  getAllBudgetStatuses,
  checkBudgetAlert,

  // Analytics functions
  getSpendingByCategory,
  getMonthlySpending,
  getTopVendors,

  // Display functions
  formatExpenseForDisplay,
  formatExpenseListForDisplay,
  formatReportForDisplay,
  formatBudgetStatusForDisplay,
  getCategoryEmoji,
  formatCurrency,

  // Helper functions
  parseExpenseFromText,
  validateCategory,
  getDefaultCategories,

  // Utility exports for testing
  getPortugalNow,
  formatDateForDb,
  escapeHtml,
  generateProgressBar,

  // Constants
  TIMEZONE,
  VALID_CATEGORIES,
  DEFAULT_BUDGETS,
  CURRENCY_SYMBOLS
};
