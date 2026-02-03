/**
 * TaskService.js - Personal task and reminder management for executive assistant
 *
 * Handles task creation, scheduling, recurring tasks, and reminders
 * Uses Portugal timezone (WET/WEST) for all date calculations
 */

// Portugal timezone
const TIMEZONE = 'Europe/Lisbon';

/**
 * Get current date in Portugal timezone
 * @returns {Date}
 */
function getPortugalNow() {
  const now = new Date();
  // Get the Portugal time string and parse it back
  const ptString = now.toLocaleString('en-US', { timeZone: TIMEZONE });
  return new Date(ptString);
}

/**
 * Format a date for SQLite storage (ISO format)
 * @param {Date|string} date
 * @returns {string}
 */
function formatDateForDb(date) {
  if (!date) return null;
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toISOString();
}

/**
 * Get start of day in Portugal timezone
 * @param {Date} date
 * @returns {Date}
 */
function getStartOfDayPortugal(date = new Date()) {
  const ptString = date.toLocaleString('en-US', {
    timeZone: TIMEZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  });
  const [month, day, year] = ptString.split('/');
  return new Date(`${year}-${month}-${day}T00:00:00`);
}

/**
 * Get end of day in Portugal timezone
 * @param {Date} date
 * @returns {Date}
 */
function getEndOfDayPortugal(date = new Date()) {
  const ptString = date.toLocaleString('en-US', {
    timeZone: TIMEZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  });
  const [month, day, year] = ptString.split('/');
  return new Date(`${year}-${month}-${day}T23:59:59`);
}

/**
 * Initialize database tables for tasks and reminders
 * @param {Database} db - better-sqlite3 database instance
 */
function initTables(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS exec_tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      priority TEXT DEFAULT 'normal',
      due_date DATETIME,
      recurring TEXT,
      delegated_to TEXT,
      status TEXT DEFAULT 'pending',
      completed_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS reminders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      task_id INTEGER,
      remind_at DATETIME NOT NULL,
      sent BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (task_id) REFERENCES exec_tasks(id)
    );

    CREATE INDEX IF NOT EXISTS idx_exec_tasks_status ON exec_tasks(status);
    CREATE INDEX IF NOT EXISTS idx_exec_tasks_due_date ON exec_tasks(due_date);
    CREATE INDEX IF NOT EXISTS idx_exec_tasks_priority ON exec_tasks(priority);
    CREATE INDEX IF NOT EXISTS idx_reminders_remind_at ON reminders(remind_at);
    CREATE INDEX IF NOT EXISTS idx_reminders_sent ON reminders(sent);
  `);
}

/**
 * Add a new task
 * @param {Database} db
 * @param {Object} params
 * @param {string} params.title - Task title (required)
 * @param {string} [params.description] - Task description
 * @param {string} [params.priority='normal'] - Priority level: low, normal, high, urgent
 * @param {Date|string} [params.dueDate] - Due date
 * @param {string} [params.recurring] - Recurrence pattern: daily, weekly, monthly, or null
 * @param {string} [params.delegatedTo] - Person task is delegated to
 * @returns {Object} Created task with id
 */
function addTask(db, { title, description, priority = 'normal', dueDate, recurring, delegatedTo }) {
  if (!title || typeof title !== 'string' || title.trim() === '') {
    throw new Error('Task title is required');
  }

  const validPriorities = ['low', 'normal', 'high', 'urgent'];
  if (priority && !validPriorities.includes(priority)) {
    throw new Error(`Invalid priority. Must be one of: ${validPriorities.join(', ')}`);
  }

  const validRecurring = ['daily', 'weekly', 'monthly', null, undefined];
  if (recurring && !['daily', 'weekly', 'monthly'].includes(recurring)) {
    throw new Error('Invalid recurring value. Must be: daily, weekly, monthly, or null');
  }

  const stmt = db.prepare(`
    INSERT INTO exec_tasks (title, description, priority, due_date, recurring, delegated_to)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  const result = stmt.run(
    title.trim(),
    description || null,
    priority,
    formatDateForDb(dueDate),
    recurring || null,
    delegatedTo || null
  );

  return getTask(db, result.lastInsertRowid);
}

/**
 * Get a single task by ID
 * @param {Database} db
 * @param {number} taskId
 * @returns {Object|null} Task object or null if not found
 */
function getTask(db, taskId) {
  const stmt = db.prepare('SELECT * FROM exec_tasks WHERE id = ?');
  return stmt.get(taskId) || null;
}

/**
 * Get tasks with optional filters
 * @param {Database} db
 * @param {Object} [filters={}]
 * @param {string} [filters.status] - Filter by status
 * @param {string} [filters.priority] - Filter by priority
 * @param {number} [filters.limit=50] - Maximum number of tasks to return
 * @returns {Array} Array of task objects
 */
function getTasks(db, { status, priority, limit = 50 } = {}) {
  let query = 'SELECT * FROM exec_tasks WHERE 1=1';
  const params = [];

  if (status) {
    query += ' AND status = ?';
    params.push(status);
  }

  if (priority) {
    query += ' AND priority = ?';
    params.push(priority);
  }

  query += ' ORDER BY CASE priority WHEN \'urgent\' THEN 1 WHEN \'high\' THEN 2 WHEN \'normal\' THEN 3 WHEN \'low\' THEN 4 END, due_date ASC NULLS LAST';
  query += ' LIMIT ?';
  params.push(limit);

  const stmt = db.prepare(query);
  return stmt.all(...params);
}

/**
 * Get tasks due today (Portugal timezone)
 * @param {Database} db
 * @returns {Array} Array of tasks due today
 */
function getTasksDueToday(db) {
  const startOfDay = getStartOfDayPortugal();
  const endOfDay = getEndOfDayPortugal();

  const stmt = db.prepare(`
    SELECT * FROM exec_tasks
    WHERE due_date >= ? AND due_date <= ?
    AND status != 'completed'
    ORDER BY CASE priority WHEN 'urgent' THEN 1 WHEN 'high' THEN 2 WHEN 'normal' THEN 3 WHEN 'low' THEN 4 END, due_date ASC
  `);

  return stmt.all(startOfDay.toISOString(), endOfDay.toISOString());
}

/**
 * Get overdue tasks (past due date, not completed)
 * @param {Database} db
 * @returns {Array} Array of overdue tasks
 */
function getOverdueTasks(db) {
  const now = getPortugalNow();

  const stmt = db.prepare(`
    SELECT * FROM exec_tasks
    WHERE due_date < ?
    AND status != 'completed'
    ORDER BY due_date ASC
  `);

  return stmt.all(now.toISOString());
}

/**
 * Update task status
 * @param {Database} db
 * @param {number} taskId
 * @param {string} status - New status: pending, in_progress, completed
 * @returns {Object} Updated task
 */
function updateTaskStatus(db, taskId, status) {
  const validStatuses = ['pending', 'in_progress', 'completed'];
  if (!validStatuses.includes(status)) {
    throw new Error(`Invalid status. Must be one of: ${validStatuses.join(', ')}`);
  }

  const task = getTask(db, taskId);
  if (!task) {
    throw new Error(`Task with ID ${taskId} not found`);
  }

  const stmt = db.prepare('UPDATE exec_tasks SET status = ? WHERE id = ?');
  stmt.run(status, taskId);

  return getTask(db, taskId);
}

/**
 * Calculate next occurrence date for recurring tasks
 * @param {Object} task - Task object with recurring and due_date
 * @returns {Date|null} Next occurrence date or null if not recurring
 */
function calculateNextRecurrence(task) {
  if (!task.recurring || !task.due_date) {
    return null;
  }

  const currentDue = new Date(task.due_date);
  let nextDue;

  switch (task.recurring) {
    case 'daily':
      nextDue = new Date(currentDue);
      nextDue.setDate(nextDue.getDate() + 1);
      break;
    case 'weekly':
      nextDue = new Date(currentDue);
      nextDue.setDate(nextDue.getDate() + 7);
      break;
    case 'monthly':
      nextDue = new Date(currentDue);
      nextDue.setMonth(nextDue.getMonth() + 1);
      break;
    default:
      return null;
  }

  return nextDue;
}

/**
 * Mark task as completed, handling recurring tasks
 * @param {Database} db
 * @param {number} taskId
 * @returns {Object} Result with completed task and optional new task for recurring
 */
function completeTask(db, taskId) {
  const task = getTask(db, taskId);
  if (!task) {
    throw new Error(`Task with ID ${taskId} not found`);
  }

  const now = getPortugalNow();

  // Mark current task as completed
  const updateStmt = db.prepare(`
    UPDATE exec_tasks
    SET status = 'completed', completed_at = ?
    WHERE id = ?
  `);
  updateStmt.run(now.toISOString(), taskId);

  const completedTask = getTask(db, taskId);
  let nextTask = null;

  // If recurring, create next occurrence
  if (task.recurring) {
    const nextDueDate = calculateNextRecurrence(task);
    if (nextDueDate) {
      nextTask = addTask(db, {
        title: task.title,
        description: task.description,
        priority: task.priority,
        dueDate: nextDueDate,
        recurring: task.recurring,
        delegatedTo: task.delegated_to
      });
    }
  }

  return {
    completedTask,
    nextTask
  };
}

/**
 * Delete a task and its associated reminders
 * @param {Database} db
 * @param {number} taskId
 * @returns {boolean} True if task was deleted
 */
function deleteTask(db, taskId) {
  const task = getTask(db, taskId);
  if (!task) {
    throw new Error(`Task with ID ${taskId} not found`);
  }

  // Delete associated reminders first
  const deleteRemindersStmt = db.prepare('DELETE FROM reminders WHERE task_id = ?');
  deleteRemindersStmt.run(taskId);

  // Delete the task
  const deleteTaskStmt = db.prepare('DELETE FROM exec_tasks WHERE id = ?');
  const result = deleteTaskStmt.run(taskId);

  return result.changes > 0;
}

/**
 * Add a reminder for a task
 * @param {Database} db
 * @param {number} taskId
 * @param {Date|string} remindAt - When to send the reminder
 * @returns {Object} Created reminder with id
 */
function addReminder(db, taskId, remindAt) {
  if (!taskId) {
    throw new Error('Task ID is required');
  }
  if (!remindAt) {
    throw new Error('Remind at date is required');
  }

  const task = getTask(db, taskId);
  if (!task) {
    throw new Error(`Task with ID ${taskId} not found`);
  }

  const stmt = db.prepare(`
    INSERT INTO reminders (task_id, remind_at)
    VALUES (?, ?)
  `);

  const result = stmt.run(taskId, formatDateForDb(remindAt));

  const getReminder = db.prepare('SELECT * FROM reminders WHERE id = ?');
  return getReminder.get(result.lastInsertRowid);
}

/**
 * Get reminders that should fire now (remind_at <= now and not sent)
 * @param {Database} db
 * @returns {Array} Array of due reminders with task details
 */
function getDueReminders(db) {
  const now = getPortugalNow();

  const stmt = db.prepare(`
    SELECT r.*, t.title as task_title, t.description as task_description,
           t.priority as task_priority, t.due_date as task_due_date
    FROM reminders r
    JOIN exec_tasks t ON r.task_id = t.id
    WHERE r.remind_at <= ? AND r.sent = 0
    ORDER BY r.remind_at ASC
  `);

  return stmt.all(now.toISOString());
}

/**
 * Mark a reminder as sent
 * @param {Database} db
 * @param {number} reminderId
 * @returns {boolean} True if reminder was updated
 */
function markReminderSent(db, reminderId) {
  const stmt = db.prepare('UPDATE reminders SET sent = 1 WHERE id = ?');
  const result = stmt.run(reminderId);
  return result.changes > 0;
}

/**
 * Get priority emoji
 * @param {string} priority
 * @returns {string} Emoji for the priority level
 */
function getPriorityEmoji(priority) {
  const emojis = {
    urgent: '\u{1F534}',  // Red circle
    high: '\u{1F7E0}',    // Orange circle
    normal: '\u{1F7E2}',  // Green circle
    low: '\u{26AA}'       // White circle
  };
  return emojis[priority] || emojis.normal;
}

/**
 * Parse natural language task creation
 * Supports patterns like:
 * - "remind me to call Sarah tomorrow"
 * - "task: review documents by Friday"
 * - "urgent: prepare presentation for 3pm"
 * - "buy groceries tomorrow at 10am"
 *
 * @param {string} text - Natural language input
 * @returns {Object} Parsed task object with title, priority, dueDate
 */
function parseTaskFromText(text) {
  if (!text || typeof text !== 'string') {
    return null;
  }

  let title = text.trim();
  let priority = 'normal';
  let dueDate = null;
  let description = null;

  // Extract priority from prefixes
  const priorityPatterns = [
    { pattern: /^urgent[:\s]+/i, priority: 'urgent' },
    { pattern: /^high[:\s]+/i, priority: 'high' },
    { pattern: /^important[:\s]+/i, priority: 'high' },
    { pattern: /^low[:\s]+/i, priority: 'low' },
    { pattern: /^!!!/i, priority: 'urgent' },
    { pattern: /^!!/i, priority: 'high' },
    { pattern: /^!/i, priority: 'normal' }
  ];

  for (const { pattern, priority: p } of priorityPatterns) {
    if (pattern.test(title)) {
      priority = p;
      title = title.replace(pattern, '').trim();
      break;
    }
  }

  // Remove common prefixes
  const prefixPatterns = [
    /^remind\s+me\s+to\s+/i,
    /^reminder[:\s]+/i,
    /^task[:\s]+/i,
    /^todo[:\s]+/i,
    /^to-do[:\s]+/i
  ];

  for (const pattern of prefixPatterns) {
    if (pattern.test(title)) {
      title = title.replace(pattern, '').trim();
      break;
    }
  }

  // Parse time expressions
  const now = getPortugalNow();

  // Time patterns to extract from title
  const timePatterns = [
    // "tomorrow at 3pm"
    {
      pattern: /\s+tomorrow\s+at\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)?$/i,
      handler: (match) => {
        const date = new Date(now);
        date.setDate(date.getDate() + 1);
        let hours = parseInt(match[1], 10);
        const minutes = parseInt(match[2] || '0', 10);
        const meridiem = (match[3] || '').toLowerCase();
        if (meridiem === 'pm' && hours < 12) hours += 12;
        if (meridiem === 'am' && hours === 12) hours = 0;
        date.setHours(hours, minutes, 0, 0);
        return date;
      }
    },
    // "tomorrow"
    {
      pattern: /\s+tomorrow$/i,
      handler: () => {
        const date = new Date(now);
        date.setDate(date.getDate() + 1);
        date.setHours(9, 0, 0, 0); // Default to 9am
        return date;
      }
    },
    // "today at 3pm"
    {
      pattern: /\s+today\s+at\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)?$/i,
      handler: (match) => {
        const date = new Date(now);
        let hours = parseInt(match[1], 10);
        const minutes = parseInt(match[2] || '0', 10);
        const meridiem = (match[3] || '').toLowerCase();
        if (meridiem === 'pm' && hours < 12) hours += 12;
        if (meridiem === 'am' && hours === 12) hours = 0;
        date.setHours(hours, minutes, 0, 0);
        return date;
      }
    },
    // "at 3pm" / "at 15:30"
    {
      pattern: /\s+at\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)?$/i,
      handler: (match) => {
        const date = new Date(now);
        let hours = parseInt(match[1], 10);
        const minutes = parseInt(match[2] || '0', 10);
        const meridiem = (match[3] || '').toLowerCase();
        if (meridiem === 'pm' && hours < 12) hours += 12;
        if (meridiem === 'am' && hours === 12) hours = 0;
        date.setHours(hours, minutes, 0, 0);
        // If time has passed, assume tomorrow
        if (date < now) {
          date.setDate(date.getDate() + 1);
        }
        return date;
      }
    },
    // "by Friday" / "on Monday"
    {
      pattern: /\s+(by|on)\s+(monday|tuesday|wednesday|thursday|friday|saturday|sunday)$/i,
      handler: (match) => {
        const days = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
        const targetDay = days.indexOf(match[2].toLowerCase());
        const date = new Date(now);
        const currentDay = date.getDay();
        let daysUntil = targetDay - currentDay;
        if (daysUntil <= 0) daysUntil += 7;
        date.setDate(date.getDate() + daysUntil);
        date.setHours(9, 0, 0, 0); // Default to 9am
        return date;
      }
    },
    // "in X hours"
    {
      pattern: /\s+in\s+(\d+)\s+hours?$/i,
      handler: (match) => {
        const date = new Date(now);
        date.setHours(date.getHours() + parseInt(match[1], 10));
        return date;
      }
    },
    // "in X minutes"
    {
      pattern: /\s+in\s+(\d+)\s+minutes?$/i,
      handler: (match) => {
        const date = new Date(now);
        date.setMinutes(date.getMinutes() + parseInt(match[1], 10));
        return date;
      }
    },
    // "in X days"
    {
      pattern: /\s+in\s+(\d+)\s+days?$/i,
      handler: (match) => {
        const date = new Date(now);
        date.setDate(date.getDate() + parseInt(match[1], 10));
        date.setHours(9, 0, 0, 0);
        return date;
      }
    },
    // "next week"
    {
      pattern: /\s+next\s+week$/i,
      handler: () => {
        const date = new Date(now);
        date.setDate(date.getDate() + 7);
        date.setHours(9, 0, 0, 0);
        return date;
      }
    },
    // "next month"
    {
      pattern: /\s+next\s+month$/i,
      handler: () => {
        const date = new Date(now);
        date.setMonth(date.getMonth() + 1);
        date.setHours(9, 0, 0, 0);
        return date;
      }
    }
  ];

  for (const { pattern, handler } of timePatterns) {
    const match = title.match(pattern);
    if (match) {
      dueDate = handler(match);
      title = title.replace(pattern, '').trim();
      break;
    }
  }

  // Clean up title
  title = title.charAt(0).toUpperCase() + title.slice(1);

  return {
    title,
    description,
    priority,
    dueDate
  };
}

/**
 * Format date for display
 * @param {string} dateStr - ISO date string
 * @returns {string} Formatted date string
 */
function formatDateForDisplay(dateStr) {
  if (!dateStr) return '';

  const date = new Date(dateStr);
  const now = getPortugalNow();
  const today = getStartOfDayPortugal(now);
  const tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);
  const dateStart = getStartOfDayPortugal(date);

  const timeStr = date.toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    timeZone: TIMEZONE
  });

  if (dateStart.getTime() === today.getTime()) {
    return `Today at ${timeStr}`;
  } else if (dateStart.getTime() === tomorrow.getTime()) {
    return `Tomorrow at ${timeStr}`;
  } else {
    const dateFormatted = date.toLocaleDateString('en-GB', {
      weekday: 'short',
      day: 'numeric',
      month: 'short',
      timeZone: TIMEZONE
    });
    return `${dateFormatted} at ${timeStr}`;
  }
}

/**
 * Format tasks for Telegram HTML display
 * @param {Array} tasks - Array of task objects
 * @returns {string} HTML-formatted string for Telegram
 */
function formatTasksForDisplay(tasks) {
  if (!tasks || tasks.length === 0) {
    return '<i>No tasks found</i>';
  }

  const lines = tasks.map((task, index) => {
    const emoji = getPriorityEmoji(task.priority);
    const statusIcon = task.status === 'completed' ? '\u{2705}' :
                       task.status === 'in_progress' ? '\u{1F504}' : '\u{2B1C}';

    let line = `${statusIcon} ${emoji} <b>${escapeHtml(task.title)}</b>`;

    if (task.due_date) {
      line += `\n    \u{1F4C5} ${formatDateForDisplay(task.due_date)}`;
    }

    if (task.delegated_to) {
      line += `\n    \u{1F464} ${escapeHtml(task.delegated_to)}`;
    }

    if (task.recurring) {
      line += `\n    \u{1F501} ${task.recurring}`;
    }

    if (task.description) {
      const shortDesc = task.description.length > 100
        ? task.description.substring(0, 97) + '...'
        : task.description;
      line += `\n    <i>${escapeHtml(shortDesc)}</i>`;
    }

    line += `\n    <code>#${task.id}</code>`;

    return line;
  });

  return lines.join('\n\n');
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

module.exports = {
  // Core functions
  initTables,
  addTask,
  getTask,
  getTasks,
  getTasksDueToday,
  getOverdueTasks,
  updateTaskStatus,
  completeTask,
  deleteTask,
  addReminder,
  getDueReminders,
  markReminderSent,
  parseTaskFromText,
  formatTasksForDisplay,

  // Helper functions
  calculateNextRecurrence,
  getPriorityEmoji,

  // Utility exports for testing
  getPortugalNow,
  formatDateForDb,
  formatDateForDisplay,
  escapeHtml,

  // Constants
  TIMEZONE
};
