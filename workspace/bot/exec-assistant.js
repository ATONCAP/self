/**
 * Executive Assistant Integration Module
 *
 * Integrates all Executive Assistant services into the Aton bot.
 * Provides command handlers, background processors, and briefing generation.
 *
 * @module exec-assistant
 */

const CalendarService = require('./services/CalendarService');
const TaskService = require('./services/TaskService');
const ContactService = require('./services/ContactService');
const FinancialService = require('./services/FinancialService');
const NewsService = require('./services/NewsService');
const EmailService = require('./services/EmailService');
const TravelService = require('./services/TravelService');
const ExpenseService = require('./services/ExpenseService');

/** Portugal timezone for all time operations */
const TIMEZONE = 'Europe/Lisbon';

/**
 * Format a date in Portugal timezone
 * @param {Date} date - Date to format
 * @param {Object} options - Intl.DateTimeFormat options
 * @returns {string} Formatted date string
 */
function formatInTimezone(date, options = {}) {
    return new Intl.DateTimeFormat('pt-PT', {
        timeZone: TIMEZONE,
        ...options
    }).format(date);
}

/**
 * Get current date/time in Portugal timezone
 * @returns {Date} Current date adjusted for display purposes
 */
function getNow() {
    return new Date();
}

/**
 * Get today's date string in YYYY-MM-DD format (Portugal timezone)
 * @returns {string} Date string
 */
function getTodayString() {
    const now = getNow();
    return formatInTimezone(now, { year: 'numeric', month: '2-digit', day: '2-digit' })
        .split('/').reverse().join('-');
}

/**
 * Get tomorrow's date string in YYYY-MM-DD format (Portugal timezone)
 * @returns {string} Date string
 */
function getTomorrowString() {
    const tomorrow = new Date(getNow());
    tomorrow.setDate(tomorrow.getDate() + 1);
    return formatInTimezone(tomorrow, { year: 'numeric', month: '2-digit', day: '2-digit' })
        .split('/').reverse().join('-');
}

/**
 * Escape HTML special characters for Telegram
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
    if (!text) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

/**
 * Initialize all Executive Assistant services
 * @param {Object} db - SQLite database instance
 * @returns {Object} Object containing all initialized services
 */
function initializeExecAssistant(db) {
    // Initialize all service tables
    CalendarService.initTables(db);
    TaskService.initTables(db);
    ContactService.initTables(db);
    FinancialService.initTables(db);
    NewsService.initTables(db);
    EmailService.initTables(db);
    TravelService.initTables(db);
    ExpenseService.initTables(db);

    console.log('[ExecAssistant] All service tables initialized');

    return {
        calendar: CalendarService,
        task: TaskService,
        contact: ContactService,
        financial: FinancialService,
        news: NewsService,
        email: EmailService,
        travel: TravelService,
        expense: ExpenseService
    };
}

/**
 * Register all Executive Assistant command handlers with the bot
 * @param {Object} bot - Telegraf bot instance
 * @param {Object} db - SQLite database instance
 */
function registerExecCommands(bot, db) {
    // Calendar command handler
    bot.command('calendar', async (ctx) => {
        try {
            const args = ctx.message.text.split(' ').slice(1);
            const subcommand = args[0]?.toLowerCase() || 'today';

            switch (subcommand) {
                case 'today': {
                    const events = CalendarService.getEventsForDay(db, getTodayString());
                    if (events.length === 0) {
                        return ctx.replyWithHTML('<b>📅 Today\'s Calendar</b>\n\nNo events scheduled for today.');
                    }
                    const eventList = events.map(e => {
                        const time = e.start_time ? `<code>${escapeHtml(e.start_time)}</code> ` : '';
                        const loc = e.location ? ` 📍 ${escapeHtml(e.location)}` : '';
                        return `• ${time}<b>${escapeHtml(e.title)}</b>${loc}`;
                    }).join('\n');
                    return ctx.replyWithHTML(`<b>📅 Today's Calendar</b>\n\n${eventList}`);
                }

                case 'week': {
                    const events = CalendarService.getEventsForWeek(db);
                    if (events.length === 0) {
                        return ctx.replyWithHTML('<b>📅 This Week</b>\n\nNo events scheduled this week.');
                    }
                    const grouped = {};
                    events.forEach(e => {
                        const day = e.start_date;
                        if (!grouped[day]) grouped[day] = [];
                        grouped[day].push(e);
                    });
                    let response = '<b>📅 This Week\'s Calendar</b>\n';
                    for (const [day, dayEvents] of Object.entries(grouped)) {
                        const dateObj = new Date(day + 'T12:00:00');
                        const dayName = formatInTimezone(dateObj, { weekday: 'long', day: 'numeric', month: 'short' });
                        response += `\n<b>${dayName}</b>\n`;
                        dayEvents.forEach(e => {
                            const time = e.start_time ? `${e.start_time} ` : '';
                            response += `  • ${time}${escapeHtml(e.title)}\n`;
                        });
                    }
                    return ctx.replyWithHTML(response);
                }

                case 'add': {
                    // Format: /calendar add YYYY-MM-DD HH:MM Title
                    const dateStr = args[1];
                    const timeStr = args[2];
                    const title = args.slice(3).join(' ');

                    if (!dateStr || !title) {
                        return ctx.replyWithHTML(
                            '<b>📅 Add Calendar Event</b>\n\n' +
                            'Usage: <code>/calendar add YYYY-MM-DD HH:MM Event Title</code>\n' +
                            'Example: <code>/calendar add 2026-02-04 14:00 Team Meeting</code>'
                        );
                    }

                    const event = CalendarService.createEvent(db, {
                        title,
                        start_date: dateStr,
                        start_time: timeStr || null,
                        reminder_minutes: 15
                    });

                    return ctx.replyWithHTML(
                        `<b>📅 Event Created</b>\n\n` +
                        `<b>${escapeHtml(event.title)}</b>\n` +
                        `📆 ${escapeHtml(event.start_date)} ${event.start_time || ''}`
                    );
                }

                default:
                    return ctx.replyWithHTML(
                        '<b>📅 Calendar Commands</b>\n\n' +
                        '<code>/calendar today</code> - Today\'s events\n' +
                        '<code>/calendar week</code> - This week\'s events\n' +
                        '<code>/calendar add</code> - Add new event'
                    );
            }
        } catch (error) {
            console.error('[ExecAssistant] Calendar error:', error);
            return ctx.replyWithHTML(`❌ Error: ${escapeHtml(error.message)}`);
        }
    });

    // Task command handler
    bot.command('task', async (ctx) => {
        try {
            const args = ctx.message.text.split(' ').slice(1);
            const subcommand = args[0]?.toLowerCase() || 'list';

            switch (subcommand) {
                case 'list': {
                    const category = args[1] || null;
                    const tasks = TaskService.getActiveTasks(db, { category, limit: 20 });
                    if (tasks.length === 0) {
                        return ctx.replyWithHTML('<b>✅ Tasks</b>\n\nNo active tasks.');
                    }
                    const taskList = tasks.map(t => {
                        const priority = t.priority === 'high' ? '🔴' : t.priority === 'medium' ? '🟡' : '🟢';
                        const due = t.due_date ? ` (${t.due_date})` : '';
                        return `${priority} ${escapeHtml(t.title)}${due}`;
                    }).join('\n');
                    return ctx.replyWithHTML(`<b>✅ Active Tasks</b>\n\n${taskList}`);
                }

                case 'add': {
                    // Format: /task add [priority] Title
                    let priority = 'medium';
                    let titleStart = 1;

                    if (['high', 'medium', 'low'].includes(args[1]?.toLowerCase())) {
                        priority = args[1].toLowerCase();
                        titleStart = 2;
                    }

                    const title = args.slice(titleStart).join(' ');
                    if (!title) {
                        return ctx.replyWithHTML(
                            '<b>✅ Add Task</b>\n\n' +
                            'Usage: <code>/task add [high|medium|low] Task Title</code>\n' +
                            'Example: <code>/task add high Review quarterly report</code>'
                        );
                    }

                    const task = TaskService.createTask(db, { title, priority });
                    const priorityEmoji = priority === 'high' ? '🔴' : priority === 'medium' ? '🟡' : '🟢';

                    return ctx.replyWithHTML(
                        `<b>✅ Task Created</b>\n\n` +
                        `${priorityEmoji} ${escapeHtml(task.title)}`
                    );
                }

                case 'done': {
                    const taskId = parseInt(args[1]);
                    if (!taskId) {
                        // Show tasks with IDs for selection
                        const tasks = TaskService.getActiveTasks(db, { limit: 10 });
                        if (tasks.length === 0) {
                            return ctx.replyWithHTML('<b>✅ Complete Task</b>\n\nNo active tasks to complete.');
                        }
                        const taskList = tasks.map(t => `<code>${t.id}</code> - ${escapeHtml(t.title)}`).join('\n');
                        return ctx.replyWithHTML(
                            `<b>✅ Complete Task</b>\n\n` +
                            `Usage: <code>/task done [id]</code>\n\n` +
                            `Active tasks:\n${taskList}`
                        );
                    }

                    const task = TaskService.completeTask(db, taskId);
                    if (!task) {
                        return ctx.replyWithHTML('❌ Task not found.');
                    }
                    return ctx.replyWithHTML(`✅ Completed: <b>${escapeHtml(task.title)}</b>`);
                }

                default:
                    return ctx.replyWithHTML(
                        '<b>✅ Task Commands</b>\n\n' +
                        '<code>/task list</code> - List active tasks\n' +
                        '<code>/task add</code> - Add new task\n' +
                        '<code>/task done</code> - Mark task complete'
                    );
            }
        } catch (error) {
            console.error('[ExecAssistant] Task error:', error);
            return ctx.replyWithHTML(`❌ Error: ${escapeHtml(error.message)}`);
        }
    });

    // Contact command handler
    bot.command('contact', async (ctx) => {
        try {
            const args = ctx.message.text.split(' ').slice(1);
            const subcommand = args[0]?.toLowerCase();

            if (subcommand === 'add') {
                // Format: /contact add Name | email | phone | company
                const data = args.slice(1).join(' ').split('|').map(s => s.trim());
                if (data.length < 1 || !data[0]) {
                    return ctx.replyWithHTML(
                        '<b>👤 Add Contact</b>\n\n' +
                        'Usage: <code>/contact add Name | email | phone | company</code>\n' +
                        'Example: <code>/contact add John Doe | john@example.com | +351912345678 | Acme Corp</code>'
                    );
                }

                const contact = ContactService.createContact(db, {
                    name: data[0],
                    email: data[1] || null,
                    phone: data[2] || null,
                    company: data[3] || null
                });

                return ctx.replyWithHTML(
                    `<b>👤 Contact Created</b>\n\n` +
                    `<b>${escapeHtml(contact.name)}</b>\n` +
                    (contact.email ? `📧 ${escapeHtml(contact.email)}\n` : '') +
                    (contact.phone ? `📱 ${escapeHtml(contact.phone)}\n` : '') +
                    (contact.company ? `🏢 ${escapeHtml(contact.company)}` : '')
                );
            }

            // Default: search by name
            const searchTerm = args.join(' ');
            if (!searchTerm) {
                return ctx.replyWithHTML(
                    '<b>👤 Contact Commands</b>\n\n' +
                    '<code>/contact [name]</code> - Search contacts\n' +
                    '<code>/contact add</code> - Add new contact'
                );
            }

            const contacts = ContactService.searchContacts(db, searchTerm);
            if (contacts.length === 0) {
                return ctx.replyWithHTML(`<b>👤 Contact Search</b>\n\nNo contacts found for "${escapeHtml(searchTerm)}".`);
            }

            const contactList = contacts.slice(0, 5).map(c => {
                let info = `<b>${escapeHtml(c.name)}</b>`;
                if (c.company) info += ` (${escapeHtml(c.company)})`;
                if (c.email) info += `\n  📧 ${escapeHtml(c.email)}`;
                if (c.phone) info += `\n  📱 ${escapeHtml(c.phone)}`;
                return info;
            }).join('\n\n');

            return ctx.replyWithHTML(`<b>👤 Contacts Found</b>\n\n${contactList}`);
        } catch (error) {
            console.error('[ExecAssistant] Contact error:', error);
            return ctx.replyWithHTML(`❌ Error: ${escapeHtml(error.message)}`);
        }
    });

    // Email command handler
    bot.command('email', async (ctx) => {
        try {
            const args = ctx.message.text.split(' ').slice(1);
            const subcommand = args[0]?.toLowerCase() || 'inbox';

            switch (subcommand) {
                case 'inbox': {
                    const emails = EmailService.getInbox(db, { unread_only: false, limit: 10 });
                    if (emails.length === 0) {
                        return ctx.replyWithHTML('<b>📧 Inbox</b>\n\nNo emails in inbox.');
                    }
                    const emailList = emails.map(e => {
                        const unread = e.is_read ? '' : '🔵 ';
                        const date = e.received_at ? e.received_at.split('T')[0] : '';
                        return `${unread}<b>${escapeHtml(e.subject)}</b>\nFrom: ${escapeHtml(e.from_address)} (${date})`;
                    }).join('\n\n');
                    return ctx.replyWithHTML(`<b>📧 Inbox</b>\n\n${emailList}`);
                }

                case 'draft': {
                    // Format: /email draft to@email.com | Subject | Body
                    const data = args.slice(1).join(' ').split('|').map(s => s.trim());
                    if (data.length < 3) {
                        return ctx.replyWithHTML(
                            '<b>📧 Draft Email</b>\n\n' +
                            'Usage: <code>/email draft to@email.com | Subject | Body</code>'
                        );
                    }

                    const draft = EmailService.createDraft(db, {
                        to_address: data[0],
                        subject: data[1],
                        body: data[2]
                    });

                    return ctx.replyWithHTML(
                        `<b>📧 Draft Saved</b>\n\n` +
                        `To: ${escapeHtml(draft.to_address)}\n` +
                        `Subject: ${escapeHtml(draft.subject)}`
                    );
                }

                case 'send': {
                    const draftId = parseInt(args[1]);
                    if (!draftId) {
                        const drafts = EmailService.getDrafts(db, { limit: 5 });
                        if (drafts.length === 0) {
                            return ctx.replyWithHTML('<b>📧 Send Email</b>\n\nNo drafts to send.');
                        }
                        const draftList = drafts.map(d =>
                            `<code>${d.id}</code> - ${escapeHtml(d.subject)} → ${escapeHtml(d.to_address)}`
                        ).join('\n');
                        return ctx.replyWithHTML(
                            `<b>📧 Send Email</b>\n\n` +
                            `Usage: <code>/email send [draft_id]</code>\n\n` +
                            `Drafts:\n${draftList}`
                        );
                    }

                    const sent = EmailService.sendDraft(db, draftId);
                    if (!sent) {
                        return ctx.replyWithHTML('❌ Draft not found.');
                    }
                    return ctx.replyWithHTML(`✅ Email sent: <b>${escapeHtml(sent.subject)}</b>`);
                }

                default:
                    return ctx.replyWithHTML(
                        '<b>📧 Email Commands</b>\n\n' +
                        '<code>/email inbox</code> - View inbox\n' +
                        '<code>/email draft</code> - Create draft\n' +
                        '<code>/email send</code> - Send draft'
                    );
            }
        } catch (error) {
            console.error('[ExecAssistant] Email error:', error);
            return ctx.replyWithHTML(`❌ Error: ${escapeHtml(error.message)}`);
        }
    });

    // Stock command handler
    bot.command('stock', async (ctx) => {
        try {
            const args = ctx.message.text.split(' ').slice(1);
            const symbol = args[0]?.toUpperCase();

            if (!symbol) {
                // Show watchlist
                const watchlist = FinancialService.getWatchlist(db);
                if (watchlist.length === 0) {
                    return ctx.replyWithHTML(
                        '<b>📈 Stock Commands</b>\n\n' +
                        'Usage: <code>/stock [symbol]</code>\n' +
                        'Example: <code>/stock AAPL</code>\n\n' +
                        'No stocks in watchlist.'
                    );
                }
                const stockList = watchlist.map(s => {
                    const change = s.change_percent ? ` (${s.change_percent > 0 ? '+' : ''}${s.change_percent.toFixed(2)}%)` : '';
                    const price = s.current_price ? `$${s.current_price.toFixed(2)}` : 'N/A';
                    return `<b>${escapeHtml(s.symbol)}</b>: ${price}${change}`;
                }).join('\n');
                return ctx.replyWithHTML(`<b>📈 Watchlist</b>\n\n${stockList}`);
            }

            // Get stock quote
            const quote = await FinancialService.getStockQuote(db, symbol);
            if (!quote || !quote.current_price) {
                return ctx.replyWithHTML(`❌ Could not fetch quote for ${escapeHtml(symbol)}`);
            }

            const changeEmoji = quote.change_percent >= 0 ? '📈' : '📉';
            const changeSign = quote.change_percent >= 0 ? '+' : '';

            return ctx.replyWithHTML(
                `<b>${changeEmoji} ${escapeHtml(symbol)}</b>\n\n` +
                `Price: <b>$${quote.current_price.toFixed(2)}</b>\n` +
                `Change: ${changeSign}${quote.change_percent?.toFixed(2) || 0}%\n` +
                (quote.high ? `High: $${quote.high.toFixed(2)}\n` : '') +
                (quote.low ? `Low: $${quote.low.toFixed(2)}\n` : '') +
                (quote.volume ? `Volume: ${quote.volume.toLocaleString()}` : '')
            );
        } catch (error) {
            console.error('[ExecAssistant] Stock error:', error);
            return ctx.replyWithHTML(`❌ Error: ${escapeHtml(error.message)}`);
        }
    });

    // News command handler
    bot.command('news', async (ctx) => {
        try {
            const args = ctx.message.text.split(' ').slice(1);
            const subcommand = args[0]?.toLowerCase() || 'digest';

            switch (subcommand) {
                case 'digest': {
                    const news = NewsService.getLatestNews(db, { limit: 10 });
                    if (news.length === 0) {
                        return ctx.replyWithHTML('<b>📰 News Digest</b>\n\nNo news articles available.');
                    }
                    const newsList = news.map(n => {
                        const source = n.source ? ` (${escapeHtml(n.source)})` : '';
                        return `• <b>${escapeHtml(n.title)}</b>${source}`;
                    }).join('\n\n');
                    return ctx.replyWithHTML(`<b>📰 News Digest</b>\n\n${newsList}`);
                }

                case 'search': {
                    const query = args.slice(1).join(' ');
                    if (!query) {
                        return ctx.replyWithHTML(
                            '<b>📰 Search News</b>\n\n' +
                            'Usage: <code>/news search [query]</code>\n' +
                            'Example: <code>/news search cryptocurrency</code>'
                        );
                    }

                    const results = NewsService.searchNews(db, query);
                    if (results.length === 0) {
                        return ctx.replyWithHTML(`<b>📰 News Search</b>\n\nNo results for "${escapeHtml(query)}".`);
                    }

                    const resultList = results.slice(0, 5).map(n =>
                        `• <b>${escapeHtml(n.title)}</b>\n  ${escapeHtml(n.summary?.substring(0, 100) || '')}...`
                    ).join('\n\n');
                    return ctx.replyWithHTML(`<b>📰 News: ${escapeHtml(query)}</b>\n\n${resultList}`);
                }

                default:
                    return ctx.replyWithHTML(
                        '<b>📰 News Commands</b>\n\n' +
                        '<code>/news digest</code> - Latest news\n' +
                        '<code>/news search</code> - Search news'
                    );
            }
        } catch (error) {
            console.error('[ExecAssistant] News error:', error);
            return ctx.replyWithHTML(`❌ Error: ${escapeHtml(error.message)}`);
        }
    });

    // Travel command handler
    bot.command('travel', async (ctx) => {
        try {
            const args = ctx.message.text.split(' ').slice(1);
            const subcommand = args[0]?.toLowerCase() || 'itinerary';

            switch (subcommand) {
                case 'search': {
                    // Format: /travel search origin destination date
                    const origin = args[1];
                    const destination = args[2];
                    const date = args[3];

                    if (!origin || !destination) {
                        return ctx.replyWithHTML(
                            '<b>✈️ Search Flights</b>\n\n' +
                            'Usage: <code>/travel search [origin] [destination] [date]</code>\n' +
                            'Example: <code>/travel search LIS NYC 2026-03-01</code>'
                        );
                    }

                    const flights = await TravelService.searchFlights(db, {
                        origin,
                        destination,
                        departure_date: date || getTomorrowString()
                    });

                    if (!flights || flights.length === 0) {
                        return ctx.replyWithHTML(`<b>✈️ Flights</b>\n\nNo flights found from ${escapeHtml(origin)} to ${escapeHtml(destination)}.`);
                    }

                    const flightList = flights.slice(0, 5).map(f =>
                        `✈️ <b>${escapeHtml(f.airline || 'Flight')}</b>\n` +
                        `  ${escapeHtml(f.departure_time)} → ${escapeHtml(f.arrival_time)}\n` +
                        `  Price: ${escapeHtml(f.price || 'N/A')}`
                    ).join('\n\n');

                    return ctx.replyWithHTML(`<b>✈️ Flights: ${escapeHtml(origin)} → ${escapeHtml(destination)}</b>\n\n${flightList}`);
                }

                case 'book': {
                    return ctx.replyWithHTML(
                        '<b>✈️ Book Travel</b>\n\n' +
                        'Booking is not yet automated. Please contact your travel agent or use:\n' +
                        '• <a href="https://www.google.com/flights">Google Flights</a>\n' +
                        '• <a href="https://www.booking.com">Booking.com</a>'
                    );
                }

                case 'itinerary': {
                    const trips = TravelService.getUpcomingTrips(db);
                    if (trips.length === 0) {
                        return ctx.replyWithHTML('<b>✈️ Travel Itinerary</b>\n\nNo upcoming trips.');
                    }

                    const tripList = trips.map(t => {
                        let info = `<b>${escapeHtml(t.destination)}</b>\n`;
                        info += `  📅 ${escapeHtml(t.start_date)} - ${escapeHtml(t.end_date)}`;
                        if (t.hotel) info += `\n  🏨 ${escapeHtml(t.hotel)}`;
                        return info;
                    }).join('\n\n');

                    return ctx.replyWithHTML(`<b>✈️ Upcoming Trips</b>\n\n${tripList}`);
                }

                default:
                    return ctx.replyWithHTML(
                        '<b>✈️ Travel Commands</b>\n\n' +
                        '<code>/travel search</code> - Search flights\n' +
                        '<code>/travel book</code> - Booking info\n' +
                        '<code>/travel itinerary</code> - View trips'
                    );
            }
        } catch (error) {
            console.error('[ExecAssistant] Travel error:', error);
            return ctx.replyWithHTML(`❌ Error: ${escapeHtml(error.message)}`);
        }
    });

    // Expense command handler
    bot.command('expense', async (ctx) => {
        try {
            const args = ctx.message.text.split(' ').slice(1);
            const subcommand = args[0]?.toLowerCase() || 'report';

            switch (subcommand) {
                case 'add': {
                    // Format: /expense add amount category description
                    const amount = parseFloat(args[1]);
                    const category = args[2];
                    const description = args.slice(3).join(' ');

                    if (!amount || !category) {
                        return ctx.replyWithHTML(
                            '<b>💰 Add Expense</b>\n\n' +
                            'Usage: <code>/expense add [amount] [category] [description]</code>\n' +
                            'Example: <code>/expense add 50.00 food Business lunch</code>\n\n' +
                            'Categories: food, transport, office, travel, software, other'
                        );
                    }

                    const expense = ExpenseService.addExpense(db, {
                        amount,
                        category,
                        description: description || category,
                        date: getTodayString()
                    });

                    return ctx.replyWithHTML(
                        `<b>💰 Expense Added</b>\n\n` +
                        `Amount: <b>€${expense.amount.toFixed(2)}</b>\n` +
                        `Category: ${escapeHtml(expense.category)}\n` +
                        `Description: ${escapeHtml(expense.description)}`
                    );
                }

                case 'report': {
                    const period = args[1] || 'month';
                    const report = ExpenseService.getExpenseReport(db, { period });

                    if (!report || report.total === 0) {
                        return ctx.replyWithHTML(`<b>💰 Expense Report (${escapeHtml(period)})</b>\n\nNo expenses recorded.`);
                    }

                    let response = `<b>💰 Expense Report (${escapeHtml(period)})</b>\n\n`;
                    response += `Total: <b>€${report.total.toFixed(2)}</b>\n\n`;

                    if (report.by_category) {
                        response += '<b>By Category:</b>\n';
                        for (const [cat, amount] of Object.entries(report.by_category)) {
                            response += `  • ${escapeHtml(cat)}: €${amount.toFixed(2)}\n`;
                        }
                    }

                    return ctx.replyWithHTML(response);
                }

                default:
                    return ctx.replyWithHTML(
                        '<b>💰 Expense Commands</b>\n\n' +
                        '<code>/expense add</code> - Add expense\n' +
                        '<code>/expense report</code> - View report'
                    );
            }
        } catch (error) {
            console.error('[ExecAssistant] Expense error:', error);
            return ctx.replyWithHTML(`❌ Error: ${escapeHtml(error.message)}`);
        }
    });

    // Daily briefing command
    bot.command('briefing', async (ctx) => {
        try {
            const briefing = await generateDailyBriefing(db, {});
            return ctx.replyWithHTML(briefing);
        } catch (error) {
            console.error('[ExecAssistant] Briefing error:', error);
            return ctx.replyWithHTML(`❌ Error generating briefing: ${escapeHtml(error.message)}`);
        }
    });

    console.log('[ExecAssistant] All command handlers registered');
}

/**
 * Start all background processors for Executive Assistant services
 * @param {Object} db - SQLite database instance
 * @param {Object} bot - Telegraf bot instance
 * @param {Object} options - Configuration options
 * @param {string} options.chatId - Chat ID to send notifications to
 * @returns {Object} Object containing interval IDs for all processors
 */
function startExecProcessors(db, bot, options = {}) {
    const { chatId } = options;
    const intervals = {};

    /**
     * Send notification to configured chat
     * @param {string} message - HTML formatted message
     */
    async function sendNotification(message) {
        if (!chatId) return;
        try {
            await bot.telegram.sendMessage(chatId, message, { parse_mode: 'HTML' });
        } catch (error) {
            console.error('[ExecAssistant] Notification error:', error.message);
        }
    }

    // Calendar reminder processor (every 1 minute)
    intervals.calendarReminder = setInterval(async () => {
        try {
            const reminders = CalendarService.getUpcomingReminders(db, 15); // 15 minute window
            for (const event of reminders) {
                const timeStr = event.start_time ? ` at ${event.start_time}` : '';
                await sendNotification(
                    `🔔 <b>Calendar Reminder</b>\n\n` +
                    `<b>${escapeHtml(event.title)}</b>${timeStr}\n` +
                    (event.location ? `📍 ${escapeHtml(event.location)}` : '')
                );
                CalendarService.markReminderSent(db, event.id);
            }
        } catch (error) {
            console.error('[ExecAssistant] Calendar reminder error:', error.message);
        }
    }, 60 * 1000);

    // Task reminder processor (every 1 minute)
    intervals.taskReminder = setInterval(async () => {
        try {
            const reminders = TaskService.getDueReminders(db);
            for (const task of reminders) {
                await sendNotification(
                    `🔔 <b>Task Reminder</b>\n\n` +
                    `<b>${escapeHtml(task.title)}</b>\n` +
                    (task.due_date ? `📅 Due: ${escapeHtml(task.due_date)}` : '')
                );
                TaskService.markReminderSent(db, task.id);
            }
        } catch (error) {
            console.error('[ExecAssistant] Task reminder error:', error.message);
        }
    }, 60 * 1000);

    // Financial monitor (every 5 minutes)
    intervals.financialMonitor = setInterval(async () => {
        try {
            const alerts = await FinancialService.checkPriceAlerts(db);
            for (const alert of alerts) {
                const emoji = alert.type === 'above' ? '📈' : '📉';
                await sendNotification(
                    `${emoji} <b>Stock Alert: ${escapeHtml(alert.symbol)}</b>\n\n` +
                    `Price ${alert.type === 'above' ? 'above' : 'below'} $${alert.threshold}\n` +
                    `Current: <b>$${alert.current_price.toFixed(2)}</b>`
                );
                FinancialService.markAlertTriggered(db, alert.id);
            }
        } catch (error) {
            console.error('[ExecAssistant] Financial monitor error:', error.message);
        }
    }, 5 * 60 * 1000);

    // News processor (every 30 minutes)
    intervals.newsProcessor = setInterval(async () => {
        try {
            await NewsService.fetchAndCacheNews(db);
        } catch (error) {
            console.error('[ExecAssistant] News processor error:', error.message);
        }
    }, 30 * 60 * 1000);

    // Document expiry checker (every 24 hours)
    intervals.documentExpiry = setInterval(async () => {
        try {
            const expiringDocs = TravelService.getExpiringDocuments(db, 30); // 30 days warning
            for (const doc of expiringDocs) {
                const daysUntil = Math.ceil((new Date(doc.expiry_date) - getNow()) / (1000 * 60 * 60 * 24));
                await sendNotification(
                    `⚠️ <b>Document Expiring Soon</b>\n\n` +
                    `<b>${escapeHtml(doc.type)}</b>: ${escapeHtml(doc.number || 'N/A')}\n` +
                    `Expires: ${escapeHtml(doc.expiry_date)} (${daysUntil} days)`
                );
            }
        } catch (error) {
            console.error('[ExecAssistant] Document expiry error:', error.message);
        }
    }, 24 * 60 * 60 * 1000);

    console.log('[ExecAssistant] All background processors started');

    return {
        intervals,
        stop: () => {
            Object.values(intervals).forEach(clearInterval);
            console.log('[ExecAssistant] All background processors stopped');
        }
    };
}

/**
 * Generate daily executive briefing
 * @param {Object} db - SQLite database instance
 * @param {Object} options - Configuration options
 * @returns {Promise<string>} HTML formatted briefing
 */
async function generateDailyBriefing(db, options = {}) {
    const today = getTodayString();
    const now = getNow();
    const timeStr = formatInTimezone(now, { hour: '2-digit', minute: '2-digit' });
    const dateStr = formatInTimezone(now, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });

    let briefing = `<b>☀️ Daily Briefing</b>\n`;
    briefing += `<i>${dateStr} • ${timeStr}</i>\n`;
    briefing += `━━━━━━━━━━━━━━━━━━━━\n\n`;

    // Today's calendar
    try {
        const events = CalendarService.getEventsForDay(db, today);
        briefing += `<b>📅 Today's Schedule</b>\n`;
        if (events.length === 0) {
            briefing += `  No events scheduled\n`;
        } else {
            events.forEach(e => {
                const time = e.start_time ? `${e.start_time} ` : '';
                briefing += `  • ${time}${escapeHtml(e.title)}\n`;
            });
        }
        briefing += `\n`;
    } catch (error) {
        console.error('[ExecAssistant] Briefing calendar error:', error.message);
    }

    // Tasks due today
    try {
        const tasksDue = TaskService.getTasksDueOn(db, today);
        const overdue = TaskService.getOverdueTasks(db);

        if (overdue.length > 0) {
            briefing += `<b>🔴 Overdue Tasks</b>\n`;
            overdue.slice(0, 5).forEach(t => {
                briefing += `  • ${escapeHtml(t.title)} (${t.due_date})\n`;
            });
            briefing += `\n`;
        }

        briefing += `<b>✅ Tasks Due Today</b>\n`;
        if (tasksDue.length === 0) {
            briefing += `  No tasks due today\n`;
        } else {
            tasksDue.forEach(t => {
                const priority = t.priority === 'high' ? '🔴' : t.priority === 'medium' ? '🟡' : '🟢';
                briefing += `  ${priority} ${escapeHtml(t.title)}\n`;
            });
        }
        briefing += `\n`;
    } catch (error) {
        console.error('[ExecAssistant] Briefing tasks error:', error.message);
    }

    // Stock watchlist
    try {
        const watchlist = FinancialService.getWatchlist(db);
        if (watchlist.length > 0) {
            briefing += `<b>📈 Markets</b>\n`;
            for (const stock of watchlist.slice(0, 5)) {
                if (stock.current_price) {
                    const change = stock.change_percent || 0;
                    const emoji = change >= 0 ? '▲' : '▼';
                    const sign = change >= 0 ? '+' : '';
                    briefing += `  ${escapeHtml(stock.symbol)}: $${stock.current_price.toFixed(2)} ${emoji}${sign}${change.toFixed(1)}%\n`;
                }
            }
            briefing += `\n`;
        }
    } catch (error) {
        console.error('[ExecAssistant] Briefing stocks error:', error.message);
    }

    // Unread news
    try {
        const news = NewsService.getLatestNews(db, { unread: true, limit: 5 });
        if (news.length > 0) {
            briefing += `<b>📰 Headlines</b>\n`;
            news.forEach(n => {
                briefing += `  • ${escapeHtml(n.title)}\n`;
            });
            briefing += `\n`;
        }
    } catch (error) {
        console.error('[ExecAssistant] Briefing news error:', error.message);
    }

    // Upcoming birthdays
    try {
        const birthdays = ContactService.getUpcomingBirthdays(db, 7);
        if (birthdays.length > 0) {
            briefing += `<b>🎂 Upcoming Birthdays</b>\n`;
            birthdays.forEach(c => {
                const bday = new Date(c.birthday + 'T12:00:00');
                const dayStr = formatInTimezone(bday, { month: 'short', day: 'numeric' });
                briefing += `  • ${escapeHtml(c.name)} (${dayStr})\n`;
            });
            briefing += `\n`;
        }
    } catch (error) {
        console.error('[ExecAssistant] Briefing birthdays error:', error.message);
    }

    briefing += `━━━━━━━━━━━━━━━━━━━━\n`;
    briefing += `<i>Have a productive day!</i>`;

    return briefing;
}

/**
 * Generate evening briefing/summary
 * @param {Object} db - SQLite database instance
 * @param {Object} options - Configuration options
 * @returns {Promise<string>} HTML formatted evening briefing
 */
async function generateEveningBriefing(db, options = {}) {
    const today = getTodayString();
    const tomorrow = getTomorrowString();
    const now = getNow();
    const dateStr = formatInTimezone(now, { weekday: 'long', day: 'numeric', month: 'long' });

    let briefing = `<b>🌙 Evening Summary</b>\n`;
    briefing += `<i>${dateStr}</i>\n`;
    briefing += `━━━━━━━━━━━━━━━━━━━━\n\n`;

    // Completed tasks today
    try {
        const completed = TaskService.getCompletedTasks(db, { since: today });
        briefing += `<b>✅ Completed Today</b>\n`;
        if (completed.length === 0) {
            briefing += `  No tasks completed today\n`;
        } else {
            completed.forEach(t => {
                briefing += `  ✓ ${escapeHtml(t.title)}\n`;
            });
        }
        briefing += `\n`;
    } catch (error) {
        console.error('[ExecAssistant] Evening briefing tasks error:', error.message);
    }

    // Tomorrow's calendar preview
    try {
        const tomorrowEvents = CalendarService.getEventsForDay(db, tomorrow);
        const tomorrowDate = new Date(tomorrow + 'T12:00:00');
        const tomorrowStr = formatInTimezone(tomorrowDate, { weekday: 'long' });

        briefing += `<b>📅 Tomorrow (${tomorrowStr})</b>\n`;
        if (tomorrowEvents.length === 0) {
            briefing += `  No events scheduled\n`;
        } else {
            tomorrowEvents.forEach(e => {
                const time = e.start_time ? `${e.start_time} ` : '';
                briefing += `  • ${time}${escapeHtml(e.title)}\n`;
            });
        }
        briefing += `\n`;
    } catch (error) {
        console.error('[ExecAssistant] Evening briefing calendar error:', error.message);
    }

    // Monthly expense status
    try {
        const report = ExpenseService.getExpenseReport(db, { period: 'month' });
        const budget = ExpenseService.getMonthlyBudget(db);

        if (report && report.total > 0) {
            briefing += `<b>💰 Monthly Expenses</b>\n`;
            briefing += `  Spent: €${report.total.toFixed(2)}`;

            if (budget && budget.amount > 0) {
                const remaining = budget.amount - report.total;
                const percentage = ((report.total / budget.amount) * 100).toFixed(0);
                briefing += ` / €${budget.amount.toFixed(2)} (${percentage}%)\n`;

                if (remaining < 0) {
                    briefing += `  ⚠️ Over budget by €${Math.abs(remaining).toFixed(2)}\n`;
                } else {
                    briefing += `  Remaining: €${remaining.toFixed(2)}\n`;
                }
            } else {
                briefing += `\n`;
            }
            briefing += `\n`;
        }
    } catch (error) {
        console.error('[ExecAssistant] Evening briefing expense error:', error.message);
    }

    // Pending high-priority tasks
    try {
        const highPriority = TaskService.getActiveTasks(db, { priority: 'high', limit: 5 });
        if (highPriority.length > 0) {
            briefing += `<b>🔴 High Priority Pending</b>\n`;
            highPriority.forEach(t => {
                const due = t.due_date ? ` (${t.due_date})` : '';
                briefing += `  • ${escapeHtml(t.title)}${due}\n`;
            });
            briefing += `\n`;
        }
    } catch (error) {
        console.error('[ExecAssistant] Evening briefing high priority error:', error.message);
    }

    briefing += `━━━━━━━━━━━━━━━━━━━━\n`;
    briefing += `<i>Rest well!</i>`;

    return briefing;
}

module.exports = {
    initializeExecAssistant,
    registerExecCommands,
    startExecProcessors,
    generateDailyBriefing,
    generateEveningBriefing,
    TIMEZONE
};
