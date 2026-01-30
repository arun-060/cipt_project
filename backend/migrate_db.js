const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('users.db');

console.log('🔧 Migrating database...');

db.serialize(() => {
    // Drop the old answers table
    db.run('DROP TABLE IF EXISTS answers', (err) => {
        if (err) {
            console.error('Error dropping table:', err);
            return;
        }
        console.log('✅ Dropped old answers table');

        // Create new answers table with correct structure
        db.run(`
      CREATE TABLE answers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        question INTEGER,
        video_filename TEXT,
        domain TEXT,
        timestamp INTEGER
      )
    `, (err) => {
            if (err) {
                console.error('Error creating table:', err);
                return;
            }
            console.log('✅ Created new answers table with correct structure');
            console.log('✅ Migration complete!');
            db.close();
        });
    });
});
