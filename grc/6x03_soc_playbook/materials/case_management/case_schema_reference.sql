CREATE TABLE IF NOT EXISTS cases (
    case_id     TEXT PRIMARY KEY,
    alert_id    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT,
    status      TEXT NOT NULL DEFAULT 'open',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    resolution  TEXT
);

CREATE TABLE IF NOT EXISTS case_notes (
    note_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL,
    note        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

CREATE TABLE IF NOT EXISTS case_iocs (
    ioc_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL,
    ioc_value   TEXT NOT NULL,
    ioc_type    TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    score       INTEGER NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);
