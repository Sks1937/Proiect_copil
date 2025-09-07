import Database from "better-sqlite3";
import fs from "fs";
const db = new Database("./auth.db");
const schema = fs.readFileSync(new URL("./schema.sql", import.meta.url), "utf8");
db.exec(schema);
export default db;
