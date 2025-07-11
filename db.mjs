import 'dotenv/config'
import { Pool } from "pg";

const databaseCheck = new Pool({
  user: process.env.PGUSER,
  host: process.env.PGHOST,
  database: process.env.PGDATABASE,
  password: process.env.PGPASSWORD,
  port: process.env.PGPORT, 
  ssl: {
    rejectUnauthorized : false
  }
});

export default databaseCheck;