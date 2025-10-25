-- Initialize MySQL database for TrueShotOdds
CREATE DATABASE IF NOT EXISTS trueshot_odds;
USE trueshot_odds;

-- Set timezone
SET time_zone = '+00:00';

-- Create user if not exists (for non-root access)
CREATE USER IF NOT EXISTS 'trueshot'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON trueshot_odds.* TO 'trueshot'@'%';
FLUSH PRIVILEGES;