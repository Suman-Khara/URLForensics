<?php

// Load Composer's autoloader — makes all installed libraries available
require_once __DIR__ . '/../vendor/autoload.php';

// Load environment variables from .env into $_ENV
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->load();

// Validate that required variables actually exist in .env
// If any are missing, this throws an error immediately — fail loud, fail early
$dotenv->required(['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASS']);

class DB {

    private static ?PDO $instance = null;

    private function __construct() {}

    public static function connect(): PDO {

        if (self::$instance === null) {

            $dsn = "mysql:host={$_ENV['DB_HOST']};dbname={$_ENV['DB_NAME']};charset=utf8mb4";

            $options = [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ];

            try {
                self::$instance = new PDO($dsn, $_ENV['DB_USER'], $_ENV['DB_PASS'], $options);
            } catch (PDOException $e) {
                error_log('DB connection failed: ' . $e->getMessage());
                throw new RuntimeException('Database connection failed');
            }
        }

        return self::$instance;
    }

    private function __clone() {}
}