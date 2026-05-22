<?php

class SSE {

    /**
     * Send the required HTTP headers to start an SSE stream.
     * Must be called before any output is sent.
     */
    public static function start(): void {
        // Tell the browser this is a stream, not a regular response
        header('Content-Type: text/event-stream');

        // Disable caching — SSE must always be fresh
        header('Cache-Control: no-cache');

        // Keep the connection open through proxies and load balancers
        header('X-Accel-Buffering: no');

        // Allow Vue frontend (different port) to receive this stream
        header('Access-Control-Allow-Origin: *');

        // Turn off PHP's output buffering — send data immediately
        if (ob_get_level() > 0) {
            ob_end_clean();
        }

        // Disable time limit — this script runs until all engines finish
        set_time_limit(0);
    }

    /**
     * Send a single SSE event to the browser.
     *
     * @param string $event  Event type — frontend listens for this name
     * @param array  $data   Payload — will be JSON encoded
     */
    public static function send(string $event, array $data): void {
        // SSE format: event name on one line, data on next, blank line to end
        echo "event: {$event}\n";
        echo "data: " . json_encode($data) . "\n\n";

        // Force PHP to flush output buffer — sends immediately to browser
        flush();
    }

    /**
     * Send a heartbeat to keep the connection alive.
     * Useful for long-running engines — prevents browser timeout.
     */
    public static function heartbeat(): void {
        // SSE comment line — browser ignores it but connection stays alive
        echo ": heartbeat\n\n";
        flush();
    }

    /**
     * Signal the browser that all engines are done.
     * Frontend listens for this to finalize the UI.
     */
    public static function done(array $summary): void {
        self::send('done', $summary);
    }
}