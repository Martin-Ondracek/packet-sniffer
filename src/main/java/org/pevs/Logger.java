package org.pevs;

import sun.rmi.runtime.Log;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.sql.Timestamp;
import java.util.Timer;

public class Logger {

    private static final String log = "sniffer.log";
    File file;

    public Logger() {
        this.file = new File(log);
        createFile();
    }

    private void createFile() {
        try {
            file.createNewFile();
        } catch (IOException ignored) {
        }
    }

    private void createLog(String log) {
        log = log + "\n";
        Path path = Paths.get(file.getAbsolutePath());
        try {
            Files.write(path, log.getBytes(), StandardOpenOption.APPEND);
        } catch (IOException ignored) {
        }

    }

    public void logInfo(String text) {
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        createLog(timestamp + " INFO: " + text);
    }

    public void logError(String text) {
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        createLog(timestamp + " ERROR: " + text);
    }

    public void logWarning(String text) {
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        createLog(timestamp + " WARNING: " + text);
    }
}

