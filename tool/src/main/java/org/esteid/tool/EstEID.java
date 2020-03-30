package org.esteid.tool;

import apdu4j.BIBO;
import apdu4j.i.SmartCardApp;
import com.google.auto.service.AutoService;
import picocli.CommandLine;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

// Tool for apdu4j
@AutoService(SmartCardApp.class)
public class EstEID implements SmartCardApp {
    public static void main(String[] args) {

        // Get the reader
        System.out.println("esteid " + getVersion());

        // Call CLI
    }

    @Override
    public int run(BIBO bibo, String[] args) {
        CLI tool = new CLI();
        CommandLine cli = new CommandLine(tool);
        cli.execute(args);
        return 0;
    }

    static String getVersion() {
        String version = "unknown-development";
        try (InputStream versionfile = org.esteid.EstEID.class.getResourceAsStream("pro_version.txt")) {
            if (versionfile != null) {
                try (BufferedReader vinfo = new BufferedReader(new InputStreamReader(versionfile, "UTF-8"))) {
                    version = vinfo.readLine();
                }
            }
        } catch (IOException e) {
            version = "unknown-error";
        }
        return version;
    }

}