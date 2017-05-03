package test;

import encryptionscheme.RC4;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

/**
 * This class is the main driver class for testing the RC4 encryption.
 * @author Jabo Johnigan
 * @version 4/29/17
 *
 */
public class Main {


    public static void main(String[] args) throws IOException {

        long startTime = System.currentTimeMillis();
        String inFile = readFile("kjvb.txt");
        byte[] plainData = inFile.getBytes();
        byte[] key = "BoJackBruh".getBytes();
        try {
            RC4 rc4 = new RC4(key, plainData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        long time = System.currentTimeMillis() - startTime;
        System.out.println("Encoding Process took : " + time + " ms");
    }

    /**
     * This method reads in the file as a string.
     * @param fileName name of file.
     * @return the file represented as a string.
     * @throws IOException no file found
     */
    private static String readFile(final String fileName) throws IOException {
        FileReader file = new FileReader(fileName);
        BufferedReader reader = new BufferedReader(file);
        String everything = null;
        try {
            StringBuilder sb = new StringBuilder();
            String line = reader.readLine();

            while (line != null) {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = reader.readLine();
            }
            everything = sb.toString();


        } finally {
            reader.close();

        }
        return everything;

    }
}