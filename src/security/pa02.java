package security;/*
Does not include a header on rubric or assignment so here is my own!! :D
| Assignment: security.pa02 - Check Sum
|
| Author: Darren Squires
| Language: Java
| To Compile: javac security.pa01.java
| gcc -o security.pa01 security.pa01.c
| g++ -o security.pa01 security.pa01.cpp
| go build security.pa01.go
| rustc security.pa01.rs
| To Execute: java -> java security.pa01 kX.txt pX.txt
| or c++ -> ./security.pa01 kX.txt pX.txt
| or c -> ./security.pa01 kX.txt pX.txt
| or go -> ./security.pa01 kX.txt pX.txt
| or rust -> ./security.pa01 kX.txt pX.txt
| or python -> python3 security.pa01.py kX.txt pX.txt
| where kX.txt is the keytext file
| and pX.txt is plaintext file
| Note:
| All input files are simple 8 bit ASCII input
| All execute commands above have been tested on Eustis
|
| Class: CIS3360 - Security in Computing - Spring 2025
| Instructor: McAlpin
| Due Date: 03/23/25

*/

import java.io.*;
import java.nio.file.*;

public class pa02 {
    private static final int MAX_LINE = 80;

    // Function to load file content into buffer
    public static byte[] loadFileContent(String filePath) throws IOException {
        byte[] content = Files.readAllBytes(Paths.get(filePath));

        // Ensure newline at the end (like in the C version)
        if (content.length == 0 || content[content.length - 1] != '\n') {
            byte[] modifiedContent = new byte[content.length + 1];
            System.arraycopy(content, 0, modifiedContent, 0, content.length);
            modifiedContent[modifiedContent.length - 1] = '\n';
            return modifiedContent;
        }

        return content;
    }

    // Function to determine padding based on checksum size
    public static int getPaddingCount(int dataLength, int checksumBits) {
        if (checksumBits == 16) {
            return (dataLength % 2 == 0) ? 0 : 1;
        } else if (checksumBits == 32) {
            return (dataLength % 4 == 0) ? 0 : (4 - (dataLength % 4));
        }
        return 0;
    }

    // Function to display input data with padding
    public static void displayInputData(byte[] inputData, int paddingCount) {
        int lineCharCount = 0;
        StringBuilder output = new StringBuilder("\n");

        // Print out characters
        for (byte b : inputData) {
            output.append((char) b);
            lineCharCount++;
            if (lineCharCount == MAX_LINE) {
                output.append("\n");
                lineCharCount = 0;
            }
        }
        for (int i = 0; i < paddingCount; i++) {
            output.append("X");
            lineCharCount++;
            if (lineCharCount == MAX_LINE && i != paddingCount - 1) {
                output.append("\n");
                lineCharCount = 0;
            }
        }

        // Ensure output ends with a newline
        if (lineCharCount != 0) {
            output.append("\n");
        }

        System.out.print(output);
    }

    // Function to calculate checksum
    public static long calculateChecksum(byte[] buffer, int checksumBits) {
        long checksumSum = 0;
        int i = 0;
        int length = buffer.length;

        switch (checksumBits) {
            case 8:
                while (i < length) {
                    checksumSum += (buffer[i] & 0xFF);
                    i++;
                }
                break;
            case 16:
                while (i + 1 < length) {
                    int word = ((buffer[i] & 0xFF) << 8) | (buffer[i + 1] & 0xFF);
                    checksumSum += word;
                    i += 2;
                }
                break;
            case 32:
                while (i + 3 < length) {
                    long word = ((buffer[i] & 0xFFL) << 24) |
                            ((buffer[i + 1] & 0xFFL) << 16) |
                            ((buffer[i + 2] & 0xFFL) << 8) |
                            (buffer[i + 3] & 0xFFL);
                    checksumSum += word;
                    i += 4;
                }
                break;
            default:
                System.out.println("Wrong checksum size.");
                return -1;
        }

        return switch (checksumBits) {
            case 8 -> checksumSum & 0xFF;
            case 16 -> checksumSum & 0xFFFF;
            default -> checksumSum & 0xFFFFFFFFL; // For 32-bit
        };
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("Usage: java ChecksumCalculator <file_path> <checksum_bits>");
            System.exit(1);
        }

        String filePath = args[0];
        int checksumBits;

        try {
            checksumBits = Integer.parseInt(args[1]);
            if (checksumBits != 8 && checksumBits != 16 && checksumBits != 32) {
                System.err.println("Checksum size must be 8, 16, or 32.");
                return;
            }

            // Load file content
            byte[] inputData = loadFileContent(filePath);
            int dataLength = inputData.length;

            // Determine padding needed
            int paddingCount = getPaddingCount(dataLength, checksumBits);
            int totalDataLength = dataLength + paddingCount;

            // Creates checksum buffer
            byte[] checksumBuffer = new byte[totalDataLength];
            System.arraycopy(inputData, 0, checksumBuffer, 0, dataLength);
            for (int i = dataLength; i < totalDataLength; i++) {
                checksumBuffer[i] = 'X'; // Adding padding
            }

            // Displays data and padding
            displayInputData(inputData, paddingCount);

            // Calculates checksum
            long checksumValue = calculateChecksum(checksumBuffer, checksumBits);

            // Output checksum result
            System.out.printf("%2d bit checksum is %8x for all %4d chars%n", checksumBits, checksumValue, totalDataLength);
        }
        catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        }
        catch (NumberFormatException e) {
            System.err.println("Invalid checksum bit size.");
        }
    }
}
/*=============================================================================
| I Darren Squires Jr (da177548) affirm that this program is
| entirely my own work and that I have neither developed my code together with
| any another person, nor copied any code from any other person, nor permitted
| my code to be copied or otherwise used by any other person, nor have I
| copied, modified, or otherwise used programs created by others. I acknowledge
| that any violation of the above terms will be treated as academic dishonesty.
+=============================================================================*/