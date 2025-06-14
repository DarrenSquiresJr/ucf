package security;/*============================================================================
| Assignment: security.pa01 - Encrypting a plaintext file using the Hill cipher
|
| Author: Darren Squires Jr
| Language: Java
| To Compile: javac security.pa01.java
| To Execute: java security.pa01 kX.txt pX.txt
| where kX.txt is the keytext file
| and pX.txt is plaintext file
| Note:
| All input files are simple 8 bit ASCII input
| All execute commands above have been tested on Eustis
|
| Class: CIS3360 - Security in Computing - Spring 2025
| Instructor: McAlpin
| Due Date: per assignment
+===========================================================================*/

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class pa01 {
    // Constants
    private static final int MAX_TEXT_SIZE = 10000;
    private static final int MAX_KEY_SIZE = 9;

    // Function to compute mod 26 of a number, ensuring it is positive
    public static int mod26(int num) {
        num = num % 26;
        if (num < 0) {
            num += 26;
        }
        return num;
    }

    // Function to read the key matrix from a file
    public static void readKeyText(String filename, int[] keySizePtr, int[][] keyMatrix) {
        try {
            Scanner keyFile = new Scanner(new File(filename));
            if (!keyFile.hasNextInt()) {
                System.out.println("Error reading key size");
                keyFile.close();
                System.exit(1);
            }

            keySizePtr[0] = keyFile.nextInt();

            if (keySizePtr[0] <= 1 || keySizePtr[0] >= 10) {
                System.out.println("Invalid key size");
                keyFile.close();
                System.exit(1);
            }

            for (int i = 0; i < keySizePtr[0]; i++) {
                for (int j = 0; j < keySizePtr[0]; j++) {
                    if (!keyFile.hasNextInt()) {
                        System.out.println("Error reading key matrix");
                        keyFile.close();
                        System.exit(1);
                    }
                    keyMatrix[i][j] = keyFile.nextInt();
                }
            }

            keyFile.close();
        }
        catch (FileNotFoundException e) {
            System.out.println("Error opening key file");
            System.exit(1);
        }
    }

    // Function to filter and convert text to lowercase
    private static String filterText(String text) {
        StringBuilder filtered = new StringBuilder();
        text = text.toLowerCase(); // Convert to lowercase first

        // Loop through each character in the text
        for (char c : text.toCharArray()) {
            // Keep only English letters (a-z) after converting to lowercase
            if (c >= 'a' && c <= 'z') {
                filtered.append(c);
            }
        }

        return filtered.toString();
    }

    // Function to read the plaintext from a file
    public static int readPlaintext(String filename, char[] plainText) {
        StringBuilder text = new StringBuilder();
        try {
            Scanner plainFile = new Scanner(new File(filename));
            while (plainFile.hasNext()) {
                String line = plainFile.nextLine();
                text.append(line); // Collect all lines of the file
            }
            plainFile.close();
        }
        catch (FileNotFoundException e) {
            System.out.println("Error opening plaintext file");
            System.exit(1);
        }

        // Filter text to keep only lowercase a-z letters
        String filteredText = filterText(text.toString());

        int textLength = filteredText.length();
        if (textLength >= MAX_TEXT_SIZE) {
            System.out.println("Plaintext too long");
            System.exit(1);
        }

        for (int i = 0; i < textLength; i++) {
            plainText[i] = filteredText.charAt(i);
        }
        return textLength;
    }

    // Function to encrypt the plaintext using the Hill cipher
    public static void encryptPlaintext(char[] plainText, int textLength, int keySize, int[][] keyMatrix, char[] cipherText) {
        // Calculate the number of blocks in the plaintext
        int numBlocks = textLength / keySize;
        int blockIndex = 0; // Index for the current block

        // Process each block of plaintext
        while (blockIndex < numBlocks) {
            for (int row = 0; row < keySize; row++) {
                long sum = 0;
                for (int col = 0; col < keySize; col++) {
                    int ptIndex = blockIndex * keySize + col; // Index in plaintext
                    long ptValue = plainText[ptIndex] - 'a';  // Convert character to 0-25

                    // Multiply corresponding matrix and plaintext values
                    sum += (long) keyMatrix[row][col] * ptValue;
                }

                // Apply mod26 to wrap within alphabet range
                sum = mod26((int) sum);

                // Convert back to character and store in ciphertext
                cipherText[blockIndex * keySize + row] = (char) (sum + 'a');
            }
            blockIndex++;
        }
        cipherText[textLength] = '\0'; // Null-terminate the ciphertext string
    }

    // Function to print the key matrix
    public static void printKeyMatrix(int keySize, int[][] keyMatrix) {
        for (int i = 0; i < keySize; i++) {
            for (int j = 0; j < keySize; j++) {
                System.out.printf("%4d", keyMatrix[i][j]);
            }
            System.out.println();
        }
    }

    // Function to print text with optional label and line breaks after 80 characters
    public static void printText(String label, char[] text, int textLength) {
        if (label != null) {
            System.out.println(label + ":");
        }
        int lineLength = 0;
        for (int i = 0; i < textLength; i++) {
            System.out.print(text[i]);
            lineLength++;
            if (lineLength == 80) {
                System.out.println();
                lineLength = 0;
            }
        }
        if (lineLength != 0) {
            System.out.println();
        }
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java security.pa01 <keyfile> <plaintextfile>");
            System.exit(1);
        }

        // Variable declaration
        int[] keySize = new int[1];
        int[][] keyMatrix = new int[MAX_KEY_SIZE][MAX_KEY_SIZE];
        char[] plainText = new char[MAX_TEXT_SIZE];
        char[] cipherText = new char[MAX_TEXT_SIZE];
        int textLength;

        // Read the key from key file
        readKeyText(args[0], keySize, keyMatrix);

        // Read the plaintext from plaintext file
        textLength = readPlaintext(args[1], plainText);

        // Pad the plaintext with x characters if necessary
        while (textLength % keySize[0] != 0) {
            plainText[textLength] = 'x';
            textLength++;
        }
        plainText[textLength] = '\0';

        // Print the key matrix
        System.out.println("\nKey matrix:");
        printKeyMatrix(keySize[0], keyMatrix);

        // Print the plaintext
        System.out.println("\nPlaintext:");
        printText(null, plainText, textLength);

        // Encrypt the plaintext using the key matrix
        encryptPlaintext(plainText, textLength, keySize[0], keyMatrix, cipherText);

        // Print the ciphertext
        System.out.println("\nCiphertext:");
        printText(null, cipherText, textLength);
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