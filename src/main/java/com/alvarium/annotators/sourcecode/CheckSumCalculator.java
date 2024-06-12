
/*******************************************************************************
 * Copyright 2024 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *******************************************************************************/
package com.alvarium.annotators.sourcecode;


import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.text.Collator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import com.alvarium.hash.HashProvider;
import com.alvarium.hash.HashProviderFactory;
import com.alvarium.hash.HashType;
import com.alvarium.hash.HashTypeException;

import com.alvarium.annotators.AnnotatorException;

public class CheckSumCalculator {

    private final HashType hash;

    private HashProvider hashProvider;

    public CheckSumCalculator(HashType hash) throws AnnotatorException {
        this.hash = hash;
        this.initHashProvider(this.hash);
    }

    /**
     *  Initializes the hash provider used to hash the source code 
     * @return HashProvider
     * @throws AnnotatorException - If hashing algorithm not found, 
     * or if an unknown exception was thrown
     */
    private final void initHashProvider(HashType hashType) throws AnnotatorException {
        try {
             this.hashProvider = new HashProviderFactory().getProvider(hashType);
        } catch (HashTypeException e) {
            throw new AnnotatorException("Hashing algorithm not found, could not hash data or generate checksum", e);
        } catch (Exception e) {
            throw new AnnotatorException("Could not hash data or generate checksum", e);
        }
    }

    /**
     * Recursively gets all files in a directory as a list of absolute paths
     * @param path
     * @return List<String> of all files in directory
     */
    private List<String> getAllFiles(String path) {
        List<String> files = new ArrayList<>();
        File directory = new File(path);

        if (directory.isDirectory()) {
            File[] directoryFiles = directory.listFiles();
            if (directoryFiles != null) {
                for (File file : directoryFiles) {
                    if (file.isFile()) {
                        files.add(file.getAbsolutePath());
                    } else if (file.isDirectory()) {
                        files.addAll(getAllFiles(file.getAbsolutePath()));
                    }
                }
            }
        } else if (directory.isFile()) {
            files.add(directory.getAbsolutePath());
        }
        return files;
    }

    /**
     * Reads and hashes a file on the local file system in in chunks of 8KB 
     * @param filePath
     * @return hash of the file's contents in string format
     * @throws AnnotatorException - When bad file path or corrupted file given
     */
    private final String readAndHashFile(String filePath) throws AnnotatorException {
        try {
            FileInputStream fs = new FileInputStream(filePath);
            final byte[] buffer = new byte[8192];
            int bytesRead = 0;
            while (true) {
                bytesRead = fs.read(buffer);
                if (bytesRead == -1) { // indicates EOF
                    break;
                } else {
                    this.hashProvider.update(buffer, 0, bytesRead);
                }
            }
            fs.close();
        } catch (OutOfMemoryError e) {
            throw new AnnotatorException(
                "Failed to read file due to size larger than 2GB, could not validate checksum" + e
            );
        } catch (IOException e) {
            throw new AnnotatorException(
                "Failed to read file contents, could not generate checksum", 
                e
            );
        } catch (SecurityException e) {
            throw new AnnotatorException(
                "Insufficient permission to access file, could not validate checksum",
                e
            );
        } catch (Exception e) {
            throw new AnnotatorException("Could not validate checksum", e);
        }
        return this.hashProvider.getValue();
    }

    /**
     * Computes the hash of all files hashes and their corresponding paths in the specified directory and returns the
     * hash value as a string.
     * @param path the path of the directory to hash
     * @return the hash value of the directory as a string
     * @throws AnnotatorException if an error occurs while hashing the directory
     */
    public String generateChecksum(String path) throws AnnotatorException {
        List<String> filePaths = getAllFiles(path);
        for(int i = 0 ; i<filePaths.size();i++){
            String hashThenPath = readAndHashFile(filePaths.get(i)) + "  " + filePaths.get(i);
            filePaths.set(i, hashThenPath);
        }
        Collections.sort(filePaths, Collator.getInstance(Locale.US));

        String hashesAndFiles = String.join("\n", filePaths) + "\n";
        final String sourceCodeChecksum = this.hashProvider.derive(hashesAndFiles.getBytes());

        return sourceCodeChecksum;
     }
}
